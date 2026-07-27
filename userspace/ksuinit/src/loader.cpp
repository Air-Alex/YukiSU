/**
 * ksuinit - Module Loader
 *
 * Handles loading the KernelSU LKM module with symbol resolution.
 */

#include "loader.hpp"
#include "log.hpp"
#include "vermagic.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <elf.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace ksuinit {

namespace {

constexpr size_t kMaximumKmsgCapture = size_t{256} * 1024;
constexpr size_t kMaximumKmsgRecords = 256;

/**
 * RAII class to manage kptr_restrict setting
 */
class KptrGuard {
public:
    KptrGuard() {
        // Save original value
        std::ifstream ifs("/proc/sys/kernel/kptr_restrict");
        if (ifs.is_open()) {
            std::getline(ifs, original_value_);
        }

        // Set to 1 to allow reading kallsyms
        std::ofstream ofs("/proc/sys/kernel/kptr_restrict");
        if (ofs.is_open()) {
            ofs << "1";
        }
    }

    KptrGuard(const KptrGuard&) = delete;
    KptrGuard& operator=(const KptrGuard&) = delete;
    KptrGuard(KptrGuard&&) = delete;
    KptrGuard& operator=(KptrGuard&&) = delete;

    ~KptrGuard() {
        // Restore original value
        if (!original_value_.empty()) {
            std::ofstream ofs("/proc/sys/kernel/kptr_restrict");
            if (ofs.is_open()) {
                ofs << original_value_;
            }
        }
    }

private:
    std::string original_value_;
};

/**
 * Non-blocking reader positioned after all existing kernel log records.
 */
class KmsgReader {
public:
    KmsgReader() {
        constexpr std::array<const char*, 2> devices = {"/dev/kmsg", "/kmsg"};
        for (const char* device : devices) {
            const int descriptor = open(device, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            if (descriptor < 0) {
                error_ = errno;
                continue;
            }
            if (lseek(descriptor, 0, SEEK_END) < 0) {
                error_ = errno;
                close(descriptor);
                continue;
            }

            descriptor_ = descriptor;
            device_ = device;
            error_ = 0;
            break;
        }
    }

    KmsgReader(const KmsgReader&) = delete;
    KmsgReader& operator=(const KmsgReader&) = delete;
    KmsgReader(KmsgReader&&) = delete;
    KmsgReader& operator=(KmsgReader&&) = delete;

    ~KmsgReader() {
        if (descriptor_ >= 0) {
            close(descriptor_);
        }
    }

    [[nodiscard]] bool is_open() const { return descriptor_ >= 0; }

    [[nodiscard]] int error() const { return error_; }

    [[nodiscard]] const char* device() const { return device_; }

    std::string read_new(int& read_error) const {
        std::string output;
        std::array<char, 8192> record{};
        read_error = 0;
        size_t records_read = 0;

        if (descriptor_ < 0) {
            read_error = EBADF;
            return output;
        }

        while (true) {
            const ssize_t length = read(descriptor_, record.data(), record.size());
            if (length > 0) {
                const size_t record_size = static_cast<size_t>(length);
                const bool needs_newline = record[record_size - 1] != '\n';
                const size_t required_space = record_size + (needs_newline ? 1 : 0);
                if (records_read >= kMaximumKmsgRecords ||
                    required_space > kMaximumKmsgCapture - output.size()) {
                    output.clear();
                    read_error = EOVERFLOW;
                    break;
                }

                output.append(record.data(), record_size);
                if (needs_newline) {
                    output.push_back('\n');
                }
                ++records_read;
                continue;
            }
            if (length == 0) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (errno == EPIPE) {
                output.clear();
                read_error = EOVERFLOW;
                break;
            }

            read_error = errno;
            break;
        }

        return output;
    }

private:
    int descriptor_ = -1;
    int error_ = ENOENT;
    const char* device_ = nullptr;
};

/**
 * Parse /proc/kallsyms to get kernel symbol addresses
 */
std::unordered_map<std::string, uint64_t> parse_kallsyms() {
    const KptrGuard guard;

    std::unordered_map<std::string, uint64_t> symbols;

    std::ifstream ifs("/proc/kallsyms");
    if (!ifs.is_open()) {
        KLOGE("Cannot open /proc/kallsyms");
        return symbols;
    }

    std::string line;
    while (std::getline(ifs, line)) {
        std::istringstream iss(line);
        std::string addr_str;
        std::string type;
        std::string name;

        if (!(iss >> addr_str >> type >> name)) {
            continue;
        }

        uint64_t addr = 0;
        try {
            addr = std::stoull(addr_str, nullptr, 16);
        } catch (...) {
            continue;
        }

        // Strip version suffixes like "$..." or ".llvm...."
        auto pos = name.find('$');
        if (pos == std::string::npos) {
            pos = name.find(".llvm.");
        }
        if (pos != std::string::npos) {
            name = name.substr(0, pos);
        }

        symbols[name] = addr;
    }

    return symbols;
}

/**
 * Read entire file into a vector
 */
bool read_file(const char* path, std::vector<uint8_t>& buffer) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        KLOGE("Cannot open file: %s", path);
        return false;
    }

    auto size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    buffer.resize(static_cast<size_t>(size));
    if (!ifs.read(reinterpret_cast<char*>(buffer.data()), size)) {
        KLOGE("Cannot read file: %s", path);
        return false;
    }

    return true;
}

/**
 * Call init_module syscall
 */
int init_module_syscall(void* module_image, unsigned long len, const char* param_values) {
    return syscall(__NR_init_module, module_image, len, param_values);
}

}  // anonymous namespace

bool load_module(const char* path) {
    // Check if we're PID 1 (init process)
    if (getpid() != 1) {
        KLOGE("Invalid process (not init)");
        return false;
    }

    // Read the module file
    std::vector<uint8_t> buffer;
    if (!read_file(path, buffer)) {
        return false;
    }

    // Parse ELF header
    if (buffer.size() < sizeof(Elf64_Ehdr)) {
        KLOGE("File too small to be an ELF");
        return false;
    }

    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(buffer.data());

    // Verify ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        KLOGE("Invalid ELF magic");
        return false;
    }

    // We only support 64-bit ELF
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        KLOGE("Only 64-bit ELF supported");
        return false;
    }

    // Parse kallsyms
    auto kernel_symbols = parse_kallsyms();
    if (kernel_symbols.empty()) {
        KLOGE("Cannot parse kallsyms");
        return false;
    }

    // Find symbol table section
    auto* shdr_base = reinterpret_cast<Elf64_Shdr*>(buffer.data() + ehdr->e_shoff);

    Elf64_Shdr* symtab = nullptr;
    Elf64_Shdr* strtab = nullptr;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        auto* shdr = &shdr_base[i];
        if (shdr->sh_type == SHT_SYMTAB) {
            symtab = shdr;
            // String table is linked in sh_link
            strtab = &shdr_base[shdr->sh_link];
            break;
        }
    }

    if (!symtab || !strtab) {
        KLOGE("Cannot find symbol table");
        return false;
    }

    // Get pointers to symbol and string tables
    auto* sym_base = reinterpret_cast<Elf64_Sym*>(buffer.data() + symtab->sh_offset);
    auto* str_base = reinterpret_cast<char*>(buffer.data() + strtab->sh_offset);

    const size_t sym_count = symtab->sh_size / sizeof(Elf64_Sym);

    // Resolve undefined symbols
    for (size_t i = 1; i < sym_count; i++) {
        auto* sym = &sym_base[i];

        // Only process undefined symbols
        if (sym->st_shndx != SHN_UNDEF) {
            continue;
        }

        // Get symbol name
        const char* name = &str_base[sym->st_name];
        if (!name || !*name) {
            continue;
        }

        // Look up in kernel symbols
        auto it = kernel_symbols.find(name);
        if (it == kernel_symbols.end()) {
            KLOGW("Cannot find symbol: %s", name);
            continue;
        }

        // Patch the symbol
        sym->st_shndx = SHN_ABS;
        sym->st_value = it->second;
    }

    std::string param_values;
    bool config_loaded = false;
    {
        const std::ifstream config("/ksu_config", std::ios::binary);
        if (config.is_open()) {
            config_loaded = true;
            std::ostringstream buffer;
            buffer << config.rdbuf();
            param_values = buffer.str();
            while (!param_values.empty() &&
                   (param_values.back() == '\n' || param_values.back() == '\r' ||
                    param_values.back() == '\0')) {
                param_values.pop_back();
            }
        }
    }
    if (access("/ksu_allow_shell", F_OK) == 0) {
        KLOGW("ksu allow shell at init");
        if (!param_values.empty()) {
            param_values += " ";
        }
        param_values += "allow_shell=1";
    }
    if (config_loaded) {
        KLOGI("Loading module configuration (%zu bytes)", param_values.size());
    }

    const KmsgReader kmsg_reader;
    if (kmsg_reader.is_open()) {
        KLOGI("Watching kernel log from %s for module load errors", kmsg_reader.device());
    } else {
        KLOGW("Cannot prepare kernel log fallback: %s", strerror(kmsg_reader.error()));
    }

    // Load the module. A version-magic mismatch returns ENOEXEC; in that exact
    // case, use the new kmsg record to safely patch .modinfo and retry once.
    int module_result = init_module_syscall(buffer.data(), buffer.size(), param_values.c_str());
    int module_errno = errno;
    if (module_result != 0 && module_errno == ENOEXEC && kmsg_reader.is_open()) {
        int read_error = 0;
        const std::string new_kmsg = kmsg_reader.read_new(read_error);
        if (read_error != 0) {
            KLOGW("Cannot read new kernel log records: %s", strerror(read_error));
        } else {
            VermagicMismatch mismatch;
            if (extract_vermagic_mismatch(new_kmsg, mismatch)) {
                std::string replacement_error;
                if (replace_module_vermagic(buffer, mismatch.module_vermagic,
                                            mismatch.required_vermagic, replacement_error)) {
                    KLOGW("Retrying module load with kernel-required vermagic: %s",
                          mismatch.required_vermagic.c_str());
                    module_result =
                        init_module_syscall(buffer.data(), buffer.size(), param_values.c_str());
                    module_errno = errno;
                } else {
                    KLOGE("Cannot replace module vermagic: %s", replacement_error.c_str());
                }
            } else {
                KLOGW("init_module returned ENOEXEC without a matching vermagic record");
            }
        }
    }

    std::fill(param_values.begin(), param_values.end(), '\0');
    if (module_result != 0) {
        KLOGE("init_module failed: %s", strerror(module_errno));
        return false;
    }

    if (config_loaded && unlink("/ksu_config") != 0 && errno != ENOENT) {
        KLOGW("Failed to remove module configuration: %s", strerror(errno));
    }
    KLOGI("Module loaded successfully");
    return true;
}

}  // namespace ksuinit
