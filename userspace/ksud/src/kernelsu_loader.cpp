#include "kernelsu_loader.hpp"

#include "log.hpp"
#include "utils.hpp"

#include <elf.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace ksud::kernelsu_loader {

namespace {

class KptrGuard {
public:
    KptrGuard() {
        if (const auto current = read_file(kPath)) {
            original_value_.assign(trim_view(*current));
        }
        (void)write_file(kPath, "1");
    }

    ~KptrGuard() {
        if (!original_value_.empty()) {
            (void)write_file(kPath, original_value_);
        }
    }

    KptrGuard(const KptrGuard&) = delete;
    KptrGuard& operator=(const KptrGuard&) = delete;
    KptrGuard(KptrGuard&&) = delete;
    KptrGuard& operator=(KptrGuard&&) = delete;

private:
    static constexpr const char* kPath = "/proc/sys/kernel/kptr_restrict";
    std::string original_value_;
};

void normalize_symbol_name(std::string* name) {
    size_t pos = name->find('$');
    if (pos == std::string::npos) {
        pos = name->find(".llvm.");
    }
    if (pos != std::string::npos) {
        name->resize(pos);
    }
}

bool read_file_bytes(const char* path, std::vector<uint8_t>* buffer) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOGE("loader: cannot open %s", path);
        return false;
    }

    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        LOGE("loader: cannot stat %s", path);
        close(fd);
        return false;
    }

    buffer->resize(static_cast<size_t>(st.st_size));
    size_t filled = 0;
    while (filled < buffer->size()) {
        const ssize_t n = read(fd, buffer->data() + filled, buffer->size() - filled);
        if (n > 0) {
            filled += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        LOGE("loader: cannot read %s", path);
        close(fd);
        return false;
    }
    close(fd);

    return true;
}

int init_module_syscall(void* module_image, unsigned long len, const char* param_values) {
    return syscall(__NR_init_module, module_image, len, param_values);
}

template <typename Ehdr, typename Shdr, typename Sym>
bool patch_undefined_symbols(std::vector<uint8_t>* buffer) {
    if (buffer->size() < sizeof(Ehdr)) {
        LOGE("loader: file too small to be an ELF");
        return false;
    }

    auto* ehdr = reinterpret_cast<Ehdr*>(buffer->data());
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("loader: invalid ELF magic");
        return false;
    }

    auto* shdr_base = reinterpret_cast<Shdr*>(buffer->data() + ehdr->e_shoff);
    const Shdr* symtab = nullptr;
    const Shdr* strtab = nullptr;

    for (int i = 0; i < ehdr->e_shnum; ++i) {
        auto* shdr = &shdr_base[i];
        if (shdr->sh_type == SHT_SYMTAB) {
            symtab = shdr;
            strtab = &shdr_base[shdr->sh_link];
            break;
        }
    }

    if (symtab == nullptr || strtab == nullptr) {
        LOGE("loader: cannot find symbol table");
        return false;
    }

    auto* sym_base = reinterpret_cast<Sym*>(buffer->data() + symtab->sh_offset);
    auto* str_base = reinterpret_cast<char*>(buffer->data() + strtab->sh_offset);
    const size_t sym_count = symtab->sh_size / sizeof(Sym);
    std::unordered_map<std::string, std::vector<Sym*>> unresolved_symbols;

    for (size_t i = 1; i < sym_count; ++i) {
        auto* sym = &sym_base[i];
        if (sym->st_shndx != SHN_UNDEF) {
            continue;
        }

        const char* name = &str_base[sym->st_name];
        if (name == nullptr || *name == '\0') {
            continue;
        }
        unresolved_symbols[name].push_back(sym);
    }

    if (unresolved_symbols.empty()) {
        return true;
    }

    KptrGuard const guard;
    // Streamed, not read whole: /proc/kallsyms is several MB and this scan stops
    // at the first module-owned symbol.
    std::string name;
    const bool opened = for_each_file_line("/proc/kallsyms", [&](std::string_view line) {
        if (unresolved_symbols.empty()) {
            return false;
        }
        std::string_view rest = line;
        const std::string_view addr_str = next_token(&rest);
        const std::string_view type = next_token(&rest);
        const std::string_view sym_name = next_token(&rest);
        (void)type;
        if (addr_str.empty() || sym_name.empty()) {
            return true;
        }

        // Kernel symbols come before module symbols in /proc/kallsyms. Stop scanning once we
        // reach module-owned entries so we don't accidentally relocate against them.
        if (!next_token(&rest).empty()) {
            return false;
        }

        // next_token yields a view into `line`, which is not NUL-terminated, so
        // bound strtoull explicitly rather than relying on *end == '\0'.
        std::array<char, 32> addr_buf{};
        if (addr_str.size() >= addr_buf.size()) {
            return true;
        }
        std::memcpy(addr_buf.data(), addr_str.data(), addr_str.size());
        char* end = nullptr;
        errno = 0;
        uint64_t const addr = std::strtoull(addr_buf.data(), &end, 16);
        if (end == addr_buf.data() || *end != '\0' || errno == ERANGE) {
            return true;
        }

        name.assign(sym_name);
        normalize_symbol_name(&name);

        const auto it = unresolved_symbols.find(name);
        if (it == unresolved_symbols.end()) {
            return true;
        }

        for (auto* sym : it->second) {
            sym->st_shndx = SHN_ABS;
            sym->st_value = static_cast<decltype(sym->st_value)>(addr);
        }
        unresolved_symbols.erase(it);
        return true;
    });
    if (!opened) {
        LOGE("loader: cannot open /proc/kallsyms");
        return false;
    }

    for (const auto& [name, _] : unresolved_symbols) {
        LOGW("loader: cannot find symbol: %s", name.c_str());
    }

    return true;
}

}  // namespace

bool load_module(const char* path, const std::string& param_values) {
    std::vector<uint8_t> buffer;
    if (!read_file_bytes(path, &buffer)) {
        return false;
    }

    if (buffer.size() < EI_NIDENT || memcmp(buffer.data(), ELFMAG, SELFMAG) != 0) {
        LOGE("loader: invalid ELF image");
        return false;
    }

    const unsigned char elf_class = buffer[EI_CLASS];
    bool patched = false;
    if (elf_class == ELFCLASS64) {
        patched = patch_undefined_symbols<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym>(&buffer);
    } else if (elf_class == ELFCLASS32) {
        patched = patch_undefined_symbols<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym>(&buffer);
    } else {
        LOGE("loader: unsupported ELF class %u", elf_class);
        return false;
    }

    if (!patched) {
        return false;
    }

    if (init_module_syscall(buffer.data(), buffer.size(), param_values.c_str()) != 0) {
        if (errno == EEXIST) {
            return true;
        }
        LOGE("loader: init_module failed: %s", strerror(errno));
        return false;
    }

    LOGI("loader: module loaded successfully");
    return true;
}

}  // namespace ksud::kernelsu_loader
