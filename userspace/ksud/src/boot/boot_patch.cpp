#include "boot_patch.hpp"
#include "../assets.hpp"
#include "../core/uts_view.hpp"
#include "../defs.hpp"
#include "../log.hpp"
#include "../utils.hpp"
#include "lkm_image.hpp"
#include "tools.hpp"
#include "uapi/imgpatch_config.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

namespace fs = std::filesystem;

namespace ksud {

// SuperKey magic marker (must match kernel's SUPERKEY_MAGIC)
constexpr uint64_t SUPERKEY_MAGIC = 0x5355504552;  // "SUPER" in hex

// SuperKey verification mode definitions (must match kernel)
// 0: signature-only (no superkey)      - do not register prctl kprobe
// 1: signature + superkey (default)    - register prctl kprobe, require both
// 2: superkey-only (signature bypass)  - register prctl kprobe, bypass signature
constexpr uint64_t SUPERKEY_VERIFICATION_SIGNATURE_ONLY = 0;
constexpr uint64_t SUPERKEY_VERIFICATION_SIGN_AND_KEY = 1;
constexpr uint64_t SUPERKEY_VERIFICATION_KEY_ONLY = 2;

namespace {

constexpr const char* kDirectLkmBackupDirectory = "/data/adb/ksu";
constexpr const char* kDirectLkmBackupPrefix = "boot-patch-v2-original";

std::optional<fs::path> find_direct_lkm_backup(const std::string& slot) {
    fs::path path =
        fs::path(kDirectLkmBackupDirectory) / (std::string(kDirectLkmBackupPrefix) + slot + ".img");
    std::error_code error;
    if (!fs::is_regular_file(path, error) || error)
        return std::nullopt;
    const auto size = fs::file_size(path, error);
    if (error || size == 0)
        return std::nullopt;
    return path;
}

bool is_boot_partition_device(const std::string& device) {
    const std::string name = fs::path(device).filename().string();
    return name == "boot" || name == "boot_a" || name == "boot_b";
}

// LZ4 legacy ramdisk magic (reject before cpio to avoid huge cache/hang).
constexpr std::array<unsigned char, 4> LZ4_LEGACY_MAGIC = {0x02, 0x21, 0x4c, 0x18};

constexpr size_t SUPERKEY_SALT_LEN = 16;

// SHA-256(salt || key), truncated to first 8 bytes (little-endian u64). Must
// match the kernel-side hash_superkey() in kernel/superkey.c.
uint64_t hash_superkey(const std::array<uint8_t, SUPERKEY_SALT_LEN>& salt, const std::string& key) {
    unsigned char digest[32] = {0};
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, salt.data(), salt.size());
    mbedtls_sha256_update(&ctx, reinterpret_cast<const unsigned char*>(key.data()), key.size());
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);

    uint64_t out = 0;
    for (size_t i = 0; i < 8; ++i) {
        out |= static_cast<uint64_t>(digest[i]) << (i * 8);
    }
    return out;
}

bool fill_random(uint8_t* buf, size_t len) {
    size_t filled = 0;
    while (filled < len) {
        const ssize_t count = getrandom(buf + filled, len - filled, 0);
        if (count > 0) {
            filled += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}

bool has_lz4_legacy_magic(const std::string& path) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    std::array<unsigned char, 4> magic{};
    size_t filled = 0;
    while (filled < magic.size()) {
        const ssize_t count = read(fd, magic.data() + filled, magic.size() - filled);
        if (count > 0) {
            filled += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR)
            continue;
        break;
    }
    close(fd);
    return filled == magic.size() &&
           memcmp(magic.data(), LZ4_LEGACY_MAGIC.data(), magic.size()) == 0;
}

std::optional<bool> lkm_supports_uts_boot_params(const std::string& lkm_path) {
    const auto content = read_file(lkm_path);
    if (!content)
        return std::nullopt;
    return content->find("parmtype=uts_boot_global:bool") != std::string::npos;
}

// Inject superkey salt+hash and verification mode into LKM file.
// Layout in the LKM .data section (matches struct superkey_data in kernel):
//   [+0]  u64 magic   (SUPERKEY_MAGIC)
//   [+8]  u8  salt[16]
//   [+24] u64 hash    (first 8 bytes of SHA-256(salt || key))
//   [+32] u64 flags   (verification mode)
// The verification mode is always injected, even when superkey is empty.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters) path then superkey
bool inject_superkey_to_lkm(const std::string& lkm_path, const std::string& superkey,
                            bool signature_bypass) {
    std::array<uint8_t, SUPERKEY_SALT_LEN> salt{};
    if (!superkey.empty()) {
        if (!fill_random(salt.data(), salt.size())) {
            LOGE("Failed to obtain SuperKey salt entropy");
            return false;
        }
    }
    uint64_t hash = superkey.empty() ? 0 : hash_superkey(salt, superkey);

    uint64_t flags;
    if (superkey.empty()) {
        // User did not configure a SuperKey: pure signature mode.
        flags = SUPERKEY_VERIFICATION_SIGNATURE_ONLY;
    } else {
        // SuperKey is set; choose between "sign+key" and "key only".
        flags =
            signature_bypass ? SUPERKEY_VERIFICATION_KEY_ONLY : SUPERKEY_VERIFICATION_SIGN_AND_KEY;
    }

    printf("- SuperKey hash: 0x%016llx\n", static_cast<unsigned long long>(hash));
    const char* mode_str;
    if (superkey.empty()) {
        mode_str = "signature-only";
    } else {
        mode_str = signature_bypass ? "key-only" : "sign+key";
    }
    printf("- Verification mode: %llu (%s)\n", static_cast<unsigned long long>(flags), mode_str);

    std::vector<uint8_t> content;
    if (!read_file_bytes(lkm_path, &content)) {
        LOGE("Failed to open LKM file: %s", lkm_path.c_str());
        return false;
    }
    const size_t size = content.size();

    // Search for SUPERKEY_MAGIC in the binary
    std::array<uint8_t, 8> magic_bytes{};
    memcpy(magic_bytes.data(), &SUPERKEY_MAGIC, magic_bytes.size());

    constexpr size_t SUPERKEY_BLOCK_LEN = 40;  // magic(8) + salt(16) + hash(8) + flags(8)
    bool found = false;
    for (size_t i = 0; i + SUPERKEY_BLOCK_LEN <= size; i++) {
        if (memcmp(&content[i], magic_bytes.data(), magic_bytes.size()) == 0) {
            memcpy(&content[i + 8], salt.data(), salt.size());
            memcpy(&content[i + 24], &hash, sizeof(hash));
            memcpy(&content[i + 32], &flags, sizeof(flags));
            found = true;
            printf("- Injected SuperKey data at offset 0x%zx (40 bytes)\n", i);
            break;
        }
    }

    if (!found) {
        printf("- Warning: SUPERKEY_MAGIC not found in LKM, SuperKey may not work\n");
        printf("- Make sure the kernel module is compiled with SuperKey support\n");
    } else if (!write_file_bytes(lkm_path, content.data(), content.size())) {
        LOGE("Failed to write patched LKM: %s", lkm_path.c_str());
        return false;
    }

    return true;
}

bool inject_imgpatch_config_to_lkm(const std::string& lkm_path, bool allow_shell, bool enable_adbd,
                                   const ksu_uts_template* uts_config) {
    static_assert(sizeof(ksu_imgpatch_config) == 512, "ImgPatch config ABI drift");
    static_assert(offsetof(ksu_imgpatch_config, uts) == 24, "ImgPatch UTS config ABI drift");

    ksu_imgpatch_config config{};
    config.magic = KSU_IMGPATCH_CONFIG_MAGIC;
    config.version = KSU_IMGPATCH_CONFIG_VERSION;
    config.size = sizeof(config);
    if (allow_shell)
        config.flags |= KSU_IMGPATCH_CONFIG_ALLOW_SHELL;
    if (enable_adbd)
        config.flags |= KSU_IMGPATCH_CONFIG_ENABLE_ADBD;
    if (uts_config != nullptr) {
        config.flags |= KSU_IMGPATCH_CONFIG_UTS_BOOT;
        config.uts = *uts_config;
    }

    std::vector<uint8_t> content;
    if (!read_file_bytes(lkm_path, &content)) {
        LOGE("Failed to open LKM file: %s", lkm_path.c_str());
        return false;
    }

    std::array<uint8_t, sizeof(config.magic)> magic_bytes{};
    memcpy(magic_bytes.data(), &config.magic, magic_bytes.size());
    std::optional<size_t> config_offset;
    bool incompatible_marker = false;
    for (size_t offset = 0; offset + sizeof(config) <= content.size(); ++offset) {
        if (memcmp(content.data() + offset, magic_bytes.data(), magic_bytes.size()) != 0)
            continue;

        ksu_imgpatch_config candidate{};
        memcpy(&candidate, content.data() + offset, sizeof(candidate));
        if (candidate.version != KSU_IMGPATCH_CONFIG_VERSION ||
            candidate.size != sizeof(candidate)) {
            incompatible_marker = true;
            continue;
        }
        if (config_offset.has_value()) {
            LOGE("LKM contains duplicate ImgPatch config markers");
            return false;
        }
        config_offset = offset;
    }

    if (!config_offset.has_value()) {
        if (config.flags != 0) {
            LOGE("Selected LKM does not support embedded ImgPatch configuration%s",
                 incompatible_marker ? " (incompatible marker version)" : "");
            return false;
        }
        return true;
    }

    memcpy(content.data() + *config_offset, &config, sizeof(config));
    if (!write_file_bytes(lkm_path, content.data(), content.size())) {
        LOGE("Failed to write ImgPatch configuration to LKM: %s", lkm_path.c_str());
        return false;
    }
    printf("- Injected ImgPatch config at offset 0x%zx: allow_shell=%d enable_adbd=%d uts=%d\n",
           *config_offset, allow_shell, enable_adbd, uts_config != nullptr);
    return true;
}

// Execute magiskboot cpio command (runs in workdir for relative path resolution).
bool do_cpio_cmd(const std::string& magiskboot, const std::string& workdir,
                 const std::string& cpio_path, const std::string& cmd) {
    auto result = exec_command_magiskboot(magiskboot, {"cpio", cpio_path, cmd}, workdir);
    if (result.exit_code != 0) {
        LOGE("magiskboot cpio %s failed", cmd.c_str());
        if (!result.stdout_str.empty()) {
            LOGE("magiskboot cpio stdout: %s", result.stdout_str.c_str());
        }
        if (!result.stderr_str.empty()) {
            LOGE("magiskboot cpio stderr: %s", result.stderr_str.c_str());
        }
        return false;
    }
    return true;
}

// Check if boot image is patched by Magisk
bool is_magisk_patched(const std::string& magiskboot, const std::string& workdir,
                       const std::string& cpio_path) {
    // Built-in magiskboot runs in-process for read-only queries, and cpio_path is
    // absolute, so neither the tool path nor a cwd is needed here.
    (void)magiskboot;
    (void)workdir;
    // magiskboot cpio test: 0 = stock, 1 = magisk, 2 = unsupported.
    if (magiskboot_query({"cpio", cpio_path, "test"}) != 1) {
        return false;
    }
    // Confirm with a Magisk-specific entry so an unrelated exit status of 1
    // cannot be read as "Magisk-patched".
    return magiskboot_query({"cpio", cpio_path, "exists init.magisk.rc"}) == 0 ||
           magiskboot_query({"cpio", cpio_path, "exists overlay.d"}) == 0;
}

// Check if boot image is patched by KernelSU
bool is_kernelsu_patched(const std::string& magiskboot, const std::string& workdir,
                         const std::string& cpio_path) {
    // Built-in magiskboot runs in-process for read-only queries, and cpio_path is
    // absolute, so neither the tool path nor a cwd is needed here.
    (void)magiskboot;
    (void)workdir;
    return magiskboot_query({"cpio", cpio_path, "exists kernelsu.ko"}) == 0;
}

// Flash boot image
bool flash_boot(const std::string& bootdevice, const std::string& new_boot) {
    if (bootdevice.empty()) {
        LOGE("Boot device not found");
        return false;
    }

    // Set device to read-write. Some devices/partitions do not require or allow
    // this ioctl; continue either way and let the write itself decide.
    if (!set_block_device_rw(bootdevice)) {
        LOGW("Continuing to flash %s anyway", bootdevice.c_str());
    }

    if (!exec_dd(new_boot, bootdevice)) {
        LOGE("Failed to flash boot image");
        return false;
    }

    return true;
}

// SHA-1 of a file, streamed. mbedTLS is already linked for the SuperKey hash, so
// this needed neither a `sha1sum` on PATH nor parsing "<hex>  <name>" back out of
// a child's stdout -- and it no longer silently returns "" when the tool is
// missing from a recovery PATH.
std::string calculate_sha1(const std::string& file_path) {
    const int fd = open(file_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOGE("sha1: cannot open %s: %s", file_path.c_str(), strerror(errno));
        return "";
    }
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    if (mbedtls_sha1_starts(&ctx) != 0) {
        mbedtls_sha1_free(&ctx);
        close(fd);
        return "";
    }
    std::array<unsigned char, 64UL * 1024> buffer{};
    bool ok = true;
    for (;;) {
        const ssize_t count = read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            if (mbedtls_sha1_update(&ctx, buffer.data(), static_cast<size_t>(count)) != 0) {
                ok = false;
                break;
            }
            continue;
        }
        if (count == 0)
            break;
        if (errno == EINTR)
            continue;
        LOGE("sha1: read %s failed: %s", file_path.c_str(), strerror(errno));
        ok = false;
        break;
    }
    close(fd);

    std::array<unsigned char, 20> digest{};
    if (ok && mbedtls_sha1_finish(&ctx, digest.data()) != 0) {
        ok = false;
    }
    mbedtls_sha1_free(&ctx);
    if (!ok) {
        return "";
    }

    // Lowercase hex, matching what sha1sum printed and what the backup format
    // stores.
    std::string hex;
    hex.reserve(digest.size() * 2);
    for (const unsigned char byte : digest) {
        append_hex(&hex, byte, false, 2);
    }
    return hex;
}

// Backup stock boot image
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool do_backup(const std::string& magiskboot, const std::string& workdir,
               const std::string& cpio_path, const std::string& image) {
    const std::string sha1 = calculate_sha1(image);
    if (sha1.empty()) {
        LOGE("Failed to calculate SHA1 of boot image");
        return false;
    }

    const std::string filename = std::string(KSU_BACKUP_FILE_PREFIX) + sha1;
    printf("- Backup stock boot image\n");

    const std::string target = std::string(KSU_BACKUP_DIR) + filename;

    // Copy image to backup location
    if (!copy_file_data(image, target)) {
        LOGE("Failed to backup boot image to %s", target.c_str());
        return false;
    }

    // Write sha1 to workdir
    const std::string sha1_file = workdir + "/" + BACKUP_FILENAME;
    write_file(sha1_file, sha1);

    // Add backup info to ramdisk
    if (!do_cpio_cmd(
            magiskboot, workdir, cpio_path,
            "add 0644 " + std::string(BACKUP_FILENAME) + " " + std::string(BACKUP_FILENAME))) {
        return false;
    }

    printf("- Stock image has been backup to\n");
    printf("- %s\n", target.c_str());
    return true;
}

std::string parse_kmi_from_kernel_file(const std::string& kernel_path) {
    std::vector<uint8_t> data;
    if (!read_file_bytes(kernel_path, &data)) {
        LOGE("Failed to read kernel from %s", kernel_path.c_str());
        return "";
    }
    if (data.empty()) {
        LOGE("Kernel image is empty: %s", kernel_path.c_str());
        return "";
    }

    for (size_t i = 0; i + 4 <= data.size(); ++i) {
        if (data[i] < '5' || data[i] > '9' || data[i + 1] != '.' || !std::isdigit(data[i + 2]) ||
            (data[i] == '5' && !std::isdigit(data[i + 3]))) {
            continue;
        }

        const size_t limit = std::min(data.size(), i + 100);
        size_t end = i;
        while (end < limit && data[end] != '\0') {
            ++end;
        }
        if (end == limit) {
            continue;
        }

        const std::string_view candidate(reinterpret_cast<const char*>(data.data() + i), end - i);
        if (const auto kmi = parse_kmi_string(candidate))
            return *kmi;
    }

    return "";
}

std::string parse_kmi_from_boot(const std::string& magiskboot, const std::string& workdir,
                                const std::string& boot_path) {
    const std::string detect_dir = workdir + "/target_kmi";
    if (!ensure_clean_dir(detect_dir)) {
        LOGE("Failed to create target KMI detection directory");
        return "";
    }

    auto unpack_result = exec_command_magiskboot(magiskboot, {"unpack", boot_path}, detect_dir);
    if (unpack_result.exit_code != 0) {
        // Kernel is extracted before ramdisk. Some legacy ramdisks can still make magiskboot
        // abort after a valid kernel file has already been written, so try that file first.
        LOGW("Target boot unpack exited with %d: %s", unpack_result.exit_code, boot_path.c_str());
        if (!unpack_result.stderr_str.empty()) {
            LOGW("magiskboot stderr: %s", unpack_result.stderr_str.c_str());
        }
    }

    const std::string kernel_path = detect_dir + "/kernel";
    const std::string kmi = parse_kmi_from_kernel_file(kernel_path);
    if (kmi.empty()) {
        LOGE("Failed to get KMI from target boot image");
    }
    return kmi;
}

// Clean old backups
void clean_backup(const std::string& current_sha1) {
    printf("- Clean up backup\n");
    const std::string backup_name = std::string(KSU_BACKUP_FILE_PREFIX) + current_sha1;

    std::error_code ec;
    for (auto it = fs::directory_iterator(KSU_BACKUP_DIR, ec);
         it != fs::directory_iterator() && !ec; it.increment(ec)) {
        std::error_code rf_ec;
        if (!it->is_regular_file(rf_ec))
            continue;

        const std::string name = it->path().filename().string();
        if (name != backup_name && starts_with(name, KSU_BACKUP_FILE_PREFIX)) {
            std::error_code remove_error;
            if (fs::remove(it->path(), remove_error)) {
                printf("- removed %s\n", name.c_str());
            } else if (remove_error) {
                LOGW("Failed to remove backup %s: %s", name.c_str(),
                     remove_error.message().c_str());
            }
        }
    }
    if (ec) {
        LOGW("Clean backup error: %s", ec.message().c_str());
    }
}

}  // namespace

bool inject_superkey_into_lkm(const std::string& lkm_path, const std::string& superkey,
                              bool signature_bypass) {
    return inject_superkey_to_lkm(lkm_path, superkey, signature_bypass);
}

bool inject_imgpatch_config_into_lkm(const std::string& lkm_path, bool allow_shell,
                                     bool enable_adbd, const ksu_uts_template* uts_config) {
    return inject_imgpatch_config_to_lkm(lkm_path, allow_shell, enable_adbd, uts_config);
}

// Parse boot patch arguments
struct BootPatchArgs {
    std::string boot_image;         // -b, --boot
    std::string kernel;             // -k, --kernel
    std::string module;             // -m, --module (LKM path)
    std::string init;               // -i, --init
    std::string superkey;           // -s, --superkey
    bool signature_bypass = false;  // --signature-bypass
    bool ota = false;               // -u, --ota
    bool flash = false;             // -f, --flash
    bool backup = false;            // --backup
    std::string out;                // -o, --out
    std::string magiskboot;         // --magiskboot
    std::string kmi;                // --kmi
    std::string partition;          // --partition
    std::string out_name;           // --out-name
    bool allow_shell = false;       // --allow-shell
    bool no_custom_rc = false;      // --no-custom-rc
    bool enable_adbd = false;       // --enable-adbd
    std::string adb_debug_prop;     // --adb-debug-prop
    std::string uts_config;         // --uts-config
    bool uts_config_seen = false;
    bool help = false;  // -h, --help
    bool valid = true;
    std::string invalid_reason;  // names the offending argument when valid is false
};

namespace {

// Without -b, boot-patch detects the boot partition itself, reads it, and -- with
// -f -- writes it back. That makes an argument this parser does not understand
// dangerous rather than merely useless: dropping a mistyped --boot silently turns
// "patch this file" into "patch the partition I picked". Every unrecognized or
// incomplete argument therefore stops the run.
void print_boot_patch_usage() {
    printf("Usage: ksud boot-patch [-b <boot.img>] [-o <dir>] [options]\n"
           "\n"
           "Without -b the boot partition is detected and read.\n"
           "Without -f nothing is written to any partition.\n"
           "\n"
           "  -b, --boot <img>       patch this image instead of the boot partition\n"
           "  -f, --flash            write the result back to the boot partition\n"
           "  -o, --out <dir>        directory to write the patched image into\n"
           "      --out-name <name>  filename for the patched image\n"
           "  -m, --module <ko>      use this LKM instead of the embedded one\n"
           "  -k, --kernel <img>     replace the kernel\n"
           "  -i, --init <bin>       replace init\n"
           "  -u, --ota              target the inactive slot\n"
           "      --partition <name> boot partition to use (boot, init_boot)\n"
           "      --kmi <kmi>        override the detected KMI\n"
           "      --backup           back up the stock image\n"
           "  -s, --superkey <key>   set the SuperKey\n"
           "      --signature-bypass relax LKM signature checking\n"
           "      --allow-shell      keep a root shell available\n"
           "      --no-custom-rc     skip the custom init.rc injection\n"
           "      --enable-adbd      run adbd as root\n"
           "      --adb-debug-prop <file>  adb debug properties to embed\n"
           "      --uts-config <file>      UTS template to embed (at most once)\n"
           "      --magiskboot <path>      accepted for compatibility; ignored\n"
           "  -h, --help             show this message\n");
}

BootPatchArgs parse_boot_patch_args(const std::vector<std::string>& args) {
    BootPatchArgs result;

    // Keep the first failure. Once the command line is known to be wrong there is
    // nothing to gain from diagnosing the rest of it.
    auto reject = [&result](std::string reason) {
        if (result.valid) {
            result.valid = false;
            result.invalid_reason = std::move(reason);
        }
    };

    for (size_t i = 0; i < args.size(); i++) {
        const std::string& arg = args[i];

        // arg stays bound to the flag itself across the ++i below, so it still
        // names the right thing in the messages here.
        auto take_value = [&](std::string& destination) {
            if (i + 1 >= args.size()) {
                reject(arg + " requires a value");
                return;
            }
            destination = args[++i];
            if (destination.empty())
                reject(arg + " requires a non-empty value");
        };

        if (arg == "-h" || arg == "--help") {
            result.help = true;
        } else if (arg == "-b" || arg == "--boot") {
            take_value(result.boot_image);
        } else if (arg == "-k" || arg == "--kernel") {
            take_value(result.kernel);
        } else if (arg == "-m" || arg == "--module") {
            take_value(result.module);
        } else if (arg == "-i" || arg == "--init") {
            take_value(result.init);
        } else if (arg == "-s" || arg == "--superkey") {
            take_value(result.superkey);
        } else if (arg == "--signature-bypass") {
            result.signature_bypass = true;
        } else if (arg == "-u" || arg == "--ota") {
            result.ota = true;
        } else if (arg == "-f" || arg == "--flash") {
            result.flash = true;
        } else if (arg == "--backup") {
            result.backup = true;
        } else if (arg == "-o" || arg == "--out") {
            take_value(result.out);
        } else if (arg == "--magiskboot") {
            take_value(result.magiskboot);
        } else if (arg == "--kmi") {
            take_value(result.kmi);
        } else if (arg == "--partition") {
            take_value(result.partition);
        } else if (arg == "--out-name") {
            take_value(result.out_name);
        } else if (arg == "--allow-shell") {
            result.allow_shell = true;
        } else if (arg == "--no-custom-rc") {
            result.no_custom_rc = true;
        } else if (arg == "--enable-adbd") {
            result.enable_adbd = true;
        } else if (arg == "--adb-debug-prop") {
            take_value(result.adb_debug_prop);
        } else if (arg == "--uts-config") {
            if (result.uts_config_seen) {
                reject("--uts-config may only be given once");
            } else {
                take_value(result.uts_config);
                result.uts_config_seen = true;
            }
        } else {
            reject("unknown argument: " + arg);
        }
    }

    return result;
}

enum class DirectLkmRestoreStatus : std::uint8_t {
    kNotPresent,
    kRestored,
    kFailed,
};

enum class DirectLkmImageStatus : std::uint8_t {
    kNoCapsule,
    kContainsCapsule,
    kUnverified,
};

bool has_direct_lkm_magic(const std::vector<std::uint8_t>& kernel) {
    constexpr std::array<std::uint8_t, 8> kCapsuleMagic = {'K', 'S', 'U', 'L', 'K', 'M', '1', 0};
    constexpr std::size_t kCapsuleHeaderSize = 96;
    const auto image_info = boot::lkm_image::parse_arm64_image(kernel);
    if (!image_info || image_info.value().image_size > kernel.size() ||
        image_info.value().image_size < kCapsuleHeaderSize)
        return false;

    const std::size_t image_size = image_info.value().image_size;
    for (std::size_t offset = 64; offset <= image_size - kCapsuleHeaderSize; offset += 16) {
        if (std::equal(kCapsuleMagic.begin(), kCapsuleMagic.end(),
                       kernel.begin() + static_cast<std::ptrdiff_t>(offset)))
            return true;
    }
    return false;
}

DirectLkmImageStatus inspect_direct_lkm_image(const fs::path& image, const std::string& magiskboot,
                                              const std::string& workdir) {
    if (image.empty())
        return DirectLkmImageStatus::kUnverified;

    const std::string check_workdir = workdir + "/direct-lkm-backup-check";
    if (!ensure_clean_dir(check_workdir)) {
        LOGW("Failed to create direct-LKM image check directory");
        return DirectLkmImageStatus::kUnverified;
    }

    auto unpack = exec_command_magiskboot(magiskboot, {"unpack", image.string()}, check_workdir);
    if (unpack.exit_code != 0) {
        LOGW("Failed to fully unpack image for direct-LKM validation: %s", image.string().c_str());
        if (!unpack.stderr_str.empty())
            LOGW("magiskboot stderr: %s", unpack.stderr_str.c_str());

        // A ramdisk decompression failure can happen after magiskboot has already
        // extracted the kernel. Retry without decompression before giving up.
        unpack = exec_command_magiskboot(magiskboot, {"unpack", image.string(), "--skip-decomp"},
                                         check_workdir);
    }

    const std::vector<std::string> kernel_candidates = {check_workdir + "/kernel",
                                                        check_workdir + "/kernel.img"};
    for (const auto& candidate : kernel_candidates) {
        std::vector<std::uint8_t> kernel_bytes;
        if (!read_file_bytes(candidate, &kernel_bytes))
            continue;

        if (!boot::lkm_image::parse_arm64_image(kernel_bytes))
            continue;

        if (!boot::lkm_image::contains_capsule(kernel_bytes)) {
            return has_direct_lkm_magic(kernel_bytes) ? DirectLkmImageStatus::kUnverified
                                                      : DirectLkmImageStatus::kNoCapsule;
        }

        auto restored = boot::lkm_image::remove_capsule(kernel_bytes);
        if (restored)
            return DirectLkmImageStatus::kContainsCapsule;

        LOGW("Could not validate direct-LKM capsule state for %s: %s", image.string().c_str(),
             restored.error().message.c_str());
        return DirectLkmImageStatus::kUnverified;
    }

    if (unpack.exit_code != 0)
        LOGW("No unpacked ARM64 kernel available for direct-LKM validation: %s",
             image.string().c_str());
    else
        LOGW("Image has no recognizable ARM64 kernel for direct-LKM validation: %s",
             image.string().c_str());
    return DirectLkmImageStatus::kUnverified;
}

DirectLkmImageStatus validate_direct_lkm_backup(const fs::path& backup,
                                                const std::string& magiskboot,
                                                const std::string& workdir) {
    const auto status = inspect_direct_lkm_image(backup, magiskboot, workdir);
    if (status != DirectLkmImageStatus::kContainsCapsule)
        return status;

    std::error_code remove_error;
    const bool removed = fs::remove(backup, remove_error);
    if (remove_error) {
        LOGE("Failed to delete invalid direct-LKM backup %s: %s", backup.string().c_str(),
             remove_error.message().c_str());
    } else if (removed) {
        printf("- Deleted invalid direct-LKM backup: %s\n", backup.string().c_str());
    } else {
        LOGW("Invalid direct-LKM backup disappeared before deletion: %s", backup.string().c_str());
    }
    return DirectLkmImageStatus::kContainsCapsule;
}

DirectLkmRestoreStatus restore_direct_lkm_kernel(const std::string& workdir) {
    const std::vector<std::string> kernel_candidates = {workdir + "/kernel",
                                                        workdir + "/kernel.img"};
    for (const auto& candidate : kernel_candidates) {
        std::vector<std::uint8_t> kernel_bytes;
        if (!read_file_bytes(candidate, &kernel_bytes))
            continue;
        if (!boot::lkm_image::contains_capsule(kernel_bytes))
            continue;

        auto restored = boot::lkm_image::remove_capsule(kernel_bytes);
        if (!restored) {
            LOGE("Direct-LKM restore failed: %s", restored.error().message.c_str());
            return DirectLkmRestoreStatus::kFailed;
        }

        if (!write_file_bytes(candidate, restored.value().data(), restored.value().size())) {
            LOGE("Failed to write restored kernel: %s", candidate.c_str());
            return DirectLkmRestoreStatus::kFailed;
        }
        printf("- Existing direct-LKM image detected\n");
        printf("- Removed direct-LKM capsule; continuing with traditional ramdisk patch\n");
        return DirectLkmRestoreStatus::kRestored;
    }
    return DirectLkmRestoreStatus::kNotPresent;
}

struct DirectLkmBootRestore {
    std::string device;
    std::string original_image;
    std::string restored_image;
};

DirectLkmRestoreStatus prepare_direct_lkm_boot_restore(const std::string& workdir,
                                                       const std::string& magiskboot,
                                                       const std::string& bootdevice,
                                                       DirectLkmBootRestore* prepared) {
    if (prepared == nullptr)
        return DirectLkmRestoreStatus::kFailed;

    const std::string original_image = workdir + "/imgpatch-boot.img";
    if (!exec_dd(bootdevice, original_image)) {
        LOGE("Failed to read boot image from %s", bootdevice.c_str());
        return DirectLkmRestoreStatus::kFailed;
    }

    const std::string restore_workdir = workdir + "/imgpatch-boot-restore";
    if (!ensure_clean_dir(restore_workdir)) {
        LOGE("Failed to create direct-LKM restore workdir: %s", restore_workdir.c_str());
        return DirectLkmRestoreStatus::kFailed;
    }

    const auto unpack =
        exec_command_magiskboot(magiskboot, {"unpack", original_image}, restore_workdir);
    if (unpack.exit_code != 0) {
        LOGE("Failed to unpack direct-LKM boot image from %s", bootdevice.c_str());
        if (!unpack.stdout_str.empty())
            LOGE("magiskboot stdout: %s", unpack.stdout_str.c_str());
        if (!unpack.stderr_str.empty())
            LOGE("magiskboot stderr: %s", unpack.stderr_str.c_str());
        return DirectLkmRestoreStatus::kFailed;
    }

    const std::vector<std::string> kernel_candidates = {restore_workdir + "/kernel",
                                                        restore_workdir + "/kernel.img"};
    bool restored_kernel = false;
    for (const auto& candidate : kernel_candidates) {
        std::vector<std::uint8_t> kernel_bytes;
        if (!read_file_bytes(candidate, &kernel_bytes))
            continue;
        if (!boot::lkm_image::contains_capsule(kernel_bytes))
            continue;

        auto restored = boot::lkm_image::remove_capsule(kernel_bytes);
        if (!restored) {
            LOGE("Direct-LKM boot restore failed: %s", restored.error().message.c_str());
            return DirectLkmRestoreStatus::kFailed;
        }

        if (!write_file_bytes(candidate, restored.value().data(), restored.value().size())) {
            LOGE("Failed to write restored kernel: %s", candidate.c_str());
            return DirectLkmRestoreStatus::kFailed;
        }
        restored_kernel = true;
        break;
    }
    if (!restored_kernel)
        return DirectLkmRestoreStatus::kNotPresent;

    const std::string restored_image = workdir + "/imgpatch-boot-restored.img";
    const auto repack = exec_command_magiskboot(
        magiskboot, {"repack", original_image, restored_image}, restore_workdir);
    std::error_code repacked_error;
    if (repack.exit_code != 0 || !fs::is_regular_file(restored_image, repacked_error) ||
        repacked_error) {
        LOGE("Failed to repack direct-LKM boot image from %s", bootdevice.c_str());
        if (!repack.stdout_str.empty())
            LOGE("magiskboot stdout: %s", repack.stdout_str.c_str());
        if (!repack.stderr_str.empty())
            LOGE("magiskboot stderr: %s", repack.stderr_str.c_str());
        return DirectLkmRestoreStatus::kFailed;
    }

    *prepared = {bootdevice, original_image, restored_image};
    printf("- Existing direct-LKM image detected in %s\n", bootdevice.c_str());
    printf("- Repacked boot image after removing the direct-LKM capsule\n");
    return DirectLkmRestoreStatus::kRestored;
}

int boot_patch_impl(const std::vector<std::string>& args) {
    auto parsed = parse_boot_patch_args(args);
    if (parsed.help) {
        print_boot_patch_usage();
        return 0;
    }
    if (!parsed.valid) {
        LOGE("boot-patch: %s", parsed.invalid_reason.c_str());
        print_boot_patch_usage();
        return 1;
    }
    const std::string ota_slot = parsed.ota ? get_slot_suffix(true) : "";
    if (parsed.ota && ota_slot.empty()) {
        LOGE("Inactive-slot install requires a valid current slot suffix (_a or _b)");
        return 1;
    }
    ksu_uts_template boot_uts_config{};
    const bool have_boot_uts_config = !parsed.uts_config.empty();

    (void)setvbuf(stdout, nullptr, _IONBF, 0);
    (void)setvbuf(stderr, nullptr, _IONBF, 0);
    printf("\n");
    printf("__   __ _   _  _  __ ___  ____   _   _ \n");
    printf("\\ \\ / /| | | || |/ /|_ _|/ ___| | | | |\n");
    printf(" \\ V / | | | || ' /  | | \\___ \\ | | | |\n");
    printf("  | |  | |_| || . \\  | |  ___) || |_| |\n");
    printf("  |_|   \\___/ |_|\\_\\|___||____/  \\___/ \n");
    printf("\n");

    if (have_boot_uts_config) {
        std::string error;
        if (!load_uts_boot_config(parsed.uts_config, &boot_uts_config, &error)) {
            LOGE("Invalid UTS boot config: %s", error.c_str());
            return 1;
        }
        printf("- UTS boot-global config validated (mask=0x%02x)\n", boot_uts_config.field_mask);
        printf("- This identity takes effect after flashing the patched image and rebooting\n");
    }

    // Create temp working directory
    // Try multiple locations in order of preference:
    // 1. TMPDIR environment variable (set by manager app to its cache dir)
    // 2. Current working directory (if writable)
    // 3. /data/local/tmp (fallback, requires shell access)
    std::string workdir;
    const char* tmpdir = nullptr;

    // Try TMPDIR env first (manager sets this to app cache dir)
    const char* env_tmpdir = getenv("TMPDIR");
    if (env_tmpdir && access(env_tmpdir, W_OK) == 0) {
        std::string template_path = std::string(env_tmpdir) + "/KernelSU_XXXXXX";
        std::vector<char> tmpdir_template(template_path.begin(), template_path.end());
        tmpdir_template.push_back('\0');
        tmpdir = mkdtemp(tmpdir_template.data());
        if (tmpdir) {
            workdir = tmpdir;
            printf("- Using TMPDIR: %s\n", env_tmpdir);
        }
    }

    // Try current directory
    if (workdir.empty()) {
        std::array<char, PATH_MAX> cwd{};
        if (getcwd(cwd.data(), cwd.size()) && access(cwd.data(), W_OK) == 0) {
            std::string template_path = std::string(cwd.data()) + "/KernelSU_XXXXXX";
            std::vector<char> tmpdir_template(template_path.begin(), template_path.end());
            tmpdir_template.push_back('\0');
            tmpdir = mkdtemp(tmpdir_template.data());
            if (tmpdir) {
                workdir = tmpdir;
                printf("- Using current directory: %s\n", cwd.data());
            }
        }
    }

    // Fallback to /data/local/tmp
    if (workdir.empty()) {
        std::array<char, 32> tmpdir_buf{};
        (void)strncpy(tmpdir_buf.data(), "/data/local/tmp/KernelSU_XXXXXX", tmpdir_buf.size() - 1);
        tmpdir_buf[tmpdir_buf.size() - 1] = '\0';
        tmpdir = mkdtemp(tmpdir_buf.data());
        if (tmpdir) {
            workdir = tmpdir;
        }
    }

    if (workdir.empty()) {
        LOGE("Failed to create temp directory");
        LOGE("Try setting TMPDIR environment variable to a writable directory");
        return 1;
    }

    // Cleanup function
    auto cleanup = [&workdir]() {
        std::error_code ec;
        fs::remove_all(workdir, ec);
        if (ec) {
            LOGW("Failed to remove temporary directory %s: %s", workdir.c_str(),
                 ec.message().c_str());
        }
    };

    // Find magiskboot
    const std::string magiskboot = find_magiskboot(parsed.magiskboot, workdir);
    if (magiskboot.empty()) {
        cleanup();
        return 1;
    }
    printf("- Using magiskboot: %s\n", magiskboot.c_str());

    // Get or detect KMI
    std::string kmi = parsed.kmi;
    const bool needs_automatic_lkm = parsed.module.empty();
    const bool needs_automatic_partition = parsed.boot_image.empty() && parsed.partition.empty();
    if (kmi.empty() && parsed.ota && (needs_automatic_lkm || needs_automatic_partition)) {
        const std::string target_boot = "/dev/block/by-name/boot" + ota_slot;
        printf("- Trying to auto detect KMI version from %s\n", target_boot.c_str());
        kmi = parse_kmi_from_boot(magiskboot, workdir, target_boot);
        if (kmi.empty()) {
            printf("! Failed to detect KMI from inactive slot boot image\n");
            printf("! Please select an LKM file manually or specify --kmi\n");
            cleanup();
            return 1;
        }
    }
    if (kmi.empty()) {
        kmi = get_current_kmi();
        if (kmi.empty() && (needs_automatic_lkm || needs_automatic_partition)) {
            printf("- Failed to obtain trusted KMI for automatic LKM/partition selection\n");
            printf("- Select both the LKM and boot image/partition manually\n");
            cleanup();
            return 1;
        }
    }
    if (!kmi.empty()) {
        printf("- KMI: %s\n", kmi.c_str());
    }

    // Determine boot image path
    std::string bootimage;
    std::string bootdevice;
    std::string rollback_bootimage;
    const bool patch_file = !parsed.boot_image.empty();

    if (patch_file) {
        bootimage = parsed.boot_image;
        if (access(bootimage.c_str(), R_OK) != 0) {
            LOGE("Boot image not found: %s", bootimage.c_str());
            cleanup();
            return 1;
        }
    } else {
        // Auto-detect boot partition
        std::string partition_name;

        // Determine if we're in replace kernel mode (when --kernel is specified)
        const bool is_replace_kernel = !parsed.kernel.empty();

        if (!parsed.partition.empty()) {
            // User specified partition name (e.g., "init_boot" or "boot")
            partition_name =
                choose_boot_partition(kmi, parsed.ota, &parsed.partition, is_replace_kernel);
        } else {
            // Auto-detect: choose_boot_partition returns full path with slot
            partition_name = choose_boot_partition(kmi, parsed.ota, nullptr, is_replace_kernel);
        }

        if (partition_name.empty()) {
            LOGE("Failed to resolve a safe boot partition");
            cleanup();
            return 1;
        }
        printf("- Bootdevice: %s\n", partition_name.c_str());

        bootimage = workdir + "/boot.img";
        if (!exec_dd(partition_name, bootimage)) {
            LOGE("Failed to read boot image from %s", partition_name.c_str());
            cleanup();
            return 1;
        }
        bootdevice = partition_name;
        rollback_bootimage = bootimage;

        if (is_boot_partition_device(bootdevice)) {
            if (const auto backup = find_direct_lkm_backup(get_slot_suffix(parsed.ota))) {
                const auto backup_status = validate_direct_lkm_backup(*backup, magiskboot, workdir);
                if (backup_status == DirectLkmImageStatus::kNoCapsule) {
                    const fs::path patch_source = fs::path(workdir) / "boot-original.img";
                    if (!copy_file_data(*backup, patch_source, 0644, false)) {
                        LOGE("Failed to stage original boot backup %s: %s",
                             backup->string().c_str(), strerror(errno));
                        cleanup();
                        return 1;
                    }
                    bootimage = patch_source.string();
                    printf(
                        "- Using verified original boot backup for traditional ramdisk patch: %s\n",
                        backup->string().c_str());
                } else if (backup_status == DirectLkmImageStatus::kContainsCapsule) {
                    printf("- Direct-LKM backup contained an embedded capsule; falling back to "
                           "current boot\n");
                } else {
                    printf("- Could not verify direct-LKM backup; falling back to current boot\n");
                }
            }
        }
    }

    // Prepare LKM module
    printf("- Preparing assets\n");
    const std::string kmod_file = workdir + "/kernelsu.ko";

    if (!parsed.module.empty()) {
        // Use specified module
        if (!copy_file_data(parsed.module, kmod_file)) {
            LOGE("Failed to copy kernel module from %s", parsed.module.c_str());
            cleanup();
            return 1;
        }
    } else {
        // Try to extract LKM from embedded assets first
        const std::string kmi_lkm_name = kmi + "_kernelsu.ko";
        printf("- KMI: %s\n", kmi.c_str());

        if (copy_asset_to_file(kmi_lkm_name, kmod_file)) {
            printf("- Using embedded LKM: %s\n", kmi_lkm_name.c_str());
        } else {
            // Fallback: try to find LKM from known locations
            const std::vector<std::string> search_paths = {
                std::string(BINARY_DIR) + kmi_lkm_name,  std::string(BINARY_DIR) + "kernelsu.ko",
                std::string(WORKING_DIR) + kmi_lkm_name, std::string(WORKING_DIR) + "kernelsu.ko",
                "/data/local/tmp/" + kmi_lkm_name,       "/data/local/tmp/kernelsu.ko",
            };

            bool found = false;
            for (const auto& path : search_paths) {
                if (access(path.c_str(), R_OK) == 0) {
                    printf("- Found LKM at %s\n", path.c_str());
                    if (copy_file_data(path, kmod_file)) {
                        found = true;
                        break;
                    }
                }
            }

            if (!found) {
                // List available KMIs from embedded assets
                auto supported = list_supported_kmi();

                printf("\n");
                printf("! No LKM module found for KMI: %s\n", kmi.c_str());
                printf("!\n");
                if (!supported.empty()) {
                    printf("! Supported KMIs in this build:\n");
                    for (const auto& k : supported) {
                        printf("!   - %s\n", k.c_str());
                    }
                    printf("!\n");
                }
                printf("! Please select an LKM file in Manager, or place it at:\n");
                printf("!   %s%s\n", BINARY_DIR, kmi_lkm_name.c_str());
                printf("!\n");
                printf("! You can download LKM from:\n");
                printf("!   https://github.com/Anatdx/YukiSU/releases\n");
                printf("\n");
                cleanup();
                return 1;
            }
        }
    }

    if (have_boot_uts_config) {
        const auto supports_uts_boot = lkm_supports_uts_boot_params(kmod_file);
        if (!supports_uts_boot.has_value()) {
            LOGE("Failed to inspect selected LKM for UTS boot parameter support");
            cleanup();
            return 1;
        }
        if (!*supports_uts_boot) {
            LOGE("Selected LKM does not support boot-global UTS configuration");
            LOGE("Missing required module parameter marker: parmtype=uts_boot_global:bool");
            LOGE("Select a UTS-capable YukiSU LKM or remove --uts-config");
            cleanup();
            return 1;
        }
        printf("- Selected LKM supports UTS boot-global parameters\n");
    }

    // Always inject verification mode (and SuperKey hash if set).
    // Pure signature mode (no superkey) still needs flags=0 to be explicitly written,
    // otherwise the LKM may have stale/wrong values and signature verification fails.
    if (!parsed.superkey.empty()) {
        printf("- Injecting SuperKey into LKM\n");
    } else if (parsed.signature_bypass) {
        printf("- Warning: signature_bypass requires superkey to be set, ignoring\n");
    }
    inject_superkey_to_lkm(kmod_file, parsed.superkey, parsed.signature_bypass);

    // Prepare init if specified
    const std::string init_file = workdir + "/init";
    if (!parsed.init.empty()) {
        if (!copy_file_data(parsed.init, init_file, 0755)) {
            LOGE("Failed to copy init from %s", parsed.init.c_str());
            cleanup();
            return 1;
        }
    } else {
        // Try to extract ksuinit from embedded assets first.
        if (copy_asset_to_file("ksuinit", init_file)) {
            printf("- Using embedded ksuinit\n");
        } else {
            // Fallback: check standard location
            const std::string ksuinit_path = std::string(BINARY_DIR) + "ksuinit";
            if (access(ksuinit_path.c_str(), R_OK) == 0 &&
                copy_file_data(ksuinit_path, init_file, 0755)) {
                printf("- Using ksuinit from %s\n", ksuinit_path.c_str());
            } else {
                LOGE("ksuinit not found in embedded assets or %s", ksuinit_path.c_str());
                LOGE("Please install KernelSU Manager or rebuild ksud with ksuinit embedded");
                cleanup();
                return 1;
            }
        }
    }
    chmod(init_file.c_str(), 0755);

    // Unpack boot image (must run in workdir so output files go there)
    printf("- Unpacking boot image\n");
    (void)fflush(stdout);
    printf("- magiskboot: %s\n", magiskboot.c_str());
    printf("- bootimage: %s\n", bootimage.c_str());
    printf("- workdir: %s\n", workdir.c_str());

    // Verify boot image exists and is readable
    struct stat boot_stat{};
    if (stat(bootimage.c_str(), &boot_stat) != 0) {
        LOGE("Boot image not accessible: %s (errno=%d)", bootimage.c_str(), errno);
        cleanup();
        return 1;
    }
    printf("- Boot image size: %ld bytes\n", static_cast<long>(boot_stat.st_size));

    // Try normal unpack first (with decompress). On some devices LZ4_LEGACY in-process decompress
    // crashes (SIGSEGV, exit 139); then we retry with --skip-decomp and tell user to use PC.
    std::vector<std::string> unpack_args = {"unpack", bootimage};  // NOLINT(misc-const-correctness)
    auto unpack_result = exec_command_magiskboot(magiskboot, unpack_args, workdir);
    printf("- unpack exit code: %d\n", unpack_result.exit_code);
    if (!unpack_result.stdout_str.empty()) {
        printf("- stdout: %s\n", unpack_result.stdout_str.c_str());
    }
    if (!unpack_result.stderr_str.empty()) {
        printf("- stderr: %s\n", unpack_result.stderr_str.c_str());
    }

#ifdef __ANDROID__
    constexpr int SIGSEGV_EXIT = 128 + 11;  // 139
    if (unpack_result.exit_code == SIGSEGV_EXIT) {
        printf(
            "- Unpack crashed (SIGSEGV); retrying with --skip-decomp to avoid LZ4 decompress.\n");
        unpack_args.push_back("--skip-decomp");
        unpack_result = exec_command_magiskboot(magiskboot, unpack_args, workdir);
        printf("- unpack (skip-decomp) exit code: %d\n", unpack_result.exit_code);
        if (unpack_result.exit_code != 0) {
            LOGE("magiskboot unpack failed with exit code %d", unpack_result.exit_code);
            cleanup();
            return 1;
        }
        const std::string ramdisk_cpio = workdir + "/ramdisk.cpio";
        if (has_lz4_legacy_magic(ramdisk_cpio)) {
            LOGE("Ramdisk is LZ4_LEGACY; on-device decompress crashed (SIGSEGV), so it was "
                 "skipped.");
            LOGE("Cannot continue without decompressed ramdisk. Patch the boot image on a PC "
                 "instead.");
            cleanup();
            return 1;
        }
    } else
#endif  // #ifdef __ANDROID__
        if (unpack_result.exit_code != 0) {
            LOGE("magiskboot unpack failed with exit code %d", unpack_result.exit_code);
            cleanup();
            return 1;
        }

    const auto direct_lkm_status = restore_direct_lkm_kernel(workdir);
    if (direct_lkm_status == DirectLkmRestoreStatus::kFailed) {
        cleanup();
        return 1;
    }
    std::string backup_source = bootimage;
    if (direct_lkm_status == DirectLkmRestoreStatus::kRestored) {
        backup_source = workdir + "/direct-lkm-restored.img";
        auto restore_repack =
            exec_command_magiskboot(magiskboot, {"repack", bootimage, backup_source}, workdir);
        std::error_code restore_repack_error;
        if (restore_repack.exit_code != 0 ||
            !fs::is_regular_file(backup_source, restore_repack_error) || restore_repack_error) {
            LOGE("Failed to repack boot image after removing the direct-LKM capsule");
            if (!restore_repack.stdout_str.empty())
                LOGE("magiskboot stdout: %s", restore_repack.stdout_str.c_str());
            if (!restore_repack.stderr_str.empty())
                LOGE("magiskboot stderr: %s", restore_repack.stderr_str.c_str());
            cleanup();
            return 1;
        }
    }

    // Find ramdisk
    std::string ramdisk;
    const std::vector<std::string> ramdisk_candidates_do_patch = {
        workdir + "/ramdisk.cpio", workdir + "/vendor_ramdisk/init_boot.cpio",
        workdir + "/vendor_ramdisk/ramdisk.cpio"};

    for (const auto& candidate : ramdisk_candidates_do_patch) {
        if (access(candidate.c_str(), R_OK) == 0) {
            ramdisk = candidate;
            break;
        }
    }

    if (ramdisk.empty()) {
        printf("- No ramdisk found, creating default\n");
        ramdisk = workdir + "/ramdisk.cpio";
        // Create empty ramdisk (use a valid entry name; "." is invalid for some magiskboot builds)
        if (!do_cpio_cmd(magiskboot, workdir, ramdisk, "mkdir 000 .backup")) {
            LOGE("Failed to create default ramdisk");
            cleanup();
            return 1;
        }
    } else {
        // Unconditionally reject LZ4 ramdisk before any cpio (avoids cpio parsing LZ4 as cpio →
        // huge cache/hang).
        if (has_lz4_legacy_magic(ramdisk)) {
            LOGE("Ramdisk is LZ4 compressed; cannot patch. Use PC to patch this boot image.\n");
            cleanup();
            return 1;
        }
    }

    // Check for Magisk
    if (is_magisk_patched(magiskboot, workdir, ramdisk)) {
        LOGE("Cannot work with Magisk patched image");
        cleanup();
        return 1;
    }

    printf("- Adding KernelSU LKM\n");
    const bool already_patched = is_kernelsu_patched(magiskboot, workdir, ramdisk);

    if (!already_patched) {
        // Backup init if it exists
        if (magiskboot_query({"cpio", ramdisk, "exists init"}) == 0) {
            do_cpio_cmd(magiskboot, workdir, ramdisk, "mv init init.real");
        }
    }

    // Add init and kernelsu.ko (use workdir for relative paths in cpio add)
    if (!do_cpio_cmd(magiskboot, workdir, ramdisk, "add 0755 init init")) {
        cleanup();
        return 1;
    }
    if (!do_cpio_cmd(magiskboot, workdir, ramdisk, "add 0755 kernelsu.ko kernelsu.ko")) {
        cleanup();
        return 1;
    }

    std::vector<std::string> ksu_config;
    if (parsed.allow_shell) {
        printf("- Adding allow shell config\n");
        ksu_config.emplace_back("allow_shell=1");
    }
    if (parsed.no_custom_rc) {
        printf("- Adding no custom rc config\n");
        ksu_config.emplace_back("norc=1");
    }
    if (have_boot_uts_config) {
        auto uts_params = encode_uts_boot_module_params(boot_uts_config);
        ksu_config.insert(ksu_config.end(), uts_params.begin(), uts_params.end());
        printf("- Adding encoded UTS boot-global config\n");
    }

    if (!ksu_config.empty()) {
        std::string config_text;
        for (size_t i = 0; i < ksu_config.size(); ++i) {
            if (i != 0)
                config_text += ' ';
            config_text += ksu_config[i];
        }
        if (!write_file(workdir + "/ksu_config", config_text)) {
            LOGE("Failed to create ksu_config");
            cleanup();
            return 1;
        }
        if (!do_cpio_cmd(magiskboot, workdir, ramdisk, "add 0644 ksu_config ksu_config")) {
            cleanup();
            return 1;
        }
    } else {
        do_cpio_cmd(magiskboot, workdir, ramdisk, "rm ksu_config");
    }

    if (magiskboot_query({"cpio", ramdisk, "exists ksu_allow_shell"}) == 0) {
        printf("- Removing legacy allow shell config\n");
        do_cpio_cmd(magiskboot, workdir, ramdisk, "rm ksu_allow_shell");
    }

    if (parsed.enable_adbd || !parsed.adb_debug_prop.empty()) {
        printf("- Adding adb debug props\n");
        if (!write_file(workdir + "/force_debuggable", "")) {
            LOGE("Failed to create force_debuggable");
            cleanup();
            return 1;
        }
        if (!do_cpio_cmd(magiskboot, workdir, ramdisk,
                         "add 0644 force_debuggable force_debuggable")) {
            cleanup();
            return 1;
        }

        std::string adb_props;
        if (parsed.enable_adbd) {
            printf("- Enabling adbd debug props\n");
            adb_props = "ro.debuggable=1\nro.force.debuggable=1\nro.adb.secure=0\n";
        }
        if (!parsed.adb_debug_prop.empty()) {
            printf("- Appending custom adb props\n");
            adb_props += parsed.adb_debug_prop;
            if (parsed.adb_debug_prop.back() != '\n')
                adb_props += '\n';
        }
        if (!write_file(workdir + "/adb_debug.prop", adb_props)) {
            LOGE("Failed to create adb_debug.prop");
            cleanup();
            return 1;
        }
        if (!do_cpio_cmd(magiskboot, workdir, ramdisk, "add 0644 adb_debug.prop adb_debug.prop")) {
            cleanup();
            return 1;
        }
    } else {
        if (magiskboot_query({"cpio", ramdisk, "exists force_debuggable"}) == 0) {
            printf("- Removing /force_debuggable\n");
            do_cpio_cmd(magiskboot, workdir, ramdisk, "rm force_debuggable");
        }

        if (magiskboot_query({"cpio", ramdisk, "exists adb_debug.prop"}) == 0) {
            printf("- Removing /adb_debug.prop\n");
            do_cpio_cmd(magiskboot, workdir, ramdisk, "rm adb_debug.prop");
        }
    }

    // Remove the legacy embedded module when repatching an image created by an older manager.
    if (magiskboot_query({"cpio", ramdisk, "exists kasumi.ko"}) == 0) {
        do_cpio_cmd(magiskboot, workdir, ramdisk, "rm kasumi.ko");
    }

    // Direct flashing automatically backs up stock images. --backup also allows an explicitly
    // selected file to be treated as stock, even when it appears to have been patched already.
    if (parsed.backup || (!already_patched && parsed.flash)) {
        if (!do_backup(magiskboot, workdir, ramdisk, backup_source)) {
            printf("- Warning: Backup stock image failed\n");
        }
    }

    // Repack boot image (must run in workdir where unpack output files are)
    // Pass explicit output path for compatibility with older magiskboot variants
    // that require: repack <in-boot.img> <out-boot.img>.
    // Output filename must match input format: boot -> new-boot.img, init_boot -> new-init_boot.img
    // (aligned with Magisk payload extract: partition.partition_name -> {partition}.img)
    const bool is_init_boot =
        (patch_file && bootimage.find("init_boot") != std::string::npos) ||
        (!bootdevice.empty() && bootdevice.find("init_boot") != std::string::npos);
    const std::string new_boot =
        workdir + "/" + (is_init_boot ? "new-init_boot.img" : "new-boot.img");
    printf("- Repacking boot image\n");
    (void)fflush(stdout);
    // MagiskbootAlone supports LZ4_LEGACY, GZIP, and LZ4 compression natively.
    // Do NOT use --skip-comp: the ramdisk must be recompressed to fit the
    // partition. Without recompression the uncompressed ramdisk makes the output
    // image far larger than the original, exhausting cache space and overflowing
    // the boot partition.
    auto repack_result =
        exec_command_magiskboot(magiskboot, {"repack", bootimage, new_boot}, workdir);
    if (repack_result.exit_code != 0) {
        LOGE("magiskboot repack failed (exit code %d)", repack_result.exit_code);
        if (!repack_result.stdout_str.empty()) {
            LOGE("magiskboot repack stdout: %s", repack_result.stdout_str.c_str());
        }
        if (!repack_result.stderr_str.empty()) {
            LOGE("magiskboot repack stderr: %s", repack_result.stderr_str.c_str());
        }
        cleanup();
        return 1;
    }
    std::error_code output_error;
    if (!fs::exists(new_boot, output_error) || output_error) {
        LOGE("magiskboot repack reported success but output not found: %s", new_boot.c_str());
        LOGE("Current magiskboot may be an incomplete build (unpack/repack stubs).");
        LOGE("Please use a full magiskboot implementation from upstream Magisk.");
        cleanup();
        return 1;
    }

    std::optional<DirectLkmBootRestore> companion_boot_restore;
    if (parsed.flash && !bootdevice.empty()) {
        const std::string companion_bootdevice =
            "/dev/block/by-name/boot" + get_slot_suffix(parsed.ota);
        if (companion_bootdevice != bootdevice) {
            DirectLkmBootRestore prepared;
            const auto companion_status = prepare_direct_lkm_boot_restore(
                workdir, magiskboot, companion_bootdevice, &prepared);
            if (companion_status == DirectLkmRestoreStatus::kFailed) {
                cleanup();
                return 1;
            }
            if (companion_status == DirectLkmRestoreStatus::kRestored)
                companion_boot_restore = std::move(prepared);
        }
    }

    // Output patched image
    if (patch_file) {
        const std::string output_dir = parsed.out.empty() ? "." : parsed.out;
        std::string name = parsed.out_name;
        if (name.empty()) {
            const time_t now = time(nullptr);
            const struct tm* tm_info = localtime(&now);
            std::array<char, 32> time_str{};
            if (tm_info != nullptr &&
                strftime(time_str.data(), time_str.size(), "%Y%m%d_%H%M%S", tm_info) != 0) {
                name = std::string("kernelsu_patched_") + time_str.data() + ".img";
            } else {
                name = "kernelsu_patched.img";
            }
        }

        const std::string output_image = output_dir + "/" + name;

        if (!copy_file_data(new_boot, output_image)) {
            LOGE("Failed to write output file");
            cleanup();
            return 1;
        }

        printf("- Output file is written to\n");
        printf("- %s\n", output_image.c_str());
    }

    // Flash if requested
    if (parsed.flash && !bootdevice.empty()) {
        printf("- Flashing new boot image\n");
        if (!flash_boot(bootdevice, new_boot)) {
            LOGE("Failed to flash boot image");
            cleanup();
            return 1;
        }
        if (companion_boot_restore &&
            !flash_boot(companion_boot_restore->device, companion_boot_restore->restored_image)) {
            LOGE("Failed to restore direct-LKM boot image; rolling back both partitions");
            if (!flash_boot(companion_boot_restore->device, companion_boot_restore->original_image))
                LOGE("Failed to roll back direct-LKM boot image");
            const std::string& rollback_image =
                rollback_bootimage.empty() ? bootimage : rollback_bootimage;
            if (!flash_boot(bootdevice, rollback_image))
                LOGE("Failed to roll back traditional boot patch");
            cleanup();
            return 1;
        }
        if (companion_boot_restore)
            printf("- Removed direct-LKM capsule from %s\n",
                   companion_boot_restore->device.c_str());
    }

    cleanup();

    printf("- Done!\n");
    return 0;
}

// Parse boot restore arguments
struct BootRestoreArgs {
    std::string boot_image;  // -b, --boot
    bool flash = false;      // -f, --flash
    std::string magiskboot;  // --magiskboot
    std::string out_name;    // --out-name
    bool help = false;       // -h, --help
    bool valid = true;
    std::string invalid_reason;
};

// boot-restore flashes and prunes the stock backups, so it gets the same
// treatment as boot-patch: an argument this parser cannot place stops the run
// instead of leaving -b empty and letting the partition path take over.
void print_boot_restore_usage() {
    printf("Usage: ksud boot-restore [-b <boot.img>] [options]\n"
           "\n"
           "Without -b the boot partition is detected and read.\n"
           "Without -f nothing is written to any partition.\n"
           "\n"
           "  -b, --boot <img>       restore from this image instead of the partition\n"
           "  -f, --flash            write the restored image back to the partition\n"
           "      --out-name <name>  filename for the restored image\n"
           "      --magiskboot <path>  accepted for compatibility; ignored\n"
           "  -h, --help             show this message\n");
}

BootRestoreArgs parse_boot_restore_args(const std::vector<std::string>& args) {
    BootRestoreArgs result;

    auto reject = [&result](std::string reason) {
        if (result.valid) {
            result.valid = false;
            result.invalid_reason = std::move(reason);
        }
    };

    for (size_t i = 0; i < args.size(); i++) {
        const std::string& arg = args[i];

        auto take_value = [&](std::string& destination) {
            if (i + 1 >= args.size()) {
                reject(arg + " requires a value");
                return;
            }
            destination = args[++i];
            if (destination.empty())
                reject(arg + " requires a non-empty value");
        };

        if (arg == "-h" || arg == "--help") {
            result.help = true;
        } else if (arg == "-b" || arg == "--boot") {
            take_value(result.boot_image);
        } else if (arg == "-f" || arg == "--flash") {
            result.flash = true;
        } else if (arg == "--magiskboot") {
            take_value(result.magiskboot);
        } else if (arg == "--out-name") {
            take_value(result.out_name);
        } else {
            reject("unknown argument: " + arg);
        }
    }

    return result;
}

std::string make_restore_output_name(const std::string& requested) {
    if (!requested.empty())
        return requested;
    const time_t now = time(nullptr);
    const struct tm* tm_info = localtime(&now);
    std::array<char, 32> time_str{};
    if (tm_info != nullptr &&
        strftime(time_str.data(), time_str.size(), "%Y%m%d_%H%M%S", tm_info) != 0)
        return std::string("kernelsu_restore_") + time_str.data() + ".img";
    return "kernelsu_restore.img";
}

}  // namespace

int boot_patch(const std::vector<std::string>& args) {
    return boot_patch_impl(args);
}

int boot_restore(const std::vector<std::string>& args) {
    auto parsed = parse_boot_restore_args(args);
    if (parsed.help) {
        print_boot_restore_usage();
        return 0;
    }
    if (!parsed.valid) {
        LOGE("boot-restore: %s", parsed.invalid_reason.c_str());
        print_boot_restore_usage();
        return 1;
    }
    // Create temp working directory
    std::array<char, 32> tmpdir_buf{};
    (void)strncpy(tmpdir_buf.data(), "/data/local/tmp/KernelSU_XXXXXX", tmpdir_buf.size() - 1);
    tmpdir_buf[tmpdir_buf.size() - 1] = '\0';
    const char* tmpdir = mkdtemp(tmpdir_buf.data());
    if (!tmpdir) {
        LOGE("Failed to create temp directory");
        return 1;
    }
    std::string workdir = tmpdir;

    auto cleanup = [&workdir]() {
        std::error_code ec;
        fs::remove_all(workdir, ec);
        if (ec) {
            LOGW("Failed to remove temporary directory %s: %s", workdir.c_str(),
                 ec.message().c_str());
        }
    };

    // Find magiskboot
    const std::string magiskboot = find_magiskboot(parsed.magiskboot, workdir);
    if (magiskboot.empty()) {
        cleanup();
        return 1;
    }

    // Validate external backups before using them. A backup containing the
    // direct-LKM capsule is itself patched and must never be flashed as stock.
    if (!parsed.flash && !parsed.boot_image.empty()) {
        const fs::path backup_path = parsed.boot_image + ".yukisu-original.img";
        std::error_code backup_error;
        if (fs::is_regular_file(backup_path, backup_error) && !backup_error) {
            const auto backup_status = validate_direct_lkm_backup(backup_path, magiskboot, workdir);
            if (backup_status == DirectLkmImageStatus::kNoCapsule) {
                const std::string output_image = "./" + make_restore_output_name(parsed.out_name);
                if (!copy_file_data(backup_path, output_image)) {
                    LOGE("Failed to restore boot backup %s: %s", backup_path.string().c_str(),
                         strerror(errno));
                    cleanup();
                    return 1;
                }
                printf("- Restored verified original boot from external backup\n");
                printf("- Output file is written to\n");
                printf("- %s\n", output_image.c_str());
                printf("- Restore successfully\n");
                printf("- Done!\n");
                cleanup();
                return 0;
            }
            if (backup_status == DirectLkmImageStatus::kContainsCapsule)
                printf("- External backup contained an embedded capsule; falling back to manual "
                       "restore\n");
            else
                printf("- Could not verify external backup; falling back to manual restore\n");
        }
    }

    bool prefer_boot_partition = false;
    std::string restore_slot;
    if (parsed.flash && parsed.boot_image.empty()) {
        restore_slot = get_slot_suffix(false);
        if (!restore_slot.empty()) {
            const fs::path bootdevice = fs::path("/dev/block/by-name/boot" + restore_slot);
            if (const auto backup = find_direct_lkm_backup(restore_slot)) {
                const auto backup_status = validate_direct_lkm_backup(*backup, magiskboot, workdir);
                if (backup_status == DirectLkmImageStatus::kNoCapsule) {
                    printf("- Restoring verified original boot backup: %s\n",
                           backup->string().c_str());
                    if (!flash_boot(bootdevice.string(), backup->string())) {
                        LOGE("Failed to restore original boot backup to %s",
                             bootdevice.string().c_str());
                        cleanup();
                        return 1;
                    }
                    printf("- Restored original boot from direct-LKM backup\n");
                    cleanup();
                    printf("- Restore successfully\n");
                    printf("- Done!\n");
                    return 0;
                }
                prefer_boot_partition = true;
                if (backup_status == DirectLkmImageStatus::kContainsCapsule)
                    printf("- Direct-LKM backup was patched; deleted it and falling back to kernel "
                           "cleanup\n");
                else
                    printf("- Direct-LKM backup could not be verified; falling back to kernel "
                           "cleanup\n");
            } else {
                // A missing backup is the manual ImgPatch recovery case. Probe
                // boot before allowing automatic selection to choose init_boot.
                const fs::path probe = fs::path(workdir) / "boot-probe.img";
                if (exec_dd(bootdevice.string(), probe.string()) &&
                    inspect_direct_lkm_image(probe, magiskboot, workdir) ==
                        DirectLkmImageStatus::kContainsCapsule) {
                    prefer_boot_partition = true;
                    printf("- Direct-LKM capsule found in boot; using manual kernel cleanup\n");
                }
            }
        }
    }

    // Get KMI for partition detection
    const std::string kmi = get_current_kmi();
    if (kmi.empty() && parsed.boot_image.empty() && !prefer_boot_partition) {
        LOGE("Trusted KMI is unavailable; refusing automatic restore partition selection");
        cleanup();
        return 1;
    }

    // Determine boot image path
    std::string bootimage;
    std::string bootdevice;

    if (!parsed.boot_image.empty()) {
        bootimage = parsed.boot_image;
        if (access(bootimage.c_str(), R_OK) != 0) {
            LOGE("Boot image not found: %s", bootimage.c_str());
            cleanup();
            return 1;
        }
    } else {
        // Auto-detect boot partition (restore doesn't replace kernel)
        const std::string partition_name = prefer_boot_partition
                                               ? "/dev/block/by-name/boot" + restore_slot
                                               : choose_boot_partition(kmi, false, nullptr, false);
        if (partition_name.empty()) {
            LOGE("Failed to resolve a safe boot partition");
            cleanup();
            return 1;
        }
        printf("- Bootdevice: %s\n", partition_name.c_str());

        bootimage = workdir + "/boot.img";
        if (!exec_dd(partition_name, bootimage)) {
            LOGE("Failed to read boot image");
            cleanup();
            return 1;
        }
        bootdevice = partition_name;
    }

    // Unpack boot image (must run in workdir so output files go there)
    printf("- Unpacking boot image\n");
    std::vector<std::string> unpack_args_restore = {"unpack",
                                                    bootimage};  // NOLINT(misc-const-correctness)
    auto unpack_result = exec_command_magiskboot(magiskboot, unpack_args_restore, workdir);
#ifdef __ANDROID__
    constexpr int SIGSEGV_EXIT_R = 128 + 11;  // 139
    if (unpack_result.exit_code == SIGSEGV_EXIT_R) {
        printf("- Unpack crashed (SIGSEGV); retrying with --skip-decomp.\n");
        unpack_args_restore.push_back("--skip-decomp");
        unpack_result = exec_command_magiskboot(magiskboot, unpack_args_restore, workdir);
    }
    if (unpack_result.exit_code == 0) {
        const std::string rd_cpio = workdir + "/ramdisk.cpio";
        if (has_lz4_legacy_magic(rd_cpio)) {
            LOGE("Ramdisk is LZ4_LEGACY; on-device decompress crashed (SIGSEGV), so it was "
                 "skipped.");
            LOGE("Restore or patch the boot image on a PC instead.");
            cleanup();
            return 1;
        }
    }
#endif  // #ifdef __ANDROID__
    if (unpack_result.exit_code != 0) {
        LOGE("magiskboot unpack failed");
        if (!unpack_result.stderr_str.empty()) {
            LOGE("stderr: %s", unpack_result.stderr_str.c_str());
        }
        cleanup();
        return 1;
    }

    std::string new_boot;
    bool from_backup = false;
    bool direct_restore = false;

    // Direct-LKM images have no ramdisk payload to restore. Remove the capsule
    // from the unpacked kernel and repack the complete boot container below.
    const std::vector<std::string> kernel_candidates = {workdir + "/kernel",
                                                        workdir + "/kernel.img"};
    for (const auto& candidate : kernel_candidates) {
        std::vector<std::uint8_t> kernel_bytes;
        if (!read_file_bytes(candidate, &kernel_bytes))
            continue;
        if (!boot::lkm_image::contains_capsule(kernel_bytes))
            continue;
        auto restored = boot::lkm_image::remove_capsule(kernel_bytes);
        if (!restored) {
            LOGE("Direct-LKM restore failed: %s", restored.error().message.c_str());
            cleanup();
            return 1;
        }
        if (!write_file_bytes(candidate, restored.value().data(), restored.value().size())) {
            LOGE("Failed to write restored kernel");
            cleanup();
            return 1;
        }
        const std::string out_img = workdir + "/new-boot.img";
        printf("- Removing direct-LKM capsule\n");
        auto repack_result =
            exec_command_magiskboot(magiskboot, {"repack", bootimage, out_img}, workdir);
        std::error_code repacked_error;
        if (repack_result.exit_code != 0 || !fs::is_regular_file(out_img, repacked_error) ||
            repacked_error) {
            LOGE("magiskboot repack failed");
            if (!repack_result.stdout_str.empty())
                LOGE("magiskboot stdout: %s", repack_result.stdout_str.c_str());
            if (!repack_result.stderr_str.empty())
                LOGE("magiskboot stderr: %s", repack_result.stderr_str.c_str());
            cleanup();
            return 1;
        }
        new_boot = out_img;
        direct_restore = true;
        break;
    }

    if (!direct_restore) {
        // Find ramdisk
        std::string ramdisk;
        const std::vector<std::string> ramdisk_candidates = {
            workdir + "/ramdisk.cpio", workdir + "/vendor_ramdisk/init_boot.cpio",
            workdir + "/vendor_ramdisk/ramdisk.cpio"};

        for (const auto& candidate : ramdisk_candidates) {
            if (access(candidate.c_str(), R_OK) == 0) {
                ramdisk = candidate;
                break;
            }
        }

        if (ramdisk.empty()) {
            LOGE("No compatible ramdisk found");
            cleanup();
            return 1;
        }

        // Check if patched by KernelSU
        if (!is_kernelsu_patched(magiskboot, workdir, ramdisk)) {
            LOGE("Boot image is not patched by KernelSU");
            cleanup();
            return 1;
        }

        // Try to find backup
        if (magiskboot_query({"cpio", ramdisk, "exists " + std::string(BACKUP_FILENAME)}) == 0) {
            // Extract backup sha1
            const std::string backup_file = workdir + "/" + BACKUP_FILENAME;
            exec_command_magiskboot(
                magiskboot,
                {"cpio", ramdisk, "extract " + std::string(BACKUP_FILENAME) + " " + backup_file},
                workdir);

            auto sha_content = read_file(backup_file);
            if (sha_content) {
                const std::string sha = trim(*sha_content);
                const std::string backup_path =
                    std::string(KSU_BACKUP_DIR) + KSU_BACKUP_FILE_PREFIX + sha;

                if (access(backup_path.c_str(), R_OK) == 0) {
                    new_boot = backup_path;
                    from_backup = true;
                    clean_backup(sha);
                } else {
                    printf("- Warning: no backup %s found!\n", backup_path.c_str());
                }
            }
        } else {
            printf("- Backup info is absent!\n");
        }

        // If no backup, manually remove KernelSU
        if (!from_backup) {
            // Remove kernelsu.ko
            do_cpio_cmd(magiskboot, workdir, ramdisk, "rm kernelsu.ko");

            // Remove the legacy embedded module if present.
            if (magiskboot_query({"cpio", ramdisk, "exists kasumi.ko"}) == 0) {
                do_cpio_cmd(magiskboot, workdir, ramdisk, "rm kasumi.ko");
            }

            // Restore init if init.real exists
            if (magiskboot_query({"cpio", ramdisk, "exists init.real"}) == 0) {
                do_cpio_cmd(magiskboot, workdir, ramdisk, "mv init.real init");
            }

            // Repack (must run in workdir where unpack output files are)
            // Output filename must match input format: boot -> new-boot.img, init_boot ->
            // new-init_boot.img
            const bool is_init_boot_restore =
                (!parsed.boot_image.empty() &&
                 parsed.boot_image.find("init_boot") != std::string::npos) ||
                (!bootdevice.empty() && bootdevice.find("init_boot") != std::string::npos);
            const std::string out_img =
                workdir + "/" + (is_init_boot_restore ? "new-init_boot.img" : "new-boot.img");
            printf("- Repacking boot image\n");
            auto repack_result =
                exec_command_magiskboot(magiskboot, {"repack", bootimage, out_img}, workdir);
            if (repack_result.exit_code != 0) {
                LOGE("magiskboot repack failed");
                cleanup();
                return 1;
            }
            new_boot = out_img;
        }
    }

    // Output restored image
    if (!parsed.boot_image.empty()) {
        std::string name = parsed.out_name;
        if (name.empty()) {
            name = make_restore_output_name("");
        }

        const std::string output_image = "./" + name;

        if (!copy_file_data(new_boot, output_image)) {
            LOGE("Failed to write output file");
            cleanup();
            return 1;
        }

        printf("- Output file is written to\n");
        printf("- %s\n", output_image.c_str());
    }

    // Flash if requested
    if (parsed.flash && !bootdevice.empty()) {
        if (from_backup) {
            printf("- Flashing new boot image from %s\n", new_boot.c_str());
        } else {
            printf("- Flashing new boot image\n");
        }
        if (!flash_boot(bootdevice, new_boot)) {
            LOGE("Failed to flash boot image");
            cleanup();
            return 1;
        }
    }

    cleanup();
    printf("- Done!\n");
    return 0;
}

namespace {

// Old kernels without UTS View may use the effective release. New kernels must
// use the immutable original identity and fail closed if it is unavailable.
std::string read_kernel_release_from_sysfs() {
    const auto release = read_file("/proc/sys/kernel/osrelease");
    return release ? std::string(trim_view(*release)) : std::string{};
}

std::string parse_kmi_from_release(const std::string& full_version) {
    // Extract major.minor (e.g. "6.6")
    const size_t dot1 = full_version.find('.');
    if (dot1 == std::string::npos)
        return "";
    size_t dot2 = full_version.find('.', dot1 + 1);
    if (dot2 == std::string::npos)
        dot2 = full_version.length();

    std::string major_minor = full_version.substr(0, dot2);

    // Try to find android version (e.g. "android15")
    const size_t android_pos = full_version.find("-android");
    if (android_pos != std::string::npos) {
        const size_t ver_start = android_pos + 8;
        size_t ver_end = full_version.find('-', ver_start);
        if (ver_end == std::string::npos)
            ver_end = full_version.length();

        const std::string android_ver = full_version.substr(ver_start, ver_end - ver_start);
        return "android" + android_ver + "-" + major_minor;
    }

    return major_minor;
}

std::string read_effective_kernel_release() {
    std::string full_version = read_kernel_release_from_sysfs();
    if (!full_version.empty())
        return full_version;

    struct utsname uts{};
    if (uname(&uts) != 0) {
        LOGE("Failed to get uname");
        return "";
    }
    return uts.release;
}

}  // namespace

std::string get_bootstrap_kmi() {
    return parse_kmi_from_release(read_effective_kernel_release());
}

std::string get_current_kmi() {
    std::string full_version;
    bool uts_view_supported = false;
    if (!get_uts_view_original_release(&full_version, &uts_view_supported)) {
        LOGE("UTS View original kernel identity is unavailable; refusing KMI auto-detection");
        return "";
    }
    if (!uts_view_supported)
        full_version = read_effective_kernel_release();
    return parse_kmi_from_release(full_version);
}

int boot_info_current_kmi() {
    const std::string kmi = get_current_kmi();
    if (kmi.empty()) {
        printf("Failed to get current KMI\n");
        return 1;
    }
    printf("%s\n", kmi.c_str());
    return 0;
}

int boot_info_target_kmi(bool ota, const std::string& boot_image) {
    if (!ota && boot_image.empty())
        return boot_info_current_kmi();

    std::string target_boot = boot_image;
    if (ota) {
        const std::string slot = get_slot_suffix(true);
        if (slot.empty()) {
            printf("Failed to obtain a valid inactive slot suffix\n");
            return 1;
        }
        target_boot = "/dev/block/by-name/boot" + slot;
    }

    std::array<char, 32> tmpdir_buf{};
    (void)strncpy(tmpdir_buf.data(), "/data/local/tmp/KernelSU_XXXXXX", tmpdir_buf.size() - 1);
    tmpdir_buf[tmpdir_buf.size() - 1] = '\0';
    const char* tmpdir = mkdtemp(tmpdir_buf.data());
    if (!tmpdir) {
        LOGE("Failed to create temp directory for target KMI detection");
        return 1;
    }

    const std::string workdir = tmpdir;
    const std::string magiskboot = find_magiskboot("", workdir);
    std::string kmi;
    if (!magiskboot.empty()) {
        kmi = parse_kmi_from_boot(magiskboot, workdir, target_boot);
    }

    std::error_code ec;
    fs::remove_all(workdir, ec);
    if (ec) {
        LOGW("Failed to remove target KMI directory %s: %s", workdir.c_str(), ec.message().c_str());
    }

    if (kmi.empty()) {
        printf("Failed to get target KMI\n");
        return 1;
    }
    printf("%s\n", kmi.c_str());
    return 0;
}

int boot_info_supported_kmis() {
    auto supported = list_supported_kmi();
    if (supported.empty()) {
        printf("No embedded LKMs found\n");
        return 1;
    }
    for (const auto& kmi : supported) {
        printf("%s\n", kmi.c_str());
    }
    return 0;
}

int boot_info_is_ab_device() {
    auto ab_update = getprop("ro.build.ab_update");
    const bool is_ab = ab_update && trim(*ab_update) == "true" && !get_slot_suffix(false).empty();
    printf("%s\n", is_ab ? "true" : "false");
    return 0;
}

std::string get_slot_suffix(bool ota) {
    auto suffix = getprop("ro.boot.slot_suffix");
    if (!suffix) {
        return "";
    }
    *suffix = trim(*suffix);
    if (*suffix != "_a" && *suffix != "_b")
        return "";

    if (ota) {
        // Toggle to other slot
        if (*suffix == "_a")
            return "_b";
        if (*suffix == "_b")
            return "_a";
    }

    return *suffix;
}

int boot_info_slot_suffix(bool ota) {
    const std::string suffix = get_slot_suffix(ota);
    if (ota && suffix.empty()) {
        printf("Failed to obtain a valid inactive slot suffix\n");
        return 1;
    }
    printf("%s\n", suffix.c_str());
    return 0;
}

std::string choose_boot_partition(const std::string& kmi, bool ota,
                                  const std::string* override_partition, bool is_replace_kernel) {
    const std::string slot = get_slot_suffix(ota);
    if (ota && slot.empty())
        return "";

    // If specific partition is specified, use it
    if (override_partition && !override_partition->empty()) {
        // Validate partition name
        if (*override_partition == "boot" || *override_partition == "init_boot" ||
            *override_partition == "vendor_boot") {
            return "/dev/block/by-name/" + *override_partition + slot;
        }
        // Invalid partition name, fallback to auto-detect
    }

    // Android 12 GKI doesn't have init_boot
    const bool skip_init_boot = kmi.find("android12-") == 0;

    // Check if init_boot exists
    std::string init_boot = "/dev/block/by-name/init_boot" + slot;
    struct stat st{};
    const bool init_boot_exist = (stat(init_boot.c_str(), &st) == 0);

    // Use init_boot if:
    // - Not replacing kernel (LKM mode)
    // - init_boot partition exists
    // - Not android12 (which doesn't have init_boot)
    if (!is_replace_kernel && init_boot_exist && !skip_init_boot) {
        return init_boot;
    }

    // Fallback to boot
    return "/dev/block/by-name/boot" + slot;
}

// Return partition name only (without path and slot suffix)
// Used by boot-info default-partition command for manager
std::string get_default_partition_name(const std::string& kmi, bool is_replace_kernel) {
    const std::string slot = get_slot_suffix(false);

    // Android 12 GKI doesn't have init_boot
    const bool skip_init_boot = kmi.find("android12-") == 0;

    // Check if init_boot exists
    const std::string init_boot = "/dev/block/by-name/init_boot" + slot;
    struct stat st{};
    const bool init_boot_exist = (stat(init_boot.c_str(), &st) == 0);

    // Use init_boot if:
    // - Not replacing kernel (LKM mode)
    // - init_boot partition exists
    // - Not android12 (which doesn't have init_boot)
    if (!is_replace_kernel && init_boot_exist && !skip_init_boot) {
        return "init_boot";
    }

    return "boot";
}

int boot_info_default_partition() {
    const std::string kmi = get_current_kmi();
    if (kmi.empty()) {
        printf("Failed to obtain trusted KMI for partition selection\n");
        return 1;
    }
    // Return partition name only, not full path.
    const std::string partition = get_default_partition_name(kmi, false);
    printf("%s\n", partition.c_str());
    return 0;
}

int boot_info_available_partitions() {
    // Return base partition names without the slot suffix.
    // Manager will add slot suffix based on user's choice
    const std::string slot = get_slot_suffix(false);

    const std::array<const char*, 3> candidates = {"boot", "init_boot", "vendor_boot"};

    for (const char* name : candidates) {
        const std::string full_path = std::string("/dev/block/by-name/") + name + slot;
        struct stat st{};
        if (stat(full_path.c_str(), &st) == 0) {
            printf("%s\n", name);
        }
    }

    return 0;
}

}  // namespace ksud
