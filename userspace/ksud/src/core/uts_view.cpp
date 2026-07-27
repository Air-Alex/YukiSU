#include "uts_view.hpp"

#include "../defs.hpp"
#include "../log.hpp"
#include "../utils.hpp"
#include "ksucalls.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace ksud {

namespace {

constexpr uint32_t UTS_CONFIG_MAGIC = 0x55545356;  // "UTSV"
constexpr uint32_t UTS_CONFIG_FILE_VERSION = 2;
constexpr uint32_t UTS_BOOT_CONFIG_VERSION = 1;

struct PersistedUtsConfig {
    uint32_t magic;
    uint32_t version;
    uint32_t size;
    uint32_t reserved;
    ksu_uts_view_config config;
};

static_assert(sizeof(PersistedUtsConfig) == 832, "UTS persistence ABI drift");

const std::string& uts_config_path() {
    static const std::string path = std::string(WORKING_DIR) + ".uts_view_config";
    return path;
}

const std::string& uts_config_lock_path() {
    static const std::string path = std::string(WORKING_DIR) + ".uts_view_config.lock";
    return path;
}

class ScopedUtsConfigLock {
public:
    ScopedUtsConfigLock() {
        if (!ensure_dir_exists(WORKING_DIR))
            return;
        fd_ = open(uts_config_lock_path().c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd_ >= 0 && flock(fd_, LOCK_EX) != 0) {
            close(fd_);
            fd_ = -1;
        }
    }

    ~ScopedUtsConfigLock() {
        if (fd_ < 0)
            return;
        (void)flock(fd_, LOCK_UN);
        close(fd_);
    }

    ScopedUtsConfigLock(const ScopedUtsConfigLock&) = delete;
    ScopedUtsConfigLock& operator=(const ScopedUtsConfigLock&) = delete;
    ScopedUtsConfigLock(ScopedUtsConfigLock&&) = delete;
    ScopedUtsConfigLock& operator=(ScopedUtsConfigLock&&) = delete;

    [[nodiscard]] bool locked() const { return fd_ >= 0; }

private:
    int fd_ = -1;
};

bool field_terminated(const char field[KSU_UTS_NAME_LEN]) {
    return memchr(field, '\0', KSU_UTS_NAME_LEN) != nullptr;
}

void normalize_template(ksu_uts_template* config) {
    if (config == nullptr)
        return;
    if ((config->field_mask & KSU_UTS_FIELD_SYSNAME) != 0 && config->sysname[0] == '\0')
        config->field_mask &= ~KSU_UTS_FIELD_SYSNAME;
    if ((config->field_mask & KSU_UTS_FIELD_NODENAME) != 0 && config->nodename[0] == '\0')
        config->field_mask &= ~KSU_UTS_FIELD_NODENAME;
    if ((config->field_mask & KSU_UTS_FIELD_RELEASE) != 0 && config->release[0] == '\0')
        config->field_mask &= ~KSU_UTS_FIELD_RELEASE;
    if ((config->field_mask & KSU_UTS_FIELD_VERSION) != 0 && config->version[0] == '\0')
        config->field_mask &= ~KSU_UTS_FIELD_VERSION;
    if ((config->field_mask & KSU_UTS_FIELD_MACHINE) != 0 && config->machine[0] == '\0')
        config->field_mask &= ~KSU_UTS_FIELD_MACHINE;
    if ((config->field_mask & KSU_UTS_FIELD_DOMAINNAME) != 0 && config->domainname[0] == '\0')
        config->field_mask &= ~KSU_UTS_FIELD_DOMAINNAME;
}

bool template_valid(const ksu_uts_template& config) {
    if (config.reserved != 0 || (config.field_mask & ~KSU_UTS_FIELD_VALID_MASK) != 0)
        return false;
    if ((config.field_mask & KSU_UTS_FIELD_SYSNAME) != 0 && !field_terminated(config.sysname))
        return false;
    if ((config.field_mask & KSU_UTS_FIELD_NODENAME) != 0 && !field_terminated(config.nodename))
        return false;
    if ((config.field_mask & KSU_UTS_FIELD_RELEASE) != 0 && !field_terminated(config.release))
        return false;
    if ((config.field_mask & KSU_UTS_FIELD_VERSION) != 0 && !field_terminated(config.version))
        return false;
    if ((config.field_mask & KSU_UTS_FIELD_MACHINE) != 0 && !field_terminated(config.machine))
        return false;
    if ((config.field_mask & KSU_UTS_FIELD_DOMAINNAME) != 0 && !field_terminated(config.domainname))
        return false;
    return true;
}

bool config_valid(const ksu_uts_view_config& config) {
    return config.version == KSU_UTS_VIEW_ABI_VERSION && config.size == sizeof(config) &&
           (config.mode & ~KSU_UTS_VIEW_MODE_VALID_MASK) == 0 &&
           (config.update_mask & ~KSU_UTS_CONFIG_UPDATE_VALID_MASK) == 0 &&
           template_valid(config.global) && template_valid(config.deny);
}

bool status_payload_valid(const ksu_uts_view_status& status) {
    constexpr uint32_t valid_status_flags =
        KSU_UTS_STATUS_ORIGINAL_VALID | KSU_UTS_STATUS_BOOT_LOCKED | KSU_UTS_STATUS_LATE_GAPS |
        KSU_UTS_STATUS_LATE_UPDATED | KSU_UTS_STATUS_LATE_CAPTURE;
    return status.size == sizeof(status) && status.source <= KSU_UTS_SOURCE_RUNTIME &&
           status.reserved == 0 && (status.status_flags & ~valid_status_flags) == 0 &&
           (status.status_flags & KSU_UTS_STATUS_ORIGINAL_VALID) != 0 &&
           (status.mode & ~KSU_UTS_VIEW_MODE_VALID_MASK) == 0 && template_valid(status.original) &&
           template_valid(status.effective_global) &&
           status.original.field_mask == KSU_UTS_FIELD_VALID_MASK &&
           status.effective_global.field_mask == KSU_UTS_FIELD_VALID_MASK &&
           status.original.release[0] != '\0';
}

bool abi2_status_state_consistent(const ksu_uts_view_status& status) {
    const bool global_enabled = (status.mode & KSU_UTS_VIEW_MODE_GLOBAL) != 0;
    const bool boot_locked = (status.status_flags & KSU_UTS_STATUS_BOOT_LOCKED) != 0;
    switch (status.source) {
    case KSU_UTS_SOURCE_NONE:
        return !global_enabled && !boot_locked;
    case KSU_UTS_SOURCE_BOOT:
        return global_enabled && boot_locked;
    case KSU_UTS_SOURCE_RUNTIME:
        return global_enabled && !boot_locked;
    default:
        return false;
    }
}

bool status_valid(const ksu_uts_view_status& status) {
    return status.version == KSU_UTS_VIEW_ABI_VERSION && status_payload_valid(status) &&
           abi2_status_state_consistent(status);
}

bool release_snapshot_valid(const ksu_uts_view_status& status) {
    return status_valid(status) &&
           (status.original.field_mask & KSU_UTS_FIELD_RELEASE) != 0 &&
           (status.effective_global.field_mask & KSU_UTS_FIELD_RELEASE) != 0 &&
           status.original.release[0] != '\0' && status.effective_global.release[0] != '\0' &&
           field_terminated(status.original.release) &&
           field_terminated(status.effective_global.release);
}

bool read_valid_config(ksu_uts_view_config* config) {
    return config != nullptr && get_uts_view_config(config) == 0 && config_valid(*config);
}

bool read_valid_status(ksu_uts_view_status* status) {
    return status != nullptr && get_uts_view_status(status) == 0 && status_valid(*status);
}

int write_all(int fd, const void* data, size_t size) {
    const auto* cursor = static_cast<const uint8_t*>(data);
    while (size != 0) {
        const ssize_t written = write(fd, cursor, size);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        cursor += written;
        size -= static_cast<size_t>(written);
    }
    return 0;
}

int save_persisted_config(const ksu_uts_view_config& config) {
    if (!ensure_dir_exists(WORKING_DIR))
        return -1;

    PersistedUtsConfig file{};
    file.magic = UTS_CONFIG_MAGIC;
    file.version = UTS_CONFIG_FILE_VERSION;
    file.size = sizeof(file);
    file.config = config;
    file.config.version = KSU_UTS_VIEW_ABI_VERSION;
    file.config.size = sizeof(file.config);
    file.config.update_mask = KSU_UTS_CONFIG_UPDATE_VALID_MASK;
    file.config.mode &= KSU_UTS_VIEW_MODE_VALID_MASK;
    normalize_template(&file.config.global);
    normalize_template(&file.config.deny);
    if (file.config.global.field_mask == 0)
        file.config.mode &= ~KSU_UTS_VIEW_MODE_GLOBAL;
    if (file.config.deny.field_mask == 0)
        file.config.mode &= ~KSU_UTS_VIEW_MODE_DENY_SCOPED;
    if (!config_valid(file.config))
        return -1;

    const std::string tmp = uts_config_path() + ".tmp." + std::to_string(getpid());
    const int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    int ret = write_all(fd, &file, sizeof(file));
    if (ret == 0 && fsync(fd) != 0)
        ret = -1;
    if (close(fd) != 0)
        ret = -1;
    if (ret == 0 && rename(tmp.c_str(), uts_config_path().c_str()) != 0)
        ret = -1;
    if (ret != 0)
        unlink(tmp.c_str());

    if (ret == 0) {
        const int dir_fd = open(WORKING_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir_fd < 0) {
            ret = -1;
        } else {
            if (fsync(dir_fd) != 0)
                ret = -1;
            if (close(dir_fd) != 0)
                ret = -1;
        }
    }
    return ret;
}

// 1 = loaded, 0 = absent, -1 = invalid/error.
int load_persisted_config(ksu_uts_view_config* config, const ksu_uts_view_status& status) {
    if (config == nullptr || !status_valid(status))
        return -1;

    struct stat metadata{};
    if (stat(uts_config_path().c_str(), &metadata) != 0)
        return errno == ENOENT ? 0 : -1;

    std::ifstream input(uts_config_path(), std::ios::binary);
    if (!input)
        return -1;

    PersistedUtsConfig file{};
    input.read(reinterpret_cast<char*>(&file), sizeof(file));
    if (input.gcount() != static_cast<std::streamsize>(sizeof(file)) || input.peek() != EOF ||
        file.magic != UTS_CONFIG_MAGIC || file.size != sizeof(file) || file.reserved != 0) {
        LOGE("UTS View persistent config is invalid");
        return -1;
    }

    normalize_template(&file.config.global);
    normalize_template(&file.config.deny);
    if (file.config.global.field_mask == 0)
        file.config.mode &= ~KSU_UTS_VIEW_MODE_GLOBAL;
    if (file.config.deny.field_mask == 0)
        file.config.mode &= ~KSU_UTS_VIEW_MODE_DENY_SCOPED;

    if (file.version != UTS_CONFIG_FILE_VERSION || !config_valid(file.config)) {
        LOGE("UTS View persistent config is invalid");
        return -1;
    }

    *config = file.config;
    return 1;
}

void print_template(const char* title, const ksu_uts_template& config) {
    printf("%s mask: 0x%02x\n", title, config.field_mask);
    if ((config.field_mask & KSU_UTS_FIELD_SYSNAME) != 0)
        printf("  sysname=%s\n", config.sysname);
    if ((config.field_mask & KSU_UTS_FIELD_NODENAME) != 0)
        printf("  nodename=%s\n", config.nodename);
    if ((config.field_mask & KSU_UTS_FIELD_RELEASE) != 0)
        printf("  release=%s\n", config.release);
    if ((config.field_mask & KSU_UTS_FIELD_VERSION) != 0)
        printf("  version=%s\n", config.version);
    if ((config.field_mask & KSU_UTS_FIELD_MACHINE) != 0)
        printf("  machine=%s\n", config.machine);
    if ((config.field_mask & KSU_UTS_FIELD_DOMAINNAME) != 0)
        printf("  domainname=%s\n", config.domainname);
}

uint32_t field_bit(const std::string& name) {
    if (name == "sysname")
        return KSU_UTS_FIELD_SYSNAME;
    if (name == "nodename")
        return KSU_UTS_FIELD_NODENAME;
    if (name == "release")
        return KSU_UTS_FIELD_RELEASE;
    if (name == "version")
        return KSU_UTS_FIELD_VERSION;
    if (name == "machine")
        return KSU_UTS_FIELD_MACHINE;
    if (name == "domainname")
        return KSU_UTS_FIELD_DOMAINNAME;
    return 0;
}

char* field_buffer(ksu_uts_template* config, uint32_t bit) {
    switch (bit) {
    case KSU_UTS_FIELD_SYSNAME:
        return config->sysname;
    case KSU_UTS_FIELD_NODENAME:
        return config->nodename;
    case KSU_UTS_FIELD_RELEASE:
        return config->release;
    case KSU_UTS_FIELD_VERSION:
        return config->version;
    case KSU_UTS_FIELD_MACHINE:
        return config->machine;
    case KSU_UTS_FIELD_DOMAINNAME:
        return config->domainname;
    default:
        return nullptr;
    }
}

bool set_field(ksu_uts_template* config, uint32_t bit, const std::string& value) {
    if (value.size() >= KSU_UTS_NAME_LEN || value.find('\0') != std::string::npos)
        return false;
    char* field = field_buffer(config, bit);
    if (field == nullptr)
        return false;
    memset(field, 0, KSU_UTS_NAME_LEN);
    if (value.empty()) {
        config->field_mask &= ~bit;
        return true;
    }
    memcpy(field, value.c_str(), value.size() + 1);
    config->field_mask |= bit;
    return true;
}

int update_template_from_args(ksu_uts_template* config, const std::vector<std::string>& args) {
    uint32_t touched_fields = 0;
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--inherit") {
            if (++i >= args.size()) {
                LOGE("--inherit requires a field name");
                return -1;
            }
            const uint32_t bit = field_bit(args[i]);
            char* field = field_buffer(config, bit);
            if (bit == 0 || field == nullptr) {
                LOGE("Unknown UTS field: %s", args[i].c_str());
                return -1;
            }
            if ((touched_fields & bit) != 0) {
                LOGE("UTS field '%s' was specified more than once", args[i].c_str());
                return -1;
            }
            touched_fields |= bit;
            config->field_mask &= ~bit;
            memset(field, 0, KSU_UTS_NAME_LEN);
            continue;
        }

        if (args[i].rfind("--", 0) != 0 || i + 1 >= args.size()) {
            LOGE("Expected --FIELD VALUE or --inherit FIELD");
            return -1;
        }
        const std::string name = args[i].substr(2);
        const uint32_t bit = field_bit(name);
        if (bit == 0) {
            LOGE("Unknown UTS field: %s", name.c_str());
            return -1;
        }
        if ((touched_fields & bit) != 0) {
            LOGE("UTS field '%s' was specified more than once", name.c_str());
            return -1;
        }
        touched_fields |= bit;
        if (!set_field(config, bit, args[++i])) {
            LOGE("UTS field '%s' exceeds 64 bytes or contains NUL", name.c_str());
            return -1;
        }
    }
    return 0;
}

int prepare_config_for_persistence(ksu_uts_view_config* config, const ksu_uts_view_status& status) {
    if (config == nullptr)
        return -1;
    if ((status.status_flags & KSU_UTS_STATUS_BOOT_LOCKED) == 0)
        return 0;

    ksu_uts_view_config persisted{};
    const int loaded = load_persisted_config(&persisted, status);
    if (loaded < 0)
        return -1;
    config->global = loaded > 0 ? persisted.global : ksu_uts_template{};
    config->mode = (config->mode & ~KSU_UTS_VIEW_MODE_GLOBAL) |
                   (loaded > 0 ? persisted.mode & KSU_UTS_VIEW_MODE_GLOBAL : 0);
    return 0;
}

void rollback_kernel_config(ksu_uts_view_config config, const ksu_uts_view_status& status) {
    config.version = KSU_UTS_VIEW_ABI_VERSION;
    config.size = sizeof(config);
    config.update_mask = KSU_UTS_CONFIG_UPDATE_VALID_MASK;
    if ((status.status_flags & KSU_UTS_STATUS_BOOT_LOCKED) != 0)
        config.update_mask &= ~KSU_UTS_CONFIG_UPDATE_GLOBAL;
    if (set_uts_view_config(config) < 0)
        LOGE("Failed to roll back UTS View after persistence error");
}

int set_mode_bit(uint64_t bit, bool enable) {
    const ScopedUtsConfigLock lock;
    if (!lock.locked()) {
        LOGE("Failed to lock UTS View configuration");
        return 1;
    }

    ksu_uts_view_config config{};
    ksu_uts_view_status status{};
    if (!read_valid_config(&config) || !read_valid_status(&status)) {
        LOGE("UTS View is not supported by this kernel");
        return 1;
    }
    if (bit == KSU_UTS_VIEW_MODE_GLOBAL &&
        (status.status_flags & KSU_UTS_STATUS_BOOT_LOCKED) != 0) {
        LOGE("Boot-global UTS identity can only be changed by repatching and rebooting");
        return 1;
    }

    const ksu_uts_view_config old_config = config;
    config.mode = enable ? (config.mode | bit) : (config.mode & ~bit);
    config.update_mask = KSU_UTS_CONFIG_UPDATE_MODE;
    if (set_uts_view_config(config) < 0)
        return 1;

    if (!read_valid_config(&config) || prepare_config_for_persistence(&config, status) < 0 ||
        save_persisted_config(config) != 0) {
        rollback_kernel_config(old_config, status);
        return 1;
    }
    return 0;
}

int set_template_command(bool global, const std::vector<std::string>& args) {
    const ScopedUtsConfigLock lock;
    if (!lock.locked()) {
        LOGE("Failed to lock UTS View configuration");
        return 1;
    }

    ksu_uts_view_config config{};
    ksu_uts_view_status status{};
    if (!read_valid_config(&config)) {
        LOGE("Failed to read UTS View configuration");
        return 1;
    }
    if (!read_valid_status(&status)) {
        LOGE("Failed to read UTS View status");
        return 1;
    }
    const ksu_uts_view_config old_config = config;
    ksu_uts_template* target = global ? &config.global : &config.deny;
    if (update_template_from_args(target, args) != 0)
        return 1;
    const uint32_t updated_mask = target->field_mask;
    config.version = KSU_UTS_VIEW_ABI_VERSION;
    config.size = sizeof(config);
    config.update_mask = global ? KSU_UTS_CONFIG_UPDATE_GLOBAL : KSU_UTS_CONFIG_UPDATE_DENY;
    if (updated_mask == 0) {
        config.mode &= ~(global ? KSU_UTS_VIEW_MODE_GLOBAL : KSU_UTS_VIEW_MODE_DENY_SCOPED);
        config.update_mask |= KSU_UTS_CONFIG_UPDATE_MODE;
    }
    if (set_uts_view_config(config) < 0) {
        LOGE("Failed to update %s UTS template", global ? "global" : "deny-scoped");
        return 1;
    }

    if (!read_valid_config(&config)) {
        LOGE("Failed to read updated UTS View configuration");
        rollback_kernel_config(old_config, status);
        return 1;
    }
    if (prepare_config_for_persistence(&config, status) < 0 || save_persisted_config(config) != 0) {
        LOGE("Failed to persist UTS View configuration");
        rollback_kernel_config(old_config, status);
        return 1;
    }
    printf("%s UTS template updated (mask=0x%02x)\n", global ? "Global" : "Deny-scoped",
           updated_mask);
    return 0;
}

std::string hex_encode_raw(const char field[KSU_UTS_NAME_LEN]) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    const size_t length = strnlen(field, KSU_UTS_NAME_LEN);
    result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        const auto value = static_cast<unsigned char>(field[i]);
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0xf]);
    }
    return result;
}

std::string hex_encode(const char field[KSU_UTS_NAME_LEN]) {
    return "hex:" + hex_encode_raw(field);
}

bool parse_config_uint32(const std::string& value, uint32_t* result) {
    if (result == nullptr || value.empty())
        return false;
    const bool hexadecimal =
        value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X');
    char* end = nullptr;
    errno = 0;
    const unsigned long parsed = strtoul(value.c_str(), &end, hexadecimal ? 16 : 10);
    if (end == value.c_str() || *end != '\0' || errno == ERANGE || parsed > UINT32_MAX)
        return false;
    *result = static_cast<uint32_t>(parsed);
    return true;
}

}  // namespace

int apply_uts_view_config() {
    const ScopedUtsConfigLock lock;
    if (!lock.locked())
        return -1;

    struct stat metadata{};
    if (stat(uts_config_path().c_str(), &metadata) != 0)
        return errno == ENOENT ? 0 : -1;

    ksu_uts_view_status status{};
    const int status_result = get_uts_view_status(&status);
    if (status_result == -ENOTTY || status_result == -EOPNOTSUPP) {
        LOGW("Persisted UTS View configuration ignored: extension unavailable");
        return 0;
    }
    if (status_result < 0) {
        LOGE("Failed to query UTS View while restoring persisted configuration");
        return -1;
    }
    if (!status_valid(status)) {
        LOGE("Persisted UTS View configuration ignored: incompatible extension ABI");
        return -1;
    }
    if ((status.status_flags & KSU_UTS_STATUS_ORIGINAL_VALID) == 0) {
        LOGE("UTS View extension has no immutable original identity");
        return -1;
    }

    ksu_uts_view_config config{};
    const int loaded = load_persisted_config(&config, status);
    if (loaded < 0)
        return -1;
    if (loaded == 0)
        return 0;

    config.update_mask = KSU_UTS_CONFIG_UPDATE_VALID_MASK;
    if ((status.status_flags & KSU_UTS_STATUS_BOOT_LOCKED) != 0) {
        config.update_mask &= ~KSU_UTS_CONFIG_UPDATE_GLOBAL;
        config.mode =
            (config.mode & ~KSU_UTS_VIEW_MODE_GLOBAL) | (status.mode & KSU_UTS_VIEW_MODE_GLOBAL);
    }
    if (set_uts_view_config(config) < 0)
        return -1;

    LOGI("Applied persisted UTS View extension configuration");
    return 0;
}

bool get_uts_view_original_release(std::string* release, bool* supported) {
    if (release == nullptr || supported == nullptr)
        return false;
    release->clear();
    *supported = false;

    ksu_uts_view_status status{};
    const int result = get_uts_view_status(&status);
    if (result == -ENOTTY || result == -EOPNOTSUPP)
        return true;
    if (result < 0)
        return false;
    *supported = true;
    if (!status_valid(status))
        return false;

    if ((status.status_flags & KSU_UTS_STATUS_ORIGINAL_VALID) == 0 ||
        (status.original.field_mask & KSU_UTS_FIELD_RELEASE) == 0 ||
        !field_terminated(status.original.release) || status.original.release[0] == '\0') {
        return false;
    }
    *release = status.original.release;
    return true;
}

int uts_view_command(const std::vector<std::string>& args) {
    if (args.empty()) {
        printf("USAGE: ksud uts-view <SUBCOMMAND>\n\n");
        printf("SUBCOMMANDS:\n");
        printf("  status\n");
        printf("  release-snapshot\n");
        printf("  get\n");
        printf("  original\n");
        printf("  effective\n");
        printf("  set-global [--FIELD VALUE] [--inherit FIELD]\n");
        printf("  set-deny [--FIELD VALUE] [--inherit FIELD]\n");
        printf("  enable-global | disable-global\n");
        printf("  enable-scoped | disable-scoped\n");
        return 1;
    }

    if (args[0] == "status") {
        ksu_uts_view_status status{};
        ksu_uts_view_config config{};
        if (!read_valid_status(&status) || !read_valid_config(&config))
            return 1;
        const char* source = "none";
        if (status.source == KSU_UTS_SOURCE_BOOT)
            source = "boot";
        else if (status.source == KSU_UTS_SOURCE_RUNTIME)
            source = "runtime";
        printf("source=%s\n", source);
        printf("mode=%llu\n", static_cast<unsigned long long>(status.mode));
        printf("boot_locked=%s\n",
               (status.status_flags & KSU_UTS_STATUS_BOOT_LOCKED) != 0 ? "true" : "false");
        printf("original_valid=%s\n",
               (status.status_flags & KSU_UTS_STATUS_ORIGINAL_VALID) != 0 ? "true" : "false");
        printf("late_gaps=%s\n",
               (status.status_flags & KSU_UTS_STATUS_LATE_GAPS) != 0 ? "true" : "false");
        printf("late_capture=%s\n",
               (status.status_flags & KSU_UTS_STATUS_LATE_CAPTURE) != 0 ? "true" : "false");
        printf("detached_task_count=%u\n", status.detached_task_count);
        printf("global_mask=0x%02x\n", config.global.field_mask);
        printf("deny_mask=0x%02x\n", config.deny.field_mask);
        if ((status.mode & KSU_UTS_VIEW_MODE_DENY_SCOPED) != 0)
            printf("note=restart target apps to apply scoped changes\n");
        if ((status.status_flags & KSU_UTS_STATUS_BOOT_LOCKED) != 0)
            printf("note=repatch and reboot to change boot-global identity\n");
        return 0;
    }
    if (args[0] == "release-snapshot") {
        ksu_uts_view_status status{};
        if (!read_valid_status(&status) || !release_snapshot_valid(status))
            return 1;
        const char* source = "none";
        if (status.source == KSU_UTS_SOURCE_BOOT)
            source = "boot";
        else if (status.source == KSU_UTS_SOURCE_RUNTIME)
            source = "runtime";
        const std::string original_release_hex = hex_encode_raw(status.original.release);
        const std::string effective_release_hex = hex_encode_raw(status.effective_global.release);
        printf("snapshot_version=1\n");
        printf("abi_version=%u\n", KSU_UTS_VIEW_ABI_VERSION);
        printf("source=%s\n", source);
        printf("mode=%llu\n", static_cast<unsigned long long>(status.mode));
        printf("boot_locked=%s\n",
               (status.status_flags & KSU_UTS_STATUS_BOOT_LOCKED) != 0 ? "true" : "false");
        printf("original_valid=true\n");
        printf("original_release_hex=%s\n", original_release_hex.c_str());
        printf("effective_release_hex=%s\n", effective_release_hex.c_str());
        return 0;
    }
    if (args[0] == "get") {
        ksu_uts_view_config config{};
        if (!read_valid_config(&config))
            return 1;
        print_template("global", config.global);
        print_template("deny", config.deny);
        return 0;
    }
    if (args[0] == "original") {
        ksu_uts_view_status status{};
        if (!read_valid_status(&status))
            return 1;
        print_template("original", status.original);
        return 0;
    }
    if (args[0] == "effective") {
        ksu_uts_view_status status{};
        if (!read_valid_status(&status))
            return 1;
        print_template("effective", status.effective_global);
        return 0;
    }
    if (args[0] == "set-global")
        return set_template_command(true, args);
    if (args[0] == "set-deny")
        return set_template_command(false, args);
    if (args[0] == "enable-global")
        return set_mode_bit(KSU_UTS_VIEW_MODE_GLOBAL, true);
    if (args[0] == "disable-global")
        return set_mode_bit(KSU_UTS_VIEW_MODE_GLOBAL, false);
    if (args[0] == "enable-scoped")
        return set_mode_bit(KSU_UTS_VIEW_MODE_DENY_SCOPED, true);
    if (args[0] == "disable-scoped")
        return set_mode_bit(KSU_UTS_VIEW_MODE_DENY_SCOPED, false);

    LOGE("Unknown uts-view subcommand: %s", args[0].c_str());
    return 1;
}

bool load_uts_boot_config(const std::string& path, ksu_uts_template* config, std::string* error) {
    if (config == nullptr)
        return false;
    *config = {};

    std::ifstream input(path);
    if (!input) {
        if (error != nullptr)
            *error = "cannot open config";
        return false;
    }

    bool have_format_version = false;
    bool have_mask = false;
    uint32_t format_version = 0;
    uint32_t declared_mask = 0;
    std::array<bool, 6> field_present{};
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const std::string stripped = trim(line);
        if (stripped.empty() || stripped[0] == '#')
            continue;
        const size_t separator = line.find('=');
        if (separator == std::string::npos) {
            if (error != nullptr)
                *error = "expected key=value";
            return false;
        }
        const std::string key = trim(line.substr(0, separator));
        const std::string value = line.substr(separator + 1);
        if (key == "format_version") {
            if (have_format_version || !parse_config_uint32(trim(value), &format_version)) {
                if (error != nullptr)
                    *error = "invalid format version";
                return false;
            }
            have_format_version = true;
            continue;
        }
        if (key == "mask") {
            if (have_mask || !parse_config_uint32(trim(value), &declared_mask)) {
                if (error != nullptr)
                    *error = "invalid mask";
                return false;
            }
            have_mask = true;
            continue;
        }
        const uint32_t bit = field_bit(key);
        if (bit == 0) {
            if (error != nullptr)
                *error = "unknown field";
            return false;
        }
        unsigned int index = 0;
        while (((1U << index) & bit) == 0)
            ++index;
        if (field_present[index]) {
            if (error != nullptr)
                *error = "duplicate field";
            return false;
        }
        if (!set_field(config, bit, value)) {
            if (error != nullptr)
                *error = "field exceeds 64 bytes or contains NUL";
            return false;
        }
        field_present[index] = true;
    }

    config->field_mask = declared_mask;
    if (!have_format_version || format_version != UTS_BOOT_CONFIG_VERSION || !have_mask ||
        config->field_mask == 0 || (config->field_mask & ~KSU_UTS_FIELD_VALID_MASK) != 0) {
        if (error != nullptr)
            *error = "missing/unsupported version or mask";
        return false;
    }
    for (unsigned int index = 0; index < field_present.size(); ++index) {
        const uint32_t bit = 1U << index;
        if ((config->field_mask & bit) != 0 && !field_present[index]) {
            if (error != nullptr)
                *error = "masked field is missing";
            return false;
        }
        if ((config->field_mask & bit) == 0) {
            char* field = field_buffer(config, bit);
            if (field != nullptr)
                memset(field, 0, KSU_UTS_NAME_LEN);
        }
    }
    normalize_template(config);
    if (config->field_mask == 0) {
        if (error != nullptr)
            *error = "no non-empty fields";
        return false;
    }
    return template_valid(*config);
}

std::vector<std::string> encode_uts_boot_module_params(const ksu_uts_template& config) {
    std::vector<std::string> params;
    params.emplace_back("uts_boot_global=1");
    params.emplace_back("uts_boot_mask=" + std::to_string(config.field_mask));
    const auto append = [&params, &config](uint32_t bit, const char* name,
                                           const char field[KSU_UTS_NAME_LEN]) {
        if ((config.field_mask & bit) != 0)
            params.emplace_back(std::string(name) + "=" + hex_encode(field));
    };
    append(KSU_UTS_FIELD_SYSNAME, "uts_boot_sysname", config.sysname);
    append(KSU_UTS_FIELD_NODENAME, "uts_boot_nodename", config.nodename);
    append(KSU_UTS_FIELD_RELEASE, "uts_boot_release", config.release);
    append(KSU_UTS_FIELD_VERSION, "uts_boot_version", config.version);
    append(KSU_UTS_FIELD_MACHINE, "uts_boot_machine", config.machine);
    append(KSU_UTS_FIELD_DOMAINNAME, "uts_boot_domainname", config.domainname);
    return params;
}

}  // namespace ksud
