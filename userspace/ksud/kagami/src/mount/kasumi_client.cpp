#include "kagami/kasumi_client.hpp"

#include "uapi/kasumi.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include <sys/types.h>
#include <unistd.h>
#endif

namespace kagami::kasumi {

static_assert(static_cast<std::uint32_t>(MountHideMode::Normal) == KSM_MOUNT_HIDE_MODE_NORMAL);
static_assert(static_cast<std::uint32_t>(MountHideMode::Aggressive) ==
              KSM_MOUNT_HIDE_MODE_AGGRESSIVE);

extern "C" int ksu_kasumi_ioctl(unsigned long cmd, void* arg);

namespace {
int execute(unsigned long cmd, void* arg) {
    return ksu_kasumi_ioctl(cmd, arg);
}

bool ioctl_arg_ok(int rc, int arg_err) {
    if (rc != 0) {
        return false;
    }
    if (arg_err != 0) {
        errno = arg_err < 0 ? -arg_err : arg_err;
        return false;
    }
    return true;
}
}  // namespace

VersionInfo version_info() {
    VersionInfo info;
    info.expected_protocol = KSM_PROTOCOL_VERSION;
    info.process_uid = process_uid();
    info.process_euid = process_euid();

    int version = 0;
    if (execute(KSM_IOC_GET_VERSION, &version) != 0) {
        info.last_errno = errno;
        info.status = Status::NotPresent;
        return info;
    }

    info.kernel_protocol = version;
    if (version < KSM_PROTOCOL_VERSION) {
        info.status = Status::KernelTooOld;
    } else if (version > KSM_PROTOCOL_VERSION) {
        info.status = Status::ClientTooOld;
    } else {
        info.status = Status::Available;
    }
    return info;
}

int process_uid() {
#if defined(__linux__)
    return static_cast<int>(getuid());
#else
    return -1;
#endif
}

int process_euid() {
#if defined(__linux__)
    return static_cast<int>(geteuid());
#else
    return -1;
#endif
}

bool is_available() {
    return version_info().status == Status::Available;
}

std::string active_rules() {
    std::vector<char> buffer(64UL * 1024, '\0');
    kasumi_syscall_list_arg arg = {};
    arg.buf = buffer.data();
    arg.size = buffer.size();
    if (execute(KSM_IOC_LIST_RULES, &arg) != 0) {
        return "";
    }
    return {buffer.data()};
}

std::string hooks() {
    std::vector<char> buffer(8UL * 1024, '\0');
    kasumi_syscall_list_arg arg = {};
    arg.buf = buffer.data();
    arg.size = buffer.size();
    if (execute(KSM_IOC_GET_HOOKS, &arg) != 0) {
        return "";
    }
    return {buffer.data()};
}

FeatureCapabilities feature_capabilities() {
    FeatureCapabilities capabilities;
    int bitmask = 0;
    if (execute(KSM_IOC_GET_FEATURES, &bitmask) != 0) {
        capabilities.last_errno = errno != 0 ? errno : EIO;
        return capabilities;
    }
    capabilities.ok = true;
    capabilities.bitmask = bitmask;
    return capabilities;
}

int features() {
    return feature_capabilities().bitmask;
}

std::vector<std::string> feature_names(int bitmask) {
    std::vector<std::string> names;
    if (bitmask & KSM_FEATURE_MOUNT_HIDE)
        names.emplace_back("mount_hide");
    if (bitmask & KSM_FEATURE_MAPS_SPOOF)
        names.emplace_back("maps_spoof");
    if (bitmask & KSM_FEATURE_STATFS_SPOOF)
        names.emplace_back("statfs_spoof");
    if (bitmask & KSM_FEATURE_KSTAT_SPOOF)
        names.emplace_back("kstat_spoof");
    if (bitmask & KSM_FEATURE_MERGE_DIR)
        names.emplace_back("merge_dir");
    if (bitmask & KSM_FEATURE_OVERLAY_XATTR_HIDE)
        names.emplace_back("overlay_xattr_hide");
    if (bitmask & KSM_FEATURE_FAKE_MOUNTINFO)
        names.emplace_back("fake_mountinfo");
    if (bitmask & KSM_FEATURE_MOUNT_HIDE_AGGRESSIVE)
        names.emplace_back("mount_hide_aggressive");
    return names;
}

std::vector<std::string> active_modules_from_rules(const std::string& rules) {
    std::set<std::string> modules;
    std::istringstream lines(rules);
    std::string line;
    while (std::getline(lines, line)) {
        const std::vector<std::string> prefixes = {
            "/data/adb/modules/",
        };
        for (const auto& prefix : prefixes) {
            std::size_t pos = line.find(prefix);
            while (pos != std::string::npos) {
                const std::size_t start = pos + prefix.size();
                const std::size_t end = line.find('/', start);
                if (end != std::string::npos && end > start) {
                    modules.insert(line.substr(start, end - start));
                }
                pos = line.find(prefix, start);
            }
        }
    }
    return {modules.begin(), modules.end()};
}

bool set_enabled(bool enable) {
    int value = enable ? 1 : 0;
    return execute(KSM_IOC_SET_ENABLED, &value) == 0;
}

bool set_debug(bool enable) {
    int value = enable ? 1 : 0;
    return execute(KSM_IOC_SET_DEBUG, &value) == 0;
}

bool set_stealth(bool enable) {
    int value = enable ? 1 : 0;
    return execute(KSM_IOC_SET_STEALTH, &value) == 0;
}

bool fix_mounts() {
    return execute(KSM_IOC_REORDER_MNT_ID, nullptr) == 0;
}

bool hide_overlay_xattrs(const std::string& path) {
    kasumi_syscall_arg arg = {};
    arg.src = path.c_str();
    return execute(KSM_IOC_HIDE_OVERLAY_XATTRS, &arg) == 0;
}

bool clear_overlay_xattr_hiding() {
    if (!(features() & KSM_FEATURE_OVERLAY_XATTR_HIDE))
        return true;
    return hide_overlay_xattrs("");
}

bool set_mount_hide(bool enable, MountHideMode mode) {
    const int bitmask = features();
    const bool mode_supported = (bitmask & KSM_FEATURE_MOUNT_HIDE_AGGRESSIVE) != 0;

    if (enable && mode == MountHideMode::Aggressive && !mode_supported) {
        errno = EOPNOTSUPP;
        return false;
    }
    if (mode_supported) {
        int raw_mode = static_cast<int>(mode);
        if (execute(KSM_IOC_SET_MOUNT_HIDE_MODE, &raw_mode) != 0)
            return false;
    }
    kasumi_mount_hide_arg arg = {};
    arg.enable = enable ? 1 : 0;
    const int rc = execute(KSM_IOC_SET_MOUNT_HIDE, &arg);
    return ioctl_arg_ok(rc, arg.err);
}

bool set_maps_spoof(bool enable) {
    kasumi_maps_spoof_arg arg = {};
    arg.enable = enable ? 1 : 0;
    const int rc = execute(KSM_IOC_SET_MAPS_SPOOF, &arg);
    return ioctl_arg_ok(rc, arg.err);
}

bool set_statfs_spoof(bool enable) {
    kasumi_statfs_spoof_arg arg = {};
    arg.enable = enable ? 1 : 0;
    const int rc = execute(KSM_IOC_SET_STATFS_SPOOF, &arg);
    return ioctl_arg_ok(rc, arg.err);
}

bool clear_rules() {
    return execute(KSM_IOC_CLEAR_ALL, nullptr) == 0;
}

bool add_rule(const std::string& target, const std::string& source, int type) {
    kasumi_syscall_arg arg = {};
    arg.src = target.c_str();
    arg.target = source.c_str();
    arg.type = type;
    return execute(KSM_IOC_ADD_RULE, &arg) == 0;
}

bool add_merge_rule(const std::string& target, const std::string& source) {
    kasumi_syscall_arg arg = {};
    arg.src = target.c_str();
    arg.target = source.c_str();
    return execute(KSM_IOC_ADD_MERGE_RULE, &arg) == 0;
}

bool hide_path(const std::string& path) {
    kasumi_syscall_arg arg = {};
    arg.src = path.c_str();
    return execute(KSM_IOC_HIDE_RULE, &arg) == 0;
}

bool delete_rule(const std::string& path) {
    kasumi_syscall_arg arg = {};
    arg.src = path.c_str();
    return execute(KSM_IOC_DEL_RULE, &arg) == 0;
}

bool add_maps_rule(unsigned long target_ino, unsigned long target_dev, unsigned long spoofed_ino,
                   unsigned long spoofed_dev, const std::string& spoofed_path) {
    kasumi_maps_rule arg = {};
    arg.target_ino = target_ino;
    arg.target_dev = target_dev;
    arg.spoofed_ino = spoofed_ino;
    arg.spoofed_dev = spoofed_dev;
    std::strncpy(arg.spoofed_pathname, spoofed_path.c_str(), KSM_MAX_LEN_PATHNAME - 1);
    const int rc = execute(KSM_IOC_ADD_MAPS_RULE, &arg);
    return ioctl_arg_ok(rc, arg.err);
}

bool clear_maps_rules() {
    return execute(KSM_IOC_CLEAR_MAPS_RULES, nullptr) == 0;
}

int enabled_state() {
    int enabled = 0;
    return execute(KSM_IOC_GET_ENABLED, &enabled) == 0 ? enabled : -1;
}

}  // namespace kagami::kasumi
