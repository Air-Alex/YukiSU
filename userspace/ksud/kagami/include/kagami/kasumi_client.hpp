#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace kagami::kasumi {

enum class Status {
    Available = 0,
    NotPresent = 1,
    KernelTooOld = 2,
    ClientTooOld = 3,
};

struct VersionInfo {
    int expected_protocol = 0;
    int kernel_protocol = 0;
    int last_errno = 0;
    int process_uid = -1;
    int process_euid = -1;
    Status status = Status::NotPresent;
};

struct FeatureCapabilities {
    bool ok = false;
    int last_errno = 0;
    int bitmask = 0;
};

enum class MountHideMode : std::uint32_t {
    Normal = 0,
    Aggressive = 1,
};

VersionInfo version_info();
bool is_available();
std::string active_rules();
std::string hooks();
FeatureCapabilities feature_capabilities();
int features();
std::vector<std::string> feature_names(int bitmask);
std::vector<std::string> active_modules_from_rules(const std::string &rules);

bool set_enabled(bool enable);
bool set_debug(bool enable);
bool set_stealth(bool enable);
bool fix_mounts();
bool hide_overlay_xattrs(const std::string &path);
bool clear_overlay_xattr_hiding();
bool set_mount_hide(bool enable, MountHideMode mode = MountHideMode::Normal);
bool set_maps_spoof(bool enable);
bool set_statfs_spoof(bool enable);
bool clear_rules();
bool add_rule(const std::string &target, const std::string &source, int type);
bool add_merge_rule(const std::string &target, const std::string &source);
bool hide_path(const std::string &path);
bool delete_rule(const std::string &path);
bool add_maps_rule(unsigned long target_ino, unsigned long target_dev, unsigned long spoofed_ino,
                   unsigned long spoofed_dev, const std::string &spoofed_path);
bool clear_maps_rules();
int enabled_state();
int process_uid();
int process_euid();

} // namespace kagami::kasumi
