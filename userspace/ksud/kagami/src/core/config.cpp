#include "kagami/config.hpp"

#include "core/json.hpp"
#include "core/log.hpp"
#include "core/runtime.hpp"
#include "utils.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace kagami {

class ConfigFileLock {
  public:
    ~ConfigFileLock() {
        if (fd_ >= 0) {
            (void)::flock(fd_, LOCK_UN);
            ::close(fd_);
        }
    }

    bool acquire(std::string &error) {
        if (!prepare_private_directory(runtime_data_dir(), error)) {
            return false;
        }
        const std::string lock_path = runtime_config_file().string() + ".lock";
        fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0) {
            error = "open " + lock_path + ": " + std::strerror(errno);
            return false;
        }
        if (::flock(fd_, LOCK_EX) != 0) {
            error = "lock " + lock_path + ": " + std::strerror(errno);
            return false;
        }
        return true;
    }

  private:
    int fd_ = -1;
};

std::string default_config_json() {
    return R"({
  "mountsource": "KSU",
  "work_dir": "/dev/kagami",
  "mirror_dir": "",
  "mirror_img_size_mb": 2048,
  "overlay_writable": false,
  "debug": false,
  "verbose": false,
  "builtin_mount_enabled": true,
  "fs_type": "auto",
  "enable_kernel_debug": false,
  "enable_stealth": true,
  "enable_overlay_xattr_hide": false,
  "enable_mount_hide": false,
  "mount_hide_mode": "normal",
  "enable_maps_spoof": false,
  "enable_statfs_spoof": false,
  "kasumi_enabled": true,
  "overlayfs_enabled": true,
  "magic_mount_enabled": true,
  "mount_backend": "auto",
  "partitions": []
}
)";
}

void prune_config_fields(json::Value &config) {
    static const auto defaults = json::parse(default_config_json());
    for (auto it = config.o.begin(); it != config.o.end();) {
        if (!defaults.find(it->first))
            it = config.o.erase(it);
        else
            ++it;
    }
}

static bool save_config(const std::string &data, std::string &error) {
    if (ksud::write_file_atomic(runtime_config_file(), data))
        return true;
    error = "write config: " + std::string(std::strerror(errno));
    return false;
}

bool write_default_config(std::string &error) {
    ConfigFileLock lock;
    return lock.acquire(error) && save_config(default_config_json(), error);
}

static std::vector<std::string> json_string_array_or_empty(const JsonValue *value) {
    std::vector<std::string> out;
    if (!value || !value->is_array()) {
        return out;
    }
    for (const auto &item : value->a) {
        if (item.is_string()) {
            out.push_back(item.s);
        }
    }
    return out;
}

std::vector<std::string> load_user_hide_rules() {
    const auto input = ksud::read_file((runtime_data_dir() / "user_hide_rules.json").string());
    if (!input)
        return {};
    JsonValue root;
    std::string error;
    if (!parse_json(*input, root, error) || !root.is_array()) {
        logging::write(logging::Level::Warning, "config", "invalid user hide rules: " + error);
        return {};
    }
    std::vector<std::string> rules;
    for (const auto &item : root.a) {
        if (item.is_string() && !item.s.empty() && item.s.front() == '/' &&
            item.s.find('\0') == std::string::npos)
            rules.push_back(item.s);
    }
    return rules;
}

bool save_user_hide_rules(const std::vector<std::string> &rules) {
    JsonValue root;
    root.type = JsonValue::Type::Array;
    for (const auto &rule : rules)
        root.a.emplace_back(rule);
    return ksud::write_file_atomic(runtime_data_dir() / "user_hide_rules.json",
                                   stringify_json(root, 2) + "\n");
}

static bool json_bool_or(const JsonValue *root, const char *key, bool fallback) {
    const auto *value = root ? root->find(key) : nullptr;
    return value ? value->bool_or(fallback) : fallback;
}

static std::string json_string_or(const JsonValue *root, const char *key,
                                  const std::string &fallback) {
    const auto *value = root ? root->find(key) : nullptr;
    return value ? value->string_or(fallback) : fallback;
}

static int json_int_or(const JsonValue *root, const char *key, int fallback) {
    const auto *value = root ? root->find(key) : nullptr;
    return value ? static_cast<int>(value->u32_or(static_cast<std::uint32_t>(fallback))) : fallback;
}

bool parse_config_json(const std::string &json, Config &config, std::string &error) {
    JsonValue root;
    if (!parse_json(json, root, error)) {
        return false;
    }
    if (!root.is_object()) {
        error = "config root must be a JSON object";
        return false;
    }

    config.mount_source = json_string_or(&root, "mountsource", config.mount_source);
    config.work_dir = json_string_or(&root, "work_dir", config.work_dir);
    config.mirror_dir = json_string_or(&root, "mirror_dir", config.mirror_dir);
    config.mirror_img_size_mb = json_int_or(&root, "mirror_img_size_mb", config.mirror_img_size_mb);
    config.overlay_writable = json_bool_or(&root, "overlay_writable", config.overlay_writable);
    config.fs_type = json_string_or(&root, "fs_type", config.fs_type);
    config.debug = json_bool_or(&root, "debug", config.debug);
    config.verbose = json_bool_or(&root, "verbose", config.verbose);
    logging::set_debug_enabled(config.debug || config.verbose);
    config.builtin_mount_enabled =
        json_bool_or(&root, "builtin_mount_enabled", config.builtin_mount_enabled);
    config.kasumi_enabled = json_bool_or(&root, "kasumi_enabled", config.kasumi_enabled);
    config.enable_kernel_debug =
        json_bool_or(&root, "enable_kernel_debug", config.enable_kernel_debug);
    config.enable_stealth = json_bool_or(&root, "enable_stealth", config.enable_stealth);
    config.enable_overlay_xattr_hide =
        json_bool_or(&root, "enable_overlay_xattr_hide", config.enable_overlay_xattr_hide);
    config.enable_mount_hide = json_bool_or(&root, "enable_mount_hide", config.enable_mount_hide);
    config.mount_hide_mode = json_string_or(&root, "mount_hide_mode", config.mount_hide_mode);
    if (config.mount_hide_mode != "normal" && config.mount_hide_mode != "aggressive")
        config.mount_hide_mode = "normal";
    config.enable_maps_spoof = json_bool_or(&root, "enable_maps_spoof", config.enable_maps_spoof);
    config.enable_statfs_spoof =
        json_bool_or(&root, "enable_statfs_spoof", config.enable_statfs_spoof);
    config.overlayfs_enabled = json_bool_or(&root, "overlayfs_enabled", config.overlayfs_enabled);
    config.magic_mount_enabled =
        json_bool_or(&root, "magic_mount_enabled", config.magic_mount_enabled);
    config.mount_backend = json_string_or(&root, "mount_backend", config.mount_backend);
    config.partitions = json_string_array_or_empty(root.find("partitions"));

    return true;
}

bool read_config_file(Config &config, std::string &error) {
    const auto input = ksud::read_file(runtime_config_file().string());
    if (!input) {
        error = "read config: " + std::string(std::strerror(errno));
        return false;
    }
    return parse_config_json(*input, config, error);
}

bool merge_config_json(const std::string &updates, std::string &error) {
    JsonValue patch;
    if (!parse_json(updates, patch, error) || !patch.is_object()) {
        if (error.empty()) {
            error = "config updates must be a JSON object";
        }
        return false;
    }

    ConfigFileLock lock;
    if (!lock.acquire(error)) {
        return false;
    }

    const auto input = ksud::read_file(runtime_config_file().string());
    if (!input && errno != ENOENT) {
        error = "read config: " + std::string(std::strerror(errno));
        return false;
    }
    JsonValue root;
    if (!parse_json(input.value_or(default_config_json()), root, error) || !root.is_object()) {
        if (error.empty()) {
            error = "config root must be an object";
        }
        return false;
    }

    prune_config_fields(root);
    prune_config_fields(patch);
    for (const auto &[key, value] : patch.o) {
        root.o[key] = value;
    }
    const bool saved = save_config(stringify_json(root, 2) + "\n", error);
    if (saved)
        logging::set_debug_enabled(json_bool_or(&root, "debug", false) ||
                                   json_bool_or(&root, "verbose", false));
    return saved;
}

} // namespace kagami
