/**
 * ksuinit - Init module
 *
 * Handles the initialization sequence:
 * - Mount filesystems
 * - Setup logging
 * - Detect GKI KernelSU
 * - Load LKM
 * - Setup real init
 */

#include "init.hpp"
#include "loader.hpp"
#include "log.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace ksuinit {

namespace {

/**
 * RAII class for auto-unmounting filesystems
 */
class AutoUmount {
public:
    AutoUmount() = default;
    AutoUmount(const AutoUmount&) = delete;
    AutoUmount& operator=(const AutoUmount&) = delete;
    AutoUmount(AutoUmount&& other) noexcept : mountpoints_(std::move(other.mountpoints_)) {
        other.mountpoints_.clear();
    }
    AutoUmount& operator=(AutoUmount&&) = delete;

    ~AutoUmount() {
        // Unmount in reverse order
        for (auto it = mountpoints_.rbegin(); it != mountpoints_.rend(); ++it) {
            if (umount2(it->c_str(), MNT_DETACH) != 0) {
                KLOGE("Cannot umount %s: %s", it->c_str(), strerror(errno));
            }
        }
    }

    void add(const std::string& mountpoint) { mountpoints_.push_back(mountpoint); }

private:
    std::vector<std::string> mountpoints_;
};

/**
 * Mount a filesystem
 */
bool mount_filesystem(const char* fstype, const char* mountpoint) {
    // Create mountpoint if it doesn't exist
    if (mkdir(mountpoint, 0755) != 0 && errno != EEXIST) {
        KLOGE("Cannot create mountpoint %s: %s", mountpoint, strerror(errno));
        return false;
    }

    // Mount the filesystem
    if (mount(fstype, mountpoint, fstype, 0, nullptr) != 0) {
        KLOGE("Cannot mount %s on %s: %s", fstype, mountpoint, strerror(errno));
        return false;
    }

    return true;
}

/**
 * Prepare the temporary /proc mount used for printk configuration.
 */
AutoUmount prepare_mount() {
    AutoUmount auto_umount;

    // Mount procfs
    if (mount_filesystem("proc", "/proc")) {
        auto_umount.add("/proc");
    }

    return auto_umount;
}

/**
 * Setup kernel logging via /dev/kmsg
 */
void setup_kmsg() {
    const char* device = "/dev/kmsg";

    // Check if /dev/kmsg exists
    if (access(device, F_OK) != 0) {
        // Try to create it
        if (mknod("/kmsg", S_IFCHR | 0666, makedev(1, 11)) == 0) {
            device = "/kmsg";
        }
    }

    // Initialize kernel log
    log_init(device);
}

/**
 * Disable kmsg rate limiting
 */
void unlimit_kmsg() {
    std::ofstream rate("/proc/sys/kernel/printk_devkmsg");
    if (rate.is_open()) {
        rate << "on\n";
    }
}

}  // anonymous namespace

bool init() {
    // Setup kernel log first
    setup_kmsg();

    KLOGI("Hello, KernelSU!");

    // Mount /proc temporarily for printk configuration.
    // They will be auto-unmounted when this scope exits
    {
        auto auto_umount = prepare_mount();

        // Disable kmsg rate limiting (requires /proc)
        unlimit_kmsg();

        // Load the KernelSU LKM module
        KLOGI("Loading kernelsu.ko..");
        if (!load_module("/kernelsu.ko")) {
            KLOGE("Cannot load kernelsu.ko");
        }
    }
    // /proc is unmounted here

    // Remove the current /init (which is us)
    if (unlink("/init") != 0) {
        KLOGE("Cannot unlink /init: %s", strerror(errno));
        return false;
    }

    // Determine the real init path
    const char* real_init = "/system/bin/init";
    if (access("/init.real", F_OK) == 0) {
        real_init = "init.real";
    }

    KLOGI("init is %s", real_init);

    // Create symlink to real init
    if (symlink(real_init, "/init") != 0) {
        KLOGE("Cannot symlink %s to /init: %s", real_init, strerror(errno));
        return false;
    }

    return true;
}

}  // namespace ksuinit
