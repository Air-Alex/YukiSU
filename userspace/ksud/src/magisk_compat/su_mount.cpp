#include "magisk_compat/su_mount.hpp"

#include "core/ksucalls.hpp"
#include "log.hpp"
#include "magisk_compat/msud.hpp"
#include "magisk_compat/su_magic.hpp"

extern "C" {
#include "uapi/feature.h"
}

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

namespace ksud {

namespace {

bool enter_init_mount_ns() {
    const int fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    const bool ok = setns(fd, CLONE_NEWNS) == 0;
    close(fd);
    return ok;
}

}  // namespace

void mount_magisk_compat_su_if_enabled() {
    const auto [value, supported] = get_feature(KSU_FEATURE_MAGISK_COMPAT);
    if (!supported || value == 0) {
        return;
    }
    magic_mount_su();
}

int mount_su_now() {
    if (!enter_init_mount_ns()) {
        LOGE("magisk_su: could not enter init mount ns");
        return 1;
    }
    return magic_mount_su() ? 0 : 1;
}

int umount_su_now() {
    if (!enter_init_mount_ns()) {
        LOGE("magisk_su: could not enter init mount ns");
        return 1;
    }
    magic_umount_su();
    return 0;
}

int apply_magisk_compat_now() {
    const auto [value, supported] = get_feature(KSU_FEATURE_MAGISK_COMPAT);
    if (!supported) {
        LOGW("magisk_su: feature unsupported");
        return 1;
    }

    if (value != 0) {
        // Zygote must inherit the complete bind tree; defer mounting until boot.
        ensure_msud_running();
        LOGI("magisk_su: enabled (msud up; su mounts on next reboot)");
    } else {
        if (enter_init_mount_ns()) {
            magic_umount_su();
        } else {
            LOGW("magisk_su: could not enter init ns; su stays until reboot");
        }
        kill_msud();
        LOGI("magisk_su: disabled live (su unmounted, msud killed)");
    }
    return 0;
}

}  // namespace ksud
