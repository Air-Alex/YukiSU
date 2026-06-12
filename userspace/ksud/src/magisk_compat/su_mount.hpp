#pragma once

namespace ksud {

void mount_magisk_compat_su_if_enabled();

// Enabling mounts on next boot; disabling tears down the live mount and broker.
int apply_magisk_compat_now();

int mount_su_now();
int umount_su_now();

}  // namespace ksud
