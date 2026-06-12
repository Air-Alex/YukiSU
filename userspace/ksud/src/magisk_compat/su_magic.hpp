#pragma once

namespace ksud {

// Caller must already be in the target mount namespace.
bool magic_mount_su();
void magic_umount_su();
bool su_magic_mounted();

}  // namespace ksud
