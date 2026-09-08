#ifndef __KSU_H_HOOK_MANAGER
#define __KSU_H_HOOK_MANAGER

#include "hook/tp_marker.h"

// Hook manager initialization and cleanup
void ksu_syscall_hook_manager_init(void);
void ksu_syscall_hook_manager_exit(void);

int ksu_set_sucompat_legacy_path_hooks(bool enabled);

#endif // #ifndef __KSU_H_HOOK_MANAGER
