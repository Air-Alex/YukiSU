#ifndef __KSU_H_APP_PROFILE
#define __KSU_H_APP_PROFILE

#include "infra/su_mount_ns.h"
#include "uapi/app_profile.h"
#include "linux/init.h"

/*
 * Thread flag set after escalating with a NO_NEW_PRIVS root profile; blocks any
 * further KernelSU escalation for this thread and its children. Bit 63 is
 * unused by arch TIF flags (valid on 64-bit thread_info.flags).
 */
#define TIF_KSU_DISABLE_ESCAPE_WITH_ROOT 63

// Forward declarations
struct cred;

// Escalate current process to root with the appropriate profile
int escape_with_root_profile(void);

void escape_to_root_for_init(void);

void __init ksu_app_profile_init(void);

#endif // #ifndef __KSU_H_APP_PROFILE
