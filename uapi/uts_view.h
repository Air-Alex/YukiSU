#ifndef __KSU_UAPI_UTS_VIEW_H
#define __KSU_UAPI_UTS_VIEW_H

#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif // #ifdef __cplusplus

#define KSU_UTS_VIEW_ABI_VERSION 2
#define KSU_UTS_NAME_LEN 65

#define KSU_UTS_FIELD_SYSNAME (1U << 0)
#define KSU_UTS_FIELD_NODENAME (1U << 1)
#define KSU_UTS_FIELD_RELEASE (1U << 2)
#define KSU_UTS_FIELD_VERSION (1U << 3)
#define KSU_UTS_FIELD_MACHINE (1U << 4)
#define KSU_UTS_FIELD_DOMAINNAME (1U << 5)
#define KSU_UTS_FIELD_VALID_MASK ((1U << 6) - 1)

#define KSU_UTS_VIEW_MODE_GLOBAL (1ULL << 0)
#define KSU_UTS_VIEW_MODE_DENY_SCOPED (1ULL << 1)
#define KSU_UTS_VIEW_MODE_VALID_MASK                                           \
  (KSU_UTS_VIEW_MODE_GLOBAL | KSU_UTS_VIEW_MODE_DENY_SCOPED)

struct ksu_uts_template {
  __u32 field_mask;
  __u32 reserved;
  char sysname[KSU_UTS_NAME_LEN];
  char nodename[KSU_UTS_NAME_LEN];
  char release[KSU_UTS_NAME_LEN];
  char version[KSU_UTS_NAME_LEN];
  char machine[KSU_UTS_NAME_LEN];
  char domainname[KSU_UTS_NAME_LEN];
};

#define KSU_UTS_CONFIG_UPDATE_GLOBAL (1U << 0)
#define KSU_UTS_CONFIG_UPDATE_DENY (1U << 1)
#define KSU_UTS_CONFIG_UPDATE_MODE (1U << 2)
#define KSU_UTS_CONFIG_UPDATE_VALID_MASK                                       \
  (KSU_UTS_CONFIG_UPDATE_GLOBAL | KSU_UTS_CONFIG_UPDATE_DENY |                 \
   KSU_UTS_CONFIG_UPDATE_MODE)

struct ksu_uts_view_config {
  __u32 version;
  __u32 size;
  __u32 update_mask;
  __u32 mode;
  struct ksu_uts_template global;
  struct ksu_uts_template deny;
};

enum ksu_uts_view_source {
  KSU_UTS_SOURCE_NONE = 0,
  KSU_UTS_SOURCE_BOOT = 1,
  KSU_UTS_SOURCE_RUNTIME = 2,
};

#define KSU_UTS_STATUS_ORIGINAL_VALID (1U << 0)
#define KSU_UTS_STATUS_BOOT_LOCKED (1U << 1)
#define KSU_UTS_STATUS_LATE_GAPS (1U << 2)
#define KSU_UTS_STATUS_LATE_UPDATED (1U << 3)
#define KSU_UTS_STATUS_LATE_CAPTURE (1U << 4)

struct ksu_uts_view_status {
  __u32 version;
  __u32 size;
  __u32 source;
  __u32 status_flags;
  __u64 mode;
  __u32 detached_task_count;
  __u32 reserved;
  struct ksu_uts_template original;
  struct ksu_uts_template effective_global;
};

#ifdef __cplusplus
}
#endif // #ifdef __cplusplus

#endif // #ifndef __KSU_UAPI_UTS_VIEW_H
