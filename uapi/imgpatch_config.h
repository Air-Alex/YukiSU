#ifndef __KSU_UAPI_IMGPATCH_CONFIG_H
#define __KSU_UAPI_IMGPATCH_CONFIG_H

#include <linux/types.h>

#include "uapi/uts_view.h"

#ifdef __cplusplus
extern "C" {
#endif // #ifdef __cplusplus

/* "KSUICFG1" in little-endian byte order. */
#define KSU_IMGPATCH_CONFIG_MAGIC 0x314746434955534bULL
#define KSU_IMGPATCH_CONFIG_VERSION 1U

#define KSU_IMGPATCH_CONFIG_ALLOW_SHELL (1ULL << 0)
#define KSU_IMGPATCH_CONFIG_ENABLE_ADBD (1ULL << 1)
#define KSU_IMGPATCH_CONFIG_UTS_BOOT (1ULL << 2)
#define KSU_IMGPATCH_CONFIG_VALID_FLAGS                                        \
  (KSU_IMGPATCH_CONFIG_ALLOW_SHELL | KSU_IMGPATCH_CONFIG_ENABLE_ADBD |         \
   KSU_IMGPATCH_CONFIG_UTS_BOOT)

/*
 * Patchable, on-disk ABI stored in the LKM .data section. Keep this block at
 * 512 bytes so future versions can add early-boot settings without changing
 * the marker scanner used by older patchers.
 */
struct ksu_imgpatch_config {
  __u64 magic;
  __u32 version;
  __u32 size;
  __u64 flags;
  struct ksu_uts_template uts;
  __u64 reserved[11];
};

#ifdef __cplusplus
}
#endif // #ifdef __cplusplus

#endif // #ifndef __KSU_UAPI_IMGPATCH_CONFIG_H
