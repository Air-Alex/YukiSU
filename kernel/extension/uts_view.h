#ifndef __KSU_EXT_UTS_VIEW_H
#define __KSU_EXT_UTS_VIEW_H

#include <linux/types.h>

#include "uapi/uts_view.h"

int ksu_uts_view_init(void);
void ksu_uts_view_exit(void);
bool ksu_uts_view_boot_requested(void);

int ksu_uts_view_get_config(struct ksu_uts_view_config *config);
int ksu_uts_view_set_config(const struct ksu_uts_view_config *config);
int ksu_uts_view_get_status(struct ksu_uts_view_status *status);

void ksu_uts_view_on_setresuid(uid_t old_uid, uid_t new_uid);

#endif // #ifndef __KSU_EXT_UTS_VIEW_H
