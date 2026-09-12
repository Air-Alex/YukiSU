#ifndef _KASUMI_FAKE_MOUNTINFO_H
#define _KASUMI_FAKE_MOUNTINFO_H

#include <linux/fs.h>
#include <linux/poll.h>

struct mnt_namespace;

int kasumi_fake_mi_init(void);
void kasumi_fake_mi_exit(void);
bool kasumi_fake_mi_active(void);
bool kasumi_fake_mi_redirect(struct file *file,
			     struct mnt_namespace **original_ns);
void kasumi_fake_mi_put_ns(struct mnt_namespace *ns);
void kasumi_fake_mi_invalidate_all(void);
u64 kasumi_fake_mi_generation(void);
void kasumi_fake_mi_poll_wait(struct file *file,
			      struct poll_table_struct *wait);

#endif
