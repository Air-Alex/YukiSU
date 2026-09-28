#ifndef KASUMI_OWNER_H
#define KASUMI_OWNER_H

#include <linux/fs.h>
#include <linux/types.h>

int kasumi_owner_init(void);
void kasumi_owner_exit(void);
bool kasumi_owner_available(void);
void kasumi_owner_observe(struct file *file);
uid_t kasumi_owner_freeze(void);

#endif
