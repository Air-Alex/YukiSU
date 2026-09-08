#ifndef __KSU_H_SUCOMPAT_VFS
#define __KSU_H_SUCOMPAT_VFS

#include <linux/types.h>

struct file;
struct inode;
struct path;

int ksu_sucompat_vfs_init(void);
void ksu_sucompat_vfs_exit(void);

int ksu_sucompat_vfs_set_enabled(bool enabled);
int ksu_sucompat_vfs_set_prompt_enabled(bool enabled);
/* enabled() is the lookup/exec gate; active() also covers pending retirement.
 */
bool ksu_sucompat_vfs_enabled(void);
bool ksu_sucompat_vfs_active(void);
bool ksu_sucompat_vfs_prompt_enabled(void);
bool ksu_sucompat_vfs_prompt_visible(void);

bool ksu_sucompat_vfs_is_inode(const struct inode *inode);
bool ksu_sucompat_vfs_is_path(const struct path *path);
bool ksu_sucompat_vfs_is_file(const struct file *file);

#endif // __KSU_H_SUCOMPAT_VFS
