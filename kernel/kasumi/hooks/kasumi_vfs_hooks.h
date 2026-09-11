#ifndef _KASUMI_VFS_HOOKS_H
#define _KASUMI_VFS_HOOKS_H

struct dir_context;
struct file;
struct kasumi_filldir_wrapper;

struct kasumi_filldir_wrapper *
kasumi_iterate_prepare_wrapper(struct file *file, struct dir_context *orig_ctx);
void kasumi_iterate_finish_wrapper(struct kasumi_filldir_wrapper *wrapper);

#endif
