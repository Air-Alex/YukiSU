#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/security.h>
#include <linux/version.h>

#include "feature/sucompat_exec.h"
#include "feature/sucompat_prompt.h"
#include "feature/sucompat_vfs.h"
#include "kasumi_bootstrap.h"
#include "kasumi_dirhijack.h"
#include "kasumi_vnode.h"
#include "ksu.h"
#include "policy/allowlist.h"
#include "selinux/selinux.h"

static DEFINE_MUTEX(su_view_lock);
static bool su_ready;
static bool su_enabled;
static bool su_prompt_enabled;
static const struct inode_operations su_inode_ops;

bool ksu_sucompat_vfs_enabled(void)
{
	return kasumi_is_ready() && READ_ONCE(su_enabled);
}
bool ksu_sucompat_vfs_active(void)
{
	return ksu_sucompat_vfs_enabled();
}
bool ksu_sucompat_vfs_prompt_enabled(void)
{
	return READ_ONCE(su_prompt_enabled);
}

bool ksu_sucompat_vfs_prompt_visible(void)
{
	uid_t uid = current_uid().val;

#ifdef CONFIG_COMPAT
	if (is_compat_task())
		return false;
#endif
	return ksu_sucompat_vfs_enabled() && READ_ONCE(su_prompt_enabled) &&
	       ksu_sucompat_prompt_consumer_ready() && is_appuid(uid) &&
	       !is_isolated_process(uid) && !ksu_uid_should_umount(uid) &&
	       !ksu_is_allow_uid_for_current(uid);
}

bool ksu_sucompat_vfs_visible(void)
{
#ifdef CONFIG_COMPAT
	if (is_compat_task())
		return false;
#endif
	return ksu_sucompat_vfs_enabled() &&
	       (ksu_is_allow_uid_for_current(current_uid().val) ||
		ksu_sucompat_vfs_prompt_visible());
}

bool ksu_sucompat_vfs_is_inode(const struct inode *inode)
{
	return inode && inode->i_op == &su_inode_ops;
}

bool ksu_sucompat_vfs_is_path(const struct path *path)
{
	return path && path->dentry &&
	       ksu_sucompat_vfs_is_inode(d_inode(path->dentry));
}

bool ksu_sucompat_vfs_is_file(const struct file *file)
{
	return file && ksu_sucompat_vfs_is_inode(file_inode(file));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int su_permission(struct mnt_idmap *idmap, struct inode *inode, int mask)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int su_permission(struct user_namespace *userns, struct inode *inode,
			 int mask)
#else
static int su_permission(struct inode *inode, int mask)
#endif
{
	if (!ksu_sucompat_vfs_visible())
		return -EACCES;
	return mask & MAY_WRITE ? -EROFS : 0;
}

static int su_open(struct inode *inode, struct file *file)
{
	return ksu_sucompat_exec_file_open(file);
}

static const struct inode_operations su_inode_ops = {
    .permission = su_permission,
};
static const struct file_operations su_file_ops = {
    .owner = THIS_MODULE,
    .open = su_open,
    .release = ksu_sucompat_exec_file_release,
};

int ksu_sucompat_vfs_setup_inode(struct inode *inode)
{
	int ret;

	inode->i_op = &su_inode_ops;
	inode->i_fop = &su_file_ops;
	inode->i_mode = S_IFREG | 0555;
	inode_lock(inode);
	ret = security_inode_notifysecctx(inode, (void *)KSU_FILE_CONTEXT,
					  sizeof(KSU_FILE_CONTEXT) - 1);
	inode_unlock(inode);
	return ret;
}

static int su_bind_locked(void)
{
	const struct cred *old;
	int ret;

	lockdep_assert_held(&su_view_lock);
	if (!ksu_cred)
		return -EAGAIN;
	old = override_creds(ksu_cred);
	ret =
	    kasumi_dirhijack_add("/system/bin/su", NULL,
				 (1UL << 63) | 0x53550001UL, KASUMI_VNODE_F_SU);
	revert_creds(old);
	return ret;
}

int ksu_sucompat_vfs_refresh(void)
{
	int ret = 0;

	mutex_lock(&su_view_lock);
	if (su_ready && su_enabled)
		ret = su_bind_locked();
	mutex_unlock(&su_view_lock);
	return ret;
}

int ksu_sucompat_vfs_set_enabled(bool enabled)
{
	int ret = 0;

	mutex_lock(&su_view_lock);
	if (enabled && (!su_ready || !kasumi_is_ready())) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (enabled) {
		ret = su_bind_locked();
		if (ret)
			goto out;
	}
	WRITE_ONCE(su_enabled, enabled);
out:
	mutex_unlock(&su_view_lock);
	return ret;
}

int ksu_sucompat_vfs_set_prompt_enabled(bool enabled)
{
	if (enabled && (!READ_ONCE(su_ready) || !kasumi_is_ready()))
		return -EOPNOTSUPP;
	WRITE_ONCE(su_prompt_enabled, enabled);
	return 0;
}

int ksu_sucompat_vfs_init(void)
{
	WRITE_ONCE(su_ready, true);
	return 0;
}

void ksu_sucompat_vfs_exit(void)
{
	mutex_lock(&su_view_lock);
	WRITE_ONCE(su_enabled, false);
	WRITE_ONCE(su_prompt_enabled, false);
	if (su_ready) {
		WRITE_ONCE(su_ready, false);
	}
	mutex_unlock(&su_view_lock);
}
