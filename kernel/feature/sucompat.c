#include <asm/current.h>
#include <asm/unistd.h>
#include <linux/compiler_types.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "arch.h"
#include "policy/feature.h"
#include "hook/syscall_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "supercall/supercall.h"
#include "uapi/supercall.h"
#include "feature/sucompat.h"

#define SU_PATH "/system/bin/su"

bool ksu_su_compat_enabled __read_mostly = true;
static bool magisk_compat_enabled __read_mostly;
static const char su_path[] = SU_PATH;

static int magisk_compat_feature_get(u64 *value)
{
	*value = magisk_compat_enabled ? 1 : 0;
	return 0;
}

static int magisk_compat_feature_set(u64 value)
{
	magisk_compat_enabled = value != 0;
	pr_info("magisk_compat: set to %d\n", magisk_compat_enabled);
	return 0;
}

static const struct ksu_feature_handler magisk_compat_handler = {
    .feature_id = KSU_FEATURE_MAGISK_COMPAT,
    .name = "magisk_compat",
    .get_handler = magisk_compat_feature_get,
    .set_handler = magisk_compat_feature_set,
};

void ksu_magisk_compat_init(void)
{
	if (ksu_register_feature_handler(&magisk_compat_handler))
		pr_err("magisk_compat: failed to register feature handler\n");
}

void ksu_magisk_compat_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_MAGISK_COMPAT);
}

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
    .feature_id = KSU_FEATURE_SU_COMPAT,
    .name = "su_compat",
    .get_handler = su_compat_feature_get,
    .set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	// To avoid having to mmap a page in userspace, just write below the
	// stack pointer.
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static char __user *empty_user_path(void)
{
	static const char empty_path[] = "";

	return userspace_stack_buffer(empty_path, sizeof(empty_path));
}

static bool is_su_path(const char __user *filename_user)
{
	char path[sizeof(su_path) + 1];
	const char __user *fn;
	long ret;
	unsigned long addr;

	if (unlikely(!filename_user))
		return false;

	addr = untagged_addr((unsigned long)filename_user);
	fn = (const char __user *)addr;
	memset(path, 0, sizeof(path));
	ret = strncpy_from_user(path, fn, sizeof(path));
	if (ret < 0)
		return false;
	path[sizeof(path) - 1] = '\0';

	return !memcmp(path, su_path, sizeof(su_path));
}

static bool is_ksud_visible(void)
{
	struct path path;

	if (kern_path(KSUD_PATH, 0, &path))
		return false;
	path_put(&path);
	return true;
}

static long ksu_handle_path_sucompat(int orig_nr, const struct pt_regs *regs,
				     const char *operation)
{
	const char __user *filename_user;
	const struct cred *old_cred;
	struct pt_regs redirect_regs;
	char __user *redirect_path;
	long ret;

	if (!ksu_su_compat_enabled)
		goto do_orig;

	if (!ksu_is_allow_uid_for_current(current_uid().val))
		goto do_orig;

	filename_user = (const char __user *)PT_REGS_PARM2(regs);
	if (!is_su_path(filename_user))
		goto do_orig;

	if (unlikely(!ksu_cred)) {
		pr_err("%s: KernelSU credential is unavailable\n", operation);
		goto do_orig;
	}

	old_cred = override_creds(ksu_cred);
	if (!is_ksud_visible())
		goto revert_orig;

	redirect_path = ksud_user_path();
	if (!redirect_path)
		goto revert_orig;

	pr_info("%s su->ksud\n", operation);
	redirect_regs = *regs;
	PT_REGS_PARM2(&redirect_regs) = (unsigned long)redirect_path;
	ret = ksu_syscall_table[orig_nr](&redirect_regs);
	revert_creds(old_cred);
	return ret;

revert_orig:
	revert_creds(old_cred);
do_orig:
	return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_faccessat_sucompat(int orig_nr, const struct pt_regs *regs)
{
	return ksu_handle_path_sucompat(orig_nr, regs, "faccessat");
}

long ksu_handle_stat_sucompat(int orig_nr, const struct pt_regs *regs)
{
	return ksu_handle_path_sucompat(orig_nr, regs, "newfstatat");
}

static void close_tmp_fd(unsigned int fd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	close_fd(fd);
#else
	ksys_close(fd);
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
}

static long
ksu_handle_execve_sucompat_common(const char __user **filename_user,
				  const char __user *const __user *argv_user,
				  unsigned long envp, bool execveat,
				  int orig_nr, const struct pt_regs *regs)
{
	const struct cred *old_cred;
	struct ksu_sulog_pending_event *pending_sucompat = NULL;
	struct pt_regs exec_regs;
	struct file *ksud_file;
	char __user *empty_path;
	int su_fd;
	int tmp_fd;
	long ret;

	if (execveat && ((int)PT_REGS_PARM1(regs) != AT_FDCWD ||
			 (int)PT_REGS_PARM5(regs) != 0))
		goto do_orig_execve;

	if (unlikely(!filename_user || !*filename_user))
		goto do_orig_execve;

	if (!ksu_su_compat_enabled)
		goto do_orig_execve;

	if (!ksu_is_allow_uid_for_current(current_uid().val))
		goto do_orig_execve;

	if (!is_su_path(*filename_user))
		goto do_orig_execve;

	pr_info("exec su found\n");
	if (unlikely(!ksu_cred)) {
		pr_err("exec su: KernelSU credential is unavailable\n");
		goto do_orig_execve;
	}

	tmp_fd = get_unused_fd_flags(O_CLOEXEC);
	if (tmp_fd < 0) {
		pr_err("alloc ksud fd failed: %d\n", tmp_fd);
		goto do_orig_execve;
	}

	old_cred = override_creds(ksu_cred);
	ksud_file = filp_open(KSUD_PATH, O_PATH, 0);
	revert_creds(old_cred);
	if (IS_ERR(ksud_file)) {
		pr_info("ksud is not visible for sucompat: %ld\n",
			PTR_ERR(ksud_file));
		put_unused_fd(tmp_fd);
		goto do_orig_execve;
	}
	fd_install(tmp_fd, ksud_file);

	empty_path = empty_user_path();
	if (!empty_path) {
		close_tmp_fd(tmp_fd);
		goto do_orig_execve;
	}

	pending_sucompat =
	    ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
	exec_regs = *regs;
	PT_REGS_PARM1(&exec_regs) = tmp_fd;
	PT_REGS_PARM2(&exec_regs) = (unsigned long)empty_path;
	PT_REGS_PARM3(&exec_regs) = (unsigned long)argv_user;
	PT_REGS_SYSCALL_PARM4(&exec_regs) = envp;
	PT_REGS_PARM5(&exec_regs) = AT_EMPTY_PATH;

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile failed: %ld\n", ret);
		ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
		close_tmp_fd(tmp_fd);
		return ret;
	}

	ret = ksu_syscall_table[__NR_execveat](&exec_regs);
	if (ret < 0) {
		pr_err("failed to exec ksud as su: %ld\n", ret);
		close_tmp_fd(tmp_fd);
	} else {
		su_fd = ksu_install_su_fd();
		if (su_fd < 0)
			pr_warn("install su session fd failed: %d\n", su_fd);
	}
	ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
	return ret;

do_orig_execve:
	return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr,
				const struct pt_regs *regs)
{
	return ksu_handle_execve_sucompat_common(
	    filename_user,
	    (const char __user *const __user *)PT_REGS_PARM2(regs),
	    PT_REGS_PARM3(regs), false, orig_nr, regs);
}

long ksu_handle_execveat_sucompat(const char __user **filename_user,
				  int orig_nr, const struct pt_regs *regs)
{
	return ksu_handle_execve_sucompat_common(
	    filename_user,
	    (const char __user *const __user *)PT_REGS_PARM3(regs),
	    PT_REGS_SYSCALL_PARM4(regs), true, orig_nr, regs);
}

// sucompat: permitted process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler))
		pr_err("Failed to register su_compat feature handler\n");
	ksu_magisk_compat_init();
}

void ksu_sucompat_exit()
{
	ksu_magisk_compat_exit();
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
