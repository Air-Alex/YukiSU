#include <linux/binfmts.h>
#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/task.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/ptrace.h>
#include <linux/mm.h>
#include <linux/elf.h>
#include <linux/auxvec.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/shmem_fs.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <asm/cacheflush.h>

#include "policy/feature.h"
#include "zygote_probe.h"
#include "zygote_nl.h"
#include "hook/lsm_hook.h"
#include "selinux/selinux.h"
#include "ksu.h"
#include "klog.h" // IWYU pragma: keep
#include "uapi/yukizygisk.h"

static const char app_process[] = "app_process";

static bool yukizygisk_enabled;

struct zp_zygote_guard {
	char name[YZ_ZYGOTE_NAME_MAX];
	pid_t last_pid;
	u32 zygote_crashes;
};

#define ZP_ZYGOTE_GUARD_MAX 4
static DEFINE_SPINLOCK(zp_safemode_lock);
static struct zp_zygote_guard zp_zygote_guards[ZP_ZYGOTE_GUARD_MAX];
static bool zp_safemode_active;
static u32 zp_safemode_zygote_crashes;
static char zp_safemode_zygote[YZ_ZYGOTE_NAME_MAX];

#define ZP_ENABLE_LSM_INJECTOR 1

#define ZP_STUB_EXTINFO_OFF 0xa00
#define ZP_STUB_STR_OFF 0xc00
#define ZP_STUB_ENTRY_STR_OFF 0xd00

/* Dynamic linker symbol offsets, split by userspace ABI. */
static u64 zp_dlopen_off;
static u64 zp_dlsym_off;
static u64 zp_dlopen32_off;
static u64 zp_dlsym32_off;

void ksu_zygote_probe_set_dlopen_off(u64 dlopen_off, u64 dlsym_off)
{
	zp_dlopen_off = dlopen_off;
	zp_dlsym_off = dlsym_off;
	pr_info("zygote_probe: dlopen=0x%llx dlsym=0x%llx set\n", dlopen_off,
		dlsym_off);
}

void ksu_zygote_probe_set_dlopen32_off(u64 dlopen_off, u64 dlsym_off)
{
	zp_dlopen32_off = dlopen_off;
	zp_dlsym32_off = dlsym_off;
	pr_info("zygote_probe: compat dlopen=0x%llx dlsym=0x%llx set\n",
		dlopen_off, dlsym_off);
}

static bool zp_yukilinker_enabled;

static DEFINE_MUTEX(zp_native_targets_lock);
static struct yz_native_target zp_native_targets[YZ_NATIVE_TARGET_MAX];
static u32 zp_native_target_count;

static DEFINE_MUTEX(zp_early_native_lock);
static struct yz_early_native_entry
    zp_early_native_entries[YZ_NATIVE_TARGET_MAX];
static u32 zp_early_native_count;
static bool zp_early_native_loaded;
static bool zp_early_native_enabled;
static bool zp_early_native_watchdog;
static u64 zp_early_dlopen_off;
static u64 zp_early_dlsym_off;
static u64 zp_early_dlopen32_off;
static u64 zp_early_dlsym32_off;
static unsigned long zp_early_native_retry_deadline;
static bool zp_early_native_missing_logged;

#define ZP_NATIVE_POLICY_TIMEOUT (10 * HZ)
#define ZP_MODULE_POLICY_TIMEOUT (10 * HZ)
#define ZP_EARLY_NATIVE_RETRY_WINDOW (15 * HZ)

struct zp_native_policy_pending {
	struct list_head list;
	pid_t tgid;
	struct ksu_file_load_policy state;
	struct delayed_work timeout;
	bool pending;
};

static DEFINE_MUTEX(zp_native_policy_lock);
static LIST_HEAD(zp_native_policy_pending);

struct zp_module_policy_group {
	struct list_head list;
	struct ksu_file_load_policy state;
	u32 users;
};

struct zp_module_policy_holder {
	struct list_head list;
	struct zp_module_policy_group *group;
	struct delayed_work timeout;
	pid_t tgid;
	bool pending;
};

static DEFINE_MUTEX(zp_module_policy_lock);
static LIST_HEAD(zp_module_policy_groups);
static LIST_HEAD(zp_module_policy_holders);

static int ksu_zygote_probe_restore_module_policy(pid_t tgid);

static bool
zp_native_policy_has_additions(const struct ksu_file_load_policy *state)
{
	return state && (state->added_av || state->tmpfs_added_av ||
			 state->process_added_av || state->dir_added_av);
}

void ksu_zygote_probe_set_yukilinker(bool enabled)
{
	zp_yukilinker_enabled = enabled;
	pr_info("zygote_probe: yukilinker first-stage = %d\n", enabled);
}

int ksu_zygote_probe_set_native_targets(const struct yz_native_targets_cmd *cmd)
{
	u32 i, n;

	if (!cmd)
		return -EINVAL;

	n = cmd->count;
	if (n > YZ_NATIVE_TARGET_MAX)
		n = YZ_NATIVE_TARGET_MAX;

	mutex_lock(&zp_native_targets_lock);
	zp_native_target_count = 0;
	for (i = 0; i < n; i++) {
		const struct yz_native_target *src = &cmd->targets[i];
		struct yz_native_target *dst =
		    &zp_native_targets[zp_native_target_count];

		if (src->type != YZ_NATIVE_TARGET_NAME &&
		    src->type != YZ_NATIVE_TARGET_PATH)
			continue;
		if (src->value[0] == '\0')
			continue;
		memcpy(dst, src, sizeof(*dst));
		dst->value[YZ_NATIVE_TARGET_VALUE_MAX - 1] = '\0';
		zp_native_target_count++;
	}
	mutex_unlock(&zp_native_targets_lock);

	pr_info("zygote_probe: native target count=%u\n",
		zp_native_target_count);
	return 0;
}

static void zp_restore_native_policy_state(struct ksu_file_load_policy *state)
{
	if (!zp_native_policy_has_additions(state))
		return;
	ksu_file_load_policy_restore(state);
	memset(state, 0, sizeof(*state));
}

static void zp_native_policy_timeout(struct work_struct *work)
{
	struct zp_native_policy_pending *entry = container_of(
	    to_delayed_work(work), struct zp_native_policy_pending, timeout);
	bool restore = false;

	mutex_lock(&zp_native_policy_lock);
	if (entry->pending) {
		entry->pending = false;
		list_del_init(&entry->list);
		restore = true;
	}
	mutex_unlock(&zp_native_policy_lock);

	if (!restore)
		return;

	pr_info("zygote_probe: load policy timeout pid=%d added=0x%x "
		"tmpfs=0x%x process=0x%x\n",
		entry->tgid, entry->state.added_av, entry->state.tmpfs_added_av,
		entry->state.process_added_av);
	zp_restore_native_policy_state(&entry->state);
	kfree(entry);
}

static void zp_publish_native_policy_state(pid_t tgid,
					   struct ksu_file_load_policy *state)
{
	struct zp_native_policy_pending *entry;
	struct zp_native_policy_pending *cur;
	struct zp_native_policy_pending *tmp;
	LIST_HEAD(old_entries);

	if (!zp_native_policy_has_additions(state))
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		pr_info("zygote_probe: load policy pid=%d alloc failed, "
			"restoring immediately\n",
			tgid);
		zp_restore_native_policy_state(state);
		return;
	}
	entry->tgid = tgid;
	entry->state = *state;
	entry->pending = true;
	INIT_LIST_HEAD(&entry->list);
	INIT_DELAYED_WORK(&entry->timeout, zp_native_policy_timeout);
	memset(state, 0, sizeof(*state));

	mutex_lock(&zp_native_policy_lock);
	list_for_each_entry_safe (cur, tmp, &zp_native_policy_pending, list) {
		if (cur->tgid != tgid)
			continue;
		cur->pending = false;
		list_move_tail(&cur->list, &old_entries);
	}
	list_add_tail(&entry->list, &zp_native_policy_pending);
	mutex_unlock(&zp_native_policy_lock);

	schedule_delayed_work(&entry->timeout, ZP_NATIVE_POLICY_TIMEOUT);

	list_for_each_entry_safe (cur, tmp, &old_entries, list) {
		cancel_delayed_work_sync(&cur->timeout);
		list_del(&cur->list);
		zp_restore_native_policy_state(&cur->state);
		kfree(cur);
	}
	pr_info("zygote_probe: load policy pid=%d pending added=0x%x "
		"tmpfs=0x%x process=0x%x\n",
		tgid, entry->state.added_av, entry->state.tmpfs_added_av,
		entry->state.process_added_av);
}

int ksu_zygote_probe_restore_native_policy(pid_t tgid)
{
	struct zp_native_policy_pending *entry;
	struct zp_native_policy_pending *tmp;
	LIST_HEAD(todo);
	int n = 0;

	if (tgid <= 0)
		return -EINVAL;

	mutex_lock(&zp_native_policy_lock);
	list_for_each_entry_safe (entry, tmp, &zp_native_policy_pending, list) {
		if (entry->tgid != tgid)
			continue;
		entry->pending = false;
		list_move_tail(&entry->list, &todo);
	}
	mutex_unlock(&zp_native_policy_lock);

	list_for_each_entry_safe (entry, tmp, &todo, list) {
		cancel_delayed_work_sync(&entry->timeout);
		list_del(&entry->list);
		zp_restore_native_policy_state(&entry->state);
		kfree(entry);
		n++;
	}
	pr_info("zygote_probe: load policy restore pid=%d entries=%d\n", tgid,
		n);
	return ksu_zygote_probe_restore_module_policy(tgid);
}

static struct zp_module_policy_group *
zp_find_module_policy_group(const struct ksu_file_load_policy *state)
{
	struct zp_module_policy_group *group;

	list_for_each_entry (group, &zp_module_policy_groups, list) {
		if (group->state.src_type == state->src_type &&
		    group->state.tgt_type == state->tgt_type)
			return group;
	}
	return NULL;
}

static struct zp_module_policy_holder *
zp_find_module_policy_holder(pid_t tgid,
			     const struct zp_module_policy_group *group)
{
	struct zp_module_policy_holder *holder;

	list_for_each_entry (holder, &zp_module_policy_holders, list) {
		if (holder->pending && holder->tgid == tgid &&
		    holder->group == group)
			return holder;
	}
	return NULL;
}

static int zp_merge_module_policy_state(struct ksu_file_load_policy *dst,
					const struct ksu_file_load_policy *src)
{
	if (!dst->src_type) {
		*dst = *src;
		return 0;
	}
	if (dst->src_type != src->src_type || dst->tgt_type != src->tgt_type)
		return -EINVAL;
	if (src->process_added_av) {
		if (!src->process_lease_refs)
			return -EINVAL;
		if (dst->process_added_av &&
		    (dst->process_type != src->process_type ||
		     dst->process_class != src->process_class ||
		     dst->process_added_av != src->process_added_av))
			return -EINVAL;
		if (!dst->process_added_av) {
			dst->process_type = src->process_type;
			dst->process_class = src->process_class;
		}
		if (U32_MAX - dst->process_lease_refs < src->process_lease_refs)
			return -EOVERFLOW;
	}
	dst->added_av |= src->added_av;
	dst->dir_added_av |= src->dir_added_av;
	dst->tmpfs_added_av |= src->tmpfs_added_av;
	dst->process_added_av |= src->process_added_av;
	dst->process_lease_refs += src->process_lease_refs;
	return 0;
}

static void
zp_put_module_policy_group_locked(struct zp_module_policy_group *group)
{
	int ret;

	if (!group || !group->users)
		return;
	if (--group->users)
		return;

	list_del(&group->list);
	ret = ksu_file_load_policy_restore(&group->state);
	pr_info("zygote_probe: module policy released src=%u tgt=%u ret=%d\n",
		group->state.src_type, group->state.tgt_type, ret);
	kfree(group);
}

static void zp_module_policy_timeout(struct work_struct *work)
{
	struct zp_module_policy_holder *holder = container_of(
	    to_delayed_work(work), struct zp_module_policy_holder, timeout);
	bool release = false;

	mutex_lock(&zp_module_policy_lock);
	if (holder->pending) {
		holder->pending = false;
		list_del_init(&holder->list);
		pr_info("zygote_probe: module policy timeout pid=%d\n",
			holder->tgid);
		zp_put_module_policy_group_locked(holder->group);
		release = true;
	}
	mutex_unlock(&zp_module_policy_lock);

	if (release)
		kfree(holder);
}

int ksu_zygote_probe_allow_module_policy(pid_t tgid, struct file *dir,
					 const struct cred *cred)
{
	struct zp_module_policy_group *group;
	struct zp_module_policy_holder *holder;
	struct zp_module_policy_group *new_group;
	struct zp_module_policy_holder *new_holder;
	struct ksu_file_load_policy state = {0};
	int restore_ret;
	int ret;

	if (tgid <= 0 || !dir || !cred)
		return -EINVAL;

	new_group = kzalloc(sizeof(*new_group), GFP_KERNEL);
	new_holder = kzalloc(sizeof(*new_holder), GFP_KERNEL);
	if (!new_group || !new_holder) {
		kfree(new_group);
		kfree(new_holder);
		return -ENOMEM;
	}

	mutex_lock(&zp_module_policy_lock);
	ret = ksu_file_load_policy_allow_cred(dir, cred, &state);
	if (ret)
		goto out_unlock;
	ret = ksu_file_load_policy_allow_execmem_cred(cred, &state);
	if (ret)
		goto out_restore;

	group = zp_find_module_policy_group(&state);
	if (!group && !zp_native_policy_has_additions(&state))
		goto out_unlock;
	if (!group) {
		group = new_group;
		new_group = NULL;
		INIT_LIST_HEAD(&group->list);
		group->state = state;
		list_add_tail(&group->list, &zp_module_policy_groups);
	} else {
		ret = zp_merge_module_policy_state(&group->state, &state);
		if (ret)
			goto out_restore;
	}
	memset(&state, 0, sizeof(state));

	holder = zp_find_module_policy_holder(tgid, group);
	if (holder)
		goto out_unlock;

	holder = new_holder;
	new_holder = NULL;
	INIT_LIST_HEAD(&holder->list);
	holder->group = group;
	holder->tgid = tgid;
	holder->pending = true;
	INIT_DELAYED_WORK(&holder->timeout, zp_module_policy_timeout);
	list_add_tail(&holder->list, &zp_module_policy_holders);
	group->users++;
	schedule_delayed_work(&holder->timeout, ZP_MODULE_POLICY_TIMEOUT);
	pr_info("zygote_probe: module policy armed pid=%d src=%u tgt=%u "
		"file=0x%x dir=0x%x tmpfs=0x%x process=0x%x\n",
		tgid, group->state.src_type, group->state.tgt_type,
		group->state.added_av, group->state.dir_added_av,
		group->state.tmpfs_added_av, group->state.process_added_av);

	goto out_unlock;

out_restore:
	restore_ret = ksu_file_load_policy_restore(&state);
	if (restore_ret)
		pr_err("zygote_probe: module policy rollback pid=%d ret=%d\n",
		       tgid, restore_ret);

out_unlock:
	mutex_unlock(&zp_module_policy_lock);
	kfree(new_group);
	kfree(new_holder);
	return ret;
}

static int ksu_zygote_probe_restore_module_policy(pid_t tgid)
{
	struct zp_module_policy_holder *holder;
	struct zp_module_policy_holder *tmp;
	LIST_HEAD(todo);
	int n = 0;

	mutex_lock(&zp_module_policy_lock);
	list_for_each_entry_safe (holder, tmp, &zp_module_policy_holders,
				  list) {
		if (!holder->pending || holder->tgid != tgid)
			continue;
		holder->pending = false;
		list_move_tail(&holder->list, &todo);
	}
	mutex_unlock(&zp_module_policy_lock);

	list_for_each_entry (holder, &todo, list)
		cancel_delayed_work_sync(&holder->timeout);

	mutex_lock(&zp_module_policy_lock);
	list_for_each_entry_safe (holder, tmp, &todo, list) {
		list_del(&holder->list);
		zp_put_module_policy_group_locked(holder->group);
		kfree(holder);
		n++;
	}
	mutex_unlock(&zp_module_policy_lock);

	if (n)
		pr_info(
		    "zygote_probe: module policy restore pid=%d entries=%d\n",
		    tgid, n);
	return 0;
}

static void zp_cleanup_module_policies(void)
{
	struct zp_module_policy_holder *holder;
	struct zp_module_policy_holder *tmp;
	LIST_HEAD(todo);

	mutex_lock(&zp_module_policy_lock);
	list_for_each_entry_safe (holder, tmp, &zp_module_policy_holders,
				  list) {
		holder->pending = false;
		list_move_tail(&holder->list, &todo);
	}
	mutex_unlock(&zp_module_policy_lock);

	list_for_each_entry (holder, &todo, list)
		cancel_delayed_work_sync(&holder->timeout);

	mutex_lock(&zp_module_policy_lock);
	list_for_each_entry_safe (holder, tmp, &todo, list) {
		list_del(&holder->list);
		zp_put_module_policy_group_locked(holder->group);
		kfree(holder);
	}
	mutex_unlock(&zp_module_policy_lock);
}

/* Patch a movz/movk x<d> sequence. */
static void __maybe_unused zp_patch_imm64(u32 *insn, u64 val)
{
	int i;

	for (i = 0; i < 4; i++) {
		u16 imm = (val >> (16 * i)) & 0xffff;

		insn[i] = (insn[i] & ~(0xffffu << 5)) | ((u32)imm << 5);
	}
}

/* 6.12 made bprm_committed_creds const. */
#define ZP_BPRM_HOOK_TARGET "selinux_bprm_committed_creds"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define ZP_BPRM_HOOK_CONST 1
#define ZP_BPRM_HOOK_ABI "const struct linux_binprm *"
#else
#define ZP_BPRM_HOOK_CONST 0
#define ZP_BPRM_HOOK_ABI "struct linux_binprm *"
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSIO...

#if ZP_BPRM_HOOK_CONST
typedef const struct linux_binprm zp_bprm_arg_t;
#else
typedef struct linux_binprm zp_bprm_arg_t;
#endif // #if ZP_BPRM_HOOK_CONST

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define ZP_BPRM_HOOK_CFI "kcfi"
#else
#define ZP_BPRM_HOOK_CFI "clang-cfi/.cfi_jt"
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSIO...

static void my_bprm_committed_creds(zp_bprm_arg_t *bprm);
static struct ksu_lsm_hook zygote_probe_hook = KSU_LSM_HOOK_INIT(
    bprm_committed_creds, ZP_BPRM_HOOK_TARGET, my_bprm_committed_creds, 0);

typedef void (*bprm_committed_creds_fn)(zp_bprm_arg_t *bprm);

static int yukizygisk_feature_get(u64 *value)
{
	*value = READ_ONCE(yukizygisk_enabled) ? 1 : 0;
	return 0;
}

static int yukizygisk_feature_set(u64 value)
{
	WRITE_ONCE(yukizygisk_enabled, value != 0);
	pr_info("zygote_probe: YukiZygisk %s\n",
		yukizygisk_enabled ? "ENABLED" : "disabled");
	return 0;
}

static const struct ksu_feature_handler yukizygisk_feature_handler = {
    .feature_id = KSU_FEATURE_YUKIZYGISK,
    .name = "yukizygisk",
    .get_handler = yukizygisk_feature_get,
    .set_handler = yukizygisk_feature_set,
};

static bool zp_is_app_process_path(const char *filename)
{
	const char *base;

	if (!filename)
		return false;
	base = strrchr(filename, '/');
	base = base ? base + 1 : filename;
	return !strncmp(base, app_process, sizeof(app_process) - 1);
}

static const char *zp_basename(const char *path)
{
	const char *base;

	if (!path)
		return NULL;
	base = strrchr(path, '/');
	return base ? base + 1 : path;
}

static void zp_copy_name(char *dst, size_t dst_len, const char *src)
{
	size_t i;

	if (!dst_len)
		return;
	for (i = 0; i + 1 < dst_len && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

static bool zp_safemode_is_active(void)
{
	return READ_ONCE(zp_safemode_active);
}

static int zp_zygote_guard_slot_locked(const char *name, int *free_slot)
{
	int i;

	if (free_slot)
		*free_slot = -1;

	for (i = 0; i < ZP_ZYGOTE_GUARD_MAX; i++) {
		if (zp_zygote_guards[i].name[0] == '\0') {
			if (free_slot && *free_slot < 0)
				*free_slot = i;
			continue;
		}
		if (!strcmp(zp_zygote_guards[i].name, name))
			return i;
	}
	return -1;
}

static bool zp_zygote_safemode_should_skip(const char *name)
{
	unsigned long flags;
	char zygote[YZ_ZYGOTE_NAME_MAX];
	pid_t pid = current->tgid;
	u32 crashes = 0;
	bool activate = false;
	bool skip = false;
	int free_slot;
	int slot;

	zp_copy_name(zygote, sizeof(zygote),
		     (name && name[0]) ? name : "zygote");

	spin_lock_irqsave(&zp_safemode_lock, flags);
	if (zp_safemode_active) {
		skip = true;
		crashes = zp_safemode_zygote_crashes;
	} else {
		slot = zp_zygote_guard_slot_locked(zygote, &free_slot);
		if (slot < 0 && free_slot >= 0) {
			slot = free_slot;
			zp_copy_name(zp_zygote_guards[slot].name,
				     sizeof(zp_zygote_guards[slot].name),
				     zygote);
		}
		if (slot >= 0) {
			struct zp_zygote_guard *guard = &zp_zygote_guards[slot];

			if (guard->last_pid == 0) {
				guard->last_pid = pid;
			} else if (guard->last_pid != pid) {
				guard->last_pid = pid;
				guard->zygote_crashes++;
				crashes = guard->zygote_crashes;
				if (crashes >= YZ_ZYGOTE_CRASH_THRESHOLD) {
					WRITE_ONCE(zp_safemode_active, true);
					zp_safemode_zygote_crashes = crashes;
					zp_copy_name(zp_safemode_zygote,
						     sizeof(zp_safemode_zygote),
						     zygote);
					activate = true;
					skip = true;
				}
			}
		}
	}
	spin_unlock_irqrestore(&zp_safemode_lock, flags);

	if (activate) {
		pr_warn("zygote_probe: safemode enabled after %u %s "
			"restart(s); skip pid=%d\n",
			crashes, zygote, pid);
		ksu_zygote_nl_emit_safemode((u32)pid, crashes);
	} else if (skip) {
		pr_info("zygote_probe: safemode active, skip zygote pid=%d "
			"name=%s crashes=%u\n",
			pid, zygote, crashes);
	}
	return skip;
}

int ksu_zygote_probe_get_safemode(struct yz_safemode_status_cmd *cmd)
{
	unsigned long flags;

	if (!cmd)
		return -EINVAL;

	memset(cmd, 0, sizeof(*cmd));
	spin_lock_irqsave(&zp_safemode_lock, flags);
	cmd->active = zp_safemode_active ? 1 : 0;
	cmd->zygote_crashes = zp_safemode_zygote_crashes;
	zp_copy_name(cmd->zygote, sizeof(cmd->zygote), zp_safemode_zygote);
	spin_unlock_irqrestore(&zp_safemode_lock, flags);
	return 0;
}

static bool zp_match_early_native_target(const char *filename, char *label,
					 size_t label_len, u8 *target_type);

static bool zp_is_init_child(void)
{
	struct task_struct *parent;
	bool is_init_child;

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	is_init_child = parent && task_pid_nr(parent) == 1;
	rcu_read_unlock();
	return is_init_child;
}

static bool zp_match_live_native_target(const char *filename, char *label,
					size_t label_len, u8 *target_type)
{
	const char *base = zp_basename(filename);
	bool matched = false;
	u32 i;

	if (target_type)
		*target_type = 0;
	if (!filename || !base)
		return false;

	mutex_lock(&zp_native_targets_lock);
	for (i = 0; i < zp_native_target_count; i++) {
		const struct yz_native_target *t = &zp_native_targets[i];

		if (t->type == YZ_NATIVE_TARGET_NAME) {
			if (strcmp(base, t->value))
				continue;
		} else if (t->type == YZ_NATIVE_TARGET_PATH) {
			if (strcmp(filename, t->value))
				continue;
		} else {
			continue;
		}
		zp_copy_name(label, label_len, t->value);
		if (target_type)
			*target_type = t->type;
		matched = true;
		break;
	}
	mutex_unlock(&zp_native_targets_lock);
	return matched;
}

static bool zp_next_arg(unsigned long *p, unsigned long end, char *arg,
			size_t arg_len)
{
	char c = '\0';
	int i = 0;

	if (!p || !arg || !arg_len || *p >= end)
		return false;

	while (*p < end && i < (int)arg_len - 1) {
		if (get_user(c, (const char __user *)*p))
			return false;
		(*p)++;
		if (!c)
			break;
		arg[i++] = c;
	}
	arg[i] = '\0';

	/* If the argument was truncated, consume it so the next iteration
	 * starts at the next argv entry. */
	while (*p < end && c) {
		if (get_user(c, (const char __user *)*p))
			return false;
		(*p)++;
	}

	return true;
}

static bool zp_parse_zygote_args(struct mm_struct *mm, char *socket_name,
				 size_t socket_name_len)
{
	unsigned long p, end;
	char arg[96];
	bool found = false;
	int argc = 0;

	if (!mm)
		return false;
	if (socket_name_len)
		socket_name[0] = '\0';
	p = READ_ONCE(mm->arg_start);
	end = READ_ONCE(mm->arg_end);
	if (!p || end <= p)
		return false;

	while (p < end && argc++ < 64) {
		static const char socket_prefix[] = "--socket-name=";

		if (!zp_next_arg(&p, end, arg, sizeof(arg)))
			return false;
		if (!strcmp(arg, "-Xzygote"))
			found = true;
		else if (!strncmp(arg, socket_prefix,
				  sizeof(socket_prefix) - 1))
			zp_copy_name(socket_name, socket_name_len,
				     arg + sizeof(socket_prefix) - 1);
	}

	if (found && socket_name_len && socket_name[0] == '\0')
		zp_copy_name(socket_name, socket_name_len, "zygote");
	return found;
}

#define ZP_LOADER64_NAME "libyukilinker64.so"
#define ZP_LOADER32_NAME "libyukilinker32.so"
#define ZP_CORE64_NAME "libzygisk64.so"
#define ZP_CORE32_NAME "libzygisk32.so"
#define ZP_NATIVE_CORE64_NAME "libyukizncore64.so"
#define ZP_NATIVE_CORE32_NAME "libyukizncore32.so"
#define ZP_RUNTIME_DIR "/data/adb/ksu/lib/yukizygisk/"
#define ZP_LOADER64_PATH ZP_RUNTIME_DIR ZP_LOADER64_NAME
#define ZP_LOADER32_PATH ZP_RUNTIME_DIR ZP_LOADER32_NAME
#define ZP_CORE64_PATH ZP_RUNTIME_DIR ZP_CORE64_NAME
#define ZP_CORE32_PATH ZP_RUNTIME_DIR ZP_CORE32_NAME
#define ZP_NATIVE_CORE64_PATH ZP_RUNTIME_DIR ZP_NATIVE_CORE64_NAME
#define ZP_NATIVE_CORE32_PATH ZP_RUNTIME_DIR ZP_NATIVE_CORE32_NAME
#define ZP_SYSTEM_LINKER64 "/system/bin/linker64"
#define ZP_SYSTEM_LINKER32 "/system/bin/linker"
#define ZP_EARLY_MANIFEST_WATCHDOG                                             \
	"/metadata/watchdog/ksu/yukizygisk/native_snapshot.bin"
#define ZP_EARLY_MANIFEST_DEFAULT "/metadata/ksu/yukizygisk/native_snapshot.bin"
#define ZP_EARLY_LOADER64_WATCHDOG                                             \
	"/metadata/watchdog/ksu/yukizygisk/libyukilinker64.so"
#define ZP_EARLY_LOADER64_DEFAULT "/metadata/ksu/yukizygisk/libyukilinker64.so"
#define ZP_EARLY_LOADER32_WATCHDOG                                             \
	"/metadata/watchdog/ksu/yukizygisk/libyukilinker32.so"
#define ZP_EARLY_LOADER32_DEFAULT "/metadata/ksu/yukizygisk/libyukilinker32.so"
#define ZP_EARLY_NATIVE_CORE64_WATCHDOG                                        \
	"/metadata/watchdog/ksu/yukizygisk/libyukizncore64.so"
#define ZP_EARLY_NATIVE_CORE64_DEFAULT                                         \
	"/metadata/ksu/yukizygisk/libyukizncore64.so"
#define ZP_EARLY_NATIVE_CORE32_WATCHDOG                                        \
	"/metadata/watchdog/ksu/yukizygisk/libyukizncore32.so"
#define ZP_EARLY_NATIVE_CORE32_DEFAULT                                         \
	"/metadata/ksu/yukizygisk/libyukizncore32.so"
#define ZP_VMA_NAME "memfd:"
#define ZP_VMA_NAME_LEN sizeof(ZP_VMA_NAME)
#define ZP_LOADER_MAX_SZ (8u << 20) /* sanity cap on a payload image */
#define ZP_DLEXT_USE_LIBRARY_FD 0x10 /* android_dlextinfo.flags bit */
#define ZP_DLEXT_FORCE_LOAD 0x40

/* bionic android_dlextinfo, LP64 subset. */
struct zp_dlextinfo {
	__u64 flags;
	__u64 reserved_addr;
	__u64 reserved_size;
	__s32 relro_fd;
	__s32 library_fd;
	__s64 library_fd_offset;
	__u64 library_namespace;
};

/* bionic android_dlextinfo, ARM EABI subset. */
struct zp_compat_dlextinfo {
	__u64 flags;
	__u32 reserved_addr;
	__u32 reserved_size;
	__s32 relro_fd;
	__s32 library_fd;
	__s64 library_fd_offset;
	__u32 library_namespace;
};
static_assert(offsetof(struct zp_compat_dlextinfo, library_fd) == 20);
static_assert(sizeof(struct zp_compat_dlextinfo) == 40);

static struct file *zp_open_first(const char *primary, const char *fallback,
				  const char **chosen_path)
{
	struct file *file;
	const struct cred *old_cred;

	old_cred = ksu_cred ? override_creds(ksu_cred) : NULL;
	file = filp_open(primary, O_RDONLY, 0);
	if (IS_ERR(file)) {
		file = filp_open(fallback, O_RDONLY, 0);
		if (!IS_ERR(file) && chosen_path)
			*chosen_path = fallback;
	} else if (chosen_path) {
		*chosen_path = primary;
	}
	if (old_cred)
		revert_creds(old_cred);
	return file;
}

static bool zp_read_exact_file(struct file *file, void *buf, size_t size,
			       loff_t *pos)
{
	ssize_t got = kernel_read(file, buf, size, pos);

	return got == (ssize_t)size;
}

enum zp_file_size_check {
	ZP_FILE_SIZE_MATCH = 0,
	ZP_FILE_SIZE_MISMATCH,
	ZP_FILE_SIZE_UNAVAILABLE,
};

static enum zp_file_size_check
zp_check_file_size(const char *path, u64 want_size, u64 *actual, long *open_err)
{
	const struct cred *old_cred;
	struct file *file;
	u64 size;

	if (actual)
		*actual = 0;
	if (open_err)
		*open_err = 0;
	if (!want_size)
		return ZP_FILE_SIZE_MISMATCH;

	old_cred = ksu_cred ? override_creds(ksu_cred) : NULL;
	file = filp_open(path, O_RDONLY, 0);
	if (old_cred)
		revert_creds(old_cred);
	if (IS_ERR(file)) {
		if (open_err)
			*open_err = PTR_ERR(file);
		return ZP_FILE_SIZE_UNAVAILABLE;
	}

	size = i_size_read(file_inode(file));
	filp_close(file, NULL);
	if (actual)
		*actual = size;
	return size == want_size ? ZP_FILE_SIZE_MATCH : ZP_FILE_SIZE_MISMATCH;
}

static bool zp_early_entry_valid(struct yz_early_native_entry *entry)
{
	entry->module_id[YZ_NATIVE_MODULE_ID_MAX - 1] = '\0';
	entry->target[YZ_NATIVE_TARGET_VALUE_MAX - 1] = '\0';
	entry->lib_path[YZ_NATIVE_MODULE_PATH_MAX - 1] = '\0';
	if (entry->target_type != YZ_NATIVE_TARGET_NAME &&
	    entry->target_type != YZ_NATIVE_TARGET_PATH)
		return false;
	if (!(entry->flags &
	      (YZ_EARLY_NATIVE_ENTRY_ABI32 | YZ_EARLY_NATIVE_ENTRY_ABI64)))
		return false;
	if (entry->module_id[0] == '\0' || entry->target[0] == '\0' ||
	    entry->lib_path[0] == '\0')
		return false;
	return true;
}

static void zp_load_early_native_locked(void)
{
	struct yz_early_native_snapshot_header hdr;
	struct file *file;
	const char *path = NULL;
	loff_t pos = 0;
	enum zp_file_size_check linker_size_check = ZP_FILE_SIZE_MISMATCH;
	enum zp_file_size_check linker32_size_check = ZP_FILE_SIZE_MISMATCH;
	u64 linker_actual_size = 0;
	u64 linker32_actual_size = 0;
	long linker_open_err = 0;
	long linker32_open_err = 0;
	bool invalid;
	u32 i;

	if (zp_early_native_loaded)
		return;
	zp_early_native_enabled = false;
	zp_early_native_watchdog = false;
	zp_early_native_count = 0;
	zp_early_dlopen_off = 0;
	zp_early_dlsym_off = 0;
	zp_early_dlopen32_off = 0;
	zp_early_dlsym32_off = 0;

	file = zp_open_first(ZP_EARLY_MANIFEST_WATCHDOG,
			     ZP_EARLY_MANIFEST_DEFAULT, &path);
	if (IS_ERR(file)) {
		if (!zp_early_native_retry_deadline)
			zp_early_native_retry_deadline =
			    jiffies + ZP_EARLY_NATIVE_RETRY_WINDOW;
		if (time_after(jiffies, zp_early_native_retry_deadline)) {
			zp_early_native_loaded = true;
			if (!zp_early_native_missing_logged) {
				zp_early_native_missing_logged = true;
				pr_info(
				    "zygote_probe: early native snapshot not "
				    "found within retry window, disabled for "
				    "this boot\n");
			}
		}
		return;
	}

	zp_early_native_loaded = true;

	if (!zp_read_exact_file(file, &hdr, sizeof(hdr), &pos)) {
		pr_info(
		    "zygote_probe: early native snapshot header read failed "
		    "from %s\n",
		    path ?: "(unknown)");
		goto out;
	}
	invalid =
	    hdr.magic != YZ_EARLY_NATIVE_MAGIC ||
	    hdr.version != YZ_EARLY_NATIVE_VERSION ||
	    hdr.header_size != sizeof(hdr) ||
	    hdr.entry_size != sizeof(struct yz_early_native_entry) ||
	    hdr.count > YZ_NATIVE_TARGET_MAX ||
	    !(hdr.flags & YZ_EARLY_NATIVE_FLAG_ENABLED) ||
	    (hdr.count && !(hdr.flags & (YZ_EARLY_NATIVE_FLAG_ABI32 |
					 YZ_EARLY_NATIVE_FLAG_ABI64))) ||
	    ((hdr.flags & YZ_EARLY_NATIVE_FLAG_ABI64) &&
	     (!hdr.dlopen_offset || !hdr.dlsym_offset || !hdr.linker_size)) ||
	    ((hdr.flags & YZ_EARLY_NATIVE_FLAG_ABI32) &&
	     (!hdr.dlopen32_offset || !hdr.dlsym32_offset ||
	      !hdr.linker32_size));
	if (!invalid && (hdr.flags & YZ_EARLY_NATIVE_FLAG_ABI64)) {
		linker_size_check =
		    zp_check_file_size(ZP_SYSTEM_LINKER64, hdr.linker_size,
				       &linker_actual_size, &linker_open_err);
		invalid = linker_size_check == ZP_FILE_SIZE_MISMATCH;
	}
	if (!invalid && (hdr.flags & YZ_EARLY_NATIVE_FLAG_ABI32)) {
		linker32_size_check = zp_check_file_size(
		    ZP_SYSTEM_LINKER32, hdr.linker32_size,
		    &linker32_actual_size, &linker32_open_err);
		invalid = linker32_size_check == ZP_FILE_SIZE_MISMATCH;
	}
	if (invalid) {
		pr_info("zygote_probe: early native snapshot invalid %s "
			"magic=0x%x ver=%u h=%u/%zu e=%u/%zu flags=0x%x "
			"count=%u dlopen=0x%llx dlsym=0x%llx "
			"linker_size=%llu actual=%llu err=%ld "
			"dlopen32=0x%llx dlsym32=0x%llx "
			"linker32_size=%llu actual32=%llu err32=%ld\n",
			path ?: "(unknown)", hdr.magic, hdr.version,
			hdr.header_size, sizeof(hdr), hdr.entry_size,
			sizeof(struct yz_early_native_entry), hdr.flags,
			hdr.count, hdr.dlopen_offset, hdr.dlsym_offset,
			hdr.linker_size, linker_actual_size, linker_open_err,
			hdr.dlopen32_offset, hdr.dlsym32_offset,
			hdr.linker32_size, linker32_actual_size,
			linker32_open_err);
		goto out;
	}
	if (linker_size_check == ZP_FILE_SIZE_UNAVAILABLE)
		pr_info("zygote_probe: early native linker size unavailable "
			"%s want=%llu err=%ld, using snapshot\n",
			ZP_SYSTEM_LINKER64, hdr.linker_size, linker_open_err);
	if (linker32_size_check == ZP_FILE_SIZE_UNAVAILABLE)
		pr_info("zygote_probe: early native compat linker size "
			"unavailable %s want=%llu err=%ld, using snapshot\n",
			ZP_SYSTEM_LINKER32, hdr.linker32_size,
			linker32_open_err);

	for (i = 0; i < hdr.count; i++) {
		struct yz_early_native_entry entry;

		if (!zp_read_exact_file(file, &entry, sizeof(entry), &pos))
			break;
		if (!zp_early_entry_valid(&entry))
			continue;
		zp_early_native_entries[zp_early_native_count++] = entry;
	}

	zp_early_dlopen_off = hdr.dlopen_offset;
	zp_early_dlsym_off = hdr.dlsym_offset;
	zp_early_dlopen32_off = hdr.dlopen32_offset;
	zp_early_dlsym32_off = hdr.dlsym32_offset;
	zp_early_native_watchdog =
	    path && !strcmp(path, ZP_EARLY_MANIFEST_WATCHDOG);
	zp_early_native_enabled = zp_early_native_count > 0;
	if (zp_early_native_enabled)
		pr_info("zygote_probe: early native snapshot %s count=%u "
			"dlopen=0x%llx dlsym=0x%llx dlopen32=0x%llx "
			"dlsym32=0x%llx\n",
			path ?: "(unknown)", zp_early_native_count,
			zp_early_dlopen_off, zp_early_dlsym_off,
			zp_early_dlopen32_off, zp_early_dlsym32_off);
out:
	filp_close(file, NULL);
}

static bool zp_early_native_active(void)
{
	bool active;

	mutex_lock(&zp_early_native_lock);
	zp_load_early_native_locked();
	active = zp_early_native_enabled;
	mutex_unlock(&zp_early_native_lock);
	return active;
}

static bool zp_match_early_native_target(const char *filename, char *label,
					 size_t label_len, u8 *target_type)
{
	const char *base = zp_basename(filename);
	bool matched = false;
	u32 i;

	if (!filename || !base)
		return false;

	mutex_lock(&zp_early_native_lock);
	zp_load_early_native_locked();
	if (!zp_early_native_enabled)
		goto out;

	for (i = 0; i < zp_early_native_count; i++) {
		struct yz_early_native_entry *entry =
		    &zp_early_native_entries[i];

		if (entry->target_type == YZ_NATIVE_TARGET_NAME) {
			if (strcmp(base, entry->target))
				continue;
		} else if (entry->target_type == YZ_NATIVE_TARGET_PATH) {
			if (strcmp(filename, entry->target))
				continue;
		} else {
			continue;
		}

		if (!zp_dlopen_off)
			zp_dlopen_off = zp_early_dlopen_off;
		if (!zp_dlsym_off)
			zp_dlsym_off = zp_early_dlsym_off;
		if (!zp_dlopen32_off)
			zp_dlopen32_off = zp_early_dlopen32_off;
		if (!zp_dlsym32_off)
			zp_dlsym32_off = zp_early_dlsym32_off;
		zp_copy_name(label, label_len, entry->target);
		if (target_type)
			*target_type = entry->target_type;
		matched = true;
		break;
	}
out:
	mutex_unlock(&zp_early_native_lock);
	return matched;
}

static const char *zp_early_loader_path(bool compat)
{
	if (compat)
		return zp_early_native_watchdog ? ZP_EARLY_LOADER32_WATCHDOG
						: ZP_EARLY_LOADER32_DEFAULT;
	return zp_early_native_watchdog ? ZP_EARLY_LOADER64_WATCHDOG
					: ZP_EARLY_LOADER64_DEFAULT;
}

static const char *zp_early_native_core_path(bool compat)
{
	if (compat)
		return zp_early_native_watchdog
			   ? ZP_EARLY_NATIVE_CORE32_WATCHDOG
			   : ZP_EARLY_NATIVE_CORE32_DEFAULT;
	return zp_early_native_watchdog ? ZP_EARLY_NATIVE_CORE64_WATCHDOG
					: ZP_EARLY_NATIVE_CORE64_DEFAULT;
}

static void zp_close_current_fd(int fd)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
	ksys_close(fd);
#else
	close_fd(fd);
#endif // #if LINUX_VERSION_CODE < KERNEL_VERSION...
}

static void zp_cache_name(char *buf, size_t len)
{
	size_t i;

	if (!len)
		return;
	for (i = 0; i + 1 < len && i < sizeof(ZP_VMA_NAME) - 1; i++)
		buf[i] = ZP_VMA_NAME[i];
	buf[i] = '\0';
}

/* Stage a private shmem payload fd in current. */
static int zp_stage_fd(const char *path, const char *name,
		       struct ksu_file_load_policy *policy_state)
{
	const struct cred *old_cred;
	struct file *src, *mfd;
	void *buf;
	loff_t sz, pos;
	ssize_t r;
	int fd;

	/* Read payload as ksu. */
	old_cred = ksu_cred ? override_creds(ksu_cred) : NULL;

	src = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(src)) {
		if (old_cred)
			revert_creds(old_cred);
		pr_info("zygote_probe: [2c-3b] open %s failed: %ld\n", path,
			PTR_ERR(src));
		return -ENOENT;
	}
	if (!S_ISREG(file_inode(src)->i_mode)) {
		filp_close(src, NULL);
		if (old_cred)
			revert_creds(old_cred);
		return -EINVAL;
	}

	sz = i_size_read(file_inode(src));
	if (sz <= 0 || sz > ZP_LOADER_MAX_SZ) {
		filp_close(src, NULL);
		if (old_cred)
			revert_creds(old_cred);
		return -EINVAL;
	}

	buf = kvmalloc(sz, GFP_KERNEL);
	if (!buf) {
		filp_close(src, NULL);
		if (old_cred)
			revert_creds(old_cred);
		return -ENOMEM;
	}
	pos = 0;
	r = kernel_read(src, buf, sz, &pos);

	if (old_cred) {
		revert_creds(old_cred);
		old_cred = NULL;
	}

	if (r != sz) {
		pr_info("zygote_probe: [2c-3b] read %s short: %zd/%lld\n", path,
			r, (long long)sz);
		filp_close(src, NULL);
		kvfree(buf);
		return r < 0 ? (int)r : -EIO;
	}

	if (policy_state) {
		int ret = ksu_file_load_policy_allow_current(src, policy_state);
		if (ret)
			pr_info("zygote_probe: [2c-3b] load policy allow %s "
				"failed: %d\n",
				path, ret);
	}
	filp_close(src, NULL);

	mfd = shmem_file_setup(name, sz, 0);
	if (IS_ERR(mfd)) {
		long err = PTR_ERR(mfd);

		pr_info("zygote_probe: [2c-3b] shmem %s failed: %ld\n", name,
			err);
		if (policy_state)
			zp_restore_native_policy_state(policy_state);
		kvfree(buf);
		return err;
	}
	/* shmem_file_setup lacks FMODE_PREAD/PWRITE by default. */
	mfd->f_mode |= FMODE_PREAD | FMODE_PWRITE | FMODE_LSEEK;
	pos = 0;
	r = kernel_write(mfd, buf, sz, &pos);
	kvfree(buf);
	if (r != sz) {
		pr_info("zygote_probe: [2c-3b] write staged %s short: "
			"%zd/%lld\n",
			path, r, (long long)sz);
		if (policy_state)
			zp_restore_native_policy_state(policy_state);
		fput(mfd);
		return r < 0 ? (int)r : -EIO;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		if (policy_state)
			zp_restore_native_policy_state(policy_state);
		fput(mfd);
		return fd;
	}
	fd_install(fd, mfd); /* consumes the shmem reference */

	pr_info("zygote_probe: [2c-3b] staged %s (%lld bytes) -> fd=%d\n", path,
		(long long)sz, fd);
	return fd;
}

/* Stage a real file-backed payload fd in current. */
static int zp_stage_file_fd(const char *path,
			    struct ksu_file_load_policy *policy_state)
{
	const struct cred *old_cred;
	struct file *file;
	loff_t sz;
	int fd;
	int ret;

	old_cred = ksu_cred ? override_creds(ksu_cred) : NULL;
	file = filp_open(path, O_RDONLY, 0);
	if (old_cred)
		revert_creds(old_cred);
	if (IS_ERR(file)) {
		pr_info("zygote_probe: [2c-3b] open real %s failed: %ld\n",
			path, PTR_ERR(file));
		return PTR_ERR(file);
	}
	if (!S_ISREG(file_inode(file)->i_mode)) {
		filp_close(file, NULL);
		return -EINVAL;
	}

	sz = i_size_read(file_inode(file));
	if (sz <= 0 || sz > ZP_LOADER_MAX_SZ) {
		filp_close(file, NULL);
		return -EINVAL;
	}

	if (policy_state) {
		ret = ksu_file_load_policy_allow_current(file, policy_state);
		if (ret)
			pr_info("zygote_probe: [2c-3b] load policy allow %s "
				"failed: %d\n",
				path, ret);
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		if (policy_state)
			zp_restore_native_policy_state(policy_state);
		filp_close(file, NULL);
		return fd;
	}
	fd_install(fd, file);

	pr_info("zygote_probe: [2c-3b] staged real %s (%lld bytes) -> fd=%d\n",
		path, (long long)sz, fd);
	return fd;
}

struct zp_early_packet_state {
	int packet_fd;
	int module_fds[YZ_NATIVE_TARGET_MAX];
	u32 module_fd_count;
};

static void zp_early_packet_state_init(struct zp_early_packet_state *state)
{
	u32 i;

	state->packet_fd = -1;
	state->module_fd_count = 0;
	for (i = 0; i < YZ_NATIVE_TARGET_MAX; i++)
		state->module_fds[i] = -1;
}

static void zp_close_early_packet_state(struct zp_early_packet_state *state)
{
	u32 i;

	if (!state)
		return;
	if (state->packet_fd >= 0) {
		zp_close_current_fd(state->packet_fd);
		state->packet_fd = -1;
	}
	for (i = 0; i < state->module_fd_count; i++) {
		if (state->module_fds[i] >= 0)
			zp_close_current_fd(state->module_fds[i]);
		state->module_fds[i] = -1;
	}
	state->module_fd_count = 0;
}

static int zp_install_packet_fd(const void *buf, size_t size)
{
	struct file *mfd;
	loff_t pos = 0;
	ssize_t w;
	int fd;

	mfd = shmem_file_setup(ZP_VMA_NAME, size, 0);
	if (IS_ERR(mfd))
		return PTR_ERR(mfd);
	mfd->f_mode |= FMODE_PREAD | FMODE_PWRITE | FMODE_LSEEK;
	w = kernel_write(mfd, buf, size, &pos);
	if (w != (ssize_t)size) {
		fput(mfd);
		return w < 0 ? (int)w : -EIO;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(mfd);
		return fd;
	}
	fd_install(fd, mfd);
	return fd;
}

static int
zp_stage_early_native_packet(u8 target_type, const char *target, bool compat,
			     struct ksu_file_load_policy *policy_state,
			     struct zp_early_packet_state *state)
{
	struct yz_early_native_entry *matches;
	struct yz_early_native_packet_header *hdr;
	struct yz_early_native_packet_entry *entries;
	void *packet;
	size_t packet_size;
	u32 match_count = 0;
	u32 i;
	int ret = 0;

	if (!target || !state)
		return -EINVAL;

	matches = kcalloc(YZ_NATIVE_TARGET_MAX, sizeof(*matches), GFP_KERNEL);
	if (!matches)
		return -ENOMEM;

	mutex_lock(&zp_early_native_lock);
	zp_load_early_native_locked();
	if (!zp_early_native_enabled) {
		mutex_unlock(&zp_early_native_lock);
		ret = -ENOENT;
		goto out_free_matches;
	}
	for (i = 0; i < zp_early_native_count; i++) {
		struct yz_early_native_entry *entry =
		    &zp_early_native_entries[i];

		if (entry->target_type != target_type)
			continue;
		if (strcmp(entry->target, target))
			continue;
		if (compat && !(entry->flags & YZ_EARLY_NATIVE_ENTRY_ABI32))
			continue;
		if (!compat && !(entry->flags & YZ_EARLY_NATIVE_ENTRY_ABI64))
			continue;
		matches[match_count++] = *entry;
	}
	mutex_unlock(&zp_early_native_lock);
	if (!match_count) {
		ret = -ENOENT;
		goto out_free_matches;
	}

	packet_size = sizeof(*hdr) + match_count * sizeof(*entries);
	packet = kvzalloc(packet_size, GFP_KERNEL);
	if (!packet) {
		ret = -ENOMEM;
		goto out_free_matches;
	}

	hdr = packet;
	entries = (struct yz_early_native_packet_entry *)(hdr + 1);
	hdr->magic = YZ_EARLY_NATIVE_PACKET_MAGIC;
	hdr->version = YZ_EARLY_NATIVE_VERSION;
	hdr->header_size = sizeof(*hdr);
	hdr->entry_size = sizeof(*entries);

	for (i = 0; i < match_count; i++) {
		int fd =
		    zp_stage_fd(matches[i].lib_path, ZP_VMA_NAME, policy_state);

		if (fd < 0) {
			pr_info(
			    "zygote_probe: early native stage %s failed: %d\n",
			    matches[i].lib_path, fd);
			continue;
		}
		state->module_fds[state->module_fd_count++] = fd;
		entries[hdr->count].module = matches[i];
		entries[hdr->count].fd = fd;
		hdr->count++;
	}
	if (!hdr->count) {
		kvfree(packet);
		zp_close_early_packet_state(state);
		ret = -ENOENT;
		goto out_free_matches;
	}

	packet_size = sizeof(*hdr) + hdr->count * sizeof(*entries);
	match_count = hdr->count;
	ret = zp_install_packet_fd(packet, packet_size);
	kvfree(packet);
	if (ret < 0) {
		zp_close_early_packet_state(state);
		goto out_free_matches;
	}
	state->packet_fd = ret;
	pr_info(
	    "zygote_probe: early native packet target=%s modules=%u fd=%d\n",
	    target, match_count, state->packet_fd);
	ret = 0;

out_free_matches:
	kfree(matches);
	return ret;
}

enum zp_inject_kind {
	ZP_INJECT_ZYGOTE = 1,
	ZP_INJECT_NATIVE = 2,
};

struct zp_inject_tw {
	struct callback_head cb;
	enum zp_inject_kind kind;
	u8 native_target_type;
	bool early_native;
	char label[64];
};

static int zp_find_stack_at_entry(struct pt_regs *regs, bool compat,
				  unsigned long *entry_addr,
				  unsigned long *entry_value)
{
	unsigned long p = user_stack_pointer(regs);
	unsigned long word;
	int argc;

#ifdef CONFIG_COMPAT
	if (compat) {
		compat_ulong_t cword;

		if (get_user(cword, (compat_ulong_t __user *)p))
			return -EFAULT;
		argc = (int)cword;
		p += sizeof(cword);
		p += (unsigned long)(argc + 1) * sizeof(cword);
		for (;;) {
			if (get_user(cword, (compat_ulong_t __user *)p))
				return -EFAULT;
			p += sizeof(cword);
			if (!cword)
				break;
		}
		for (;;) {
			compat_ulong_t cval;

			if (get_user(cword, (compat_ulong_t __user *)p) ||
			    get_user(
				cval,
				(compat_ulong_t __user *)(p + sizeof(cword))))
				return -EFAULT;
			if (cword == AT_NULL)
				return -ENOENT;
			if (cword == AT_ENTRY) {
				*entry_addr = p + sizeof(cword);
				*entry_value = cval;
				return 0;
			}
			p += 2 * sizeof(cword);
		}
	}
#else
	(void)compat;
#endif // #ifdef CONFIG_COMPAT

	if (get_user(word, (unsigned long __user *)p))
		return -EFAULT;
	argc = (int)word;
	p += sizeof(word);
	p += (unsigned long)(argc + 1) * sizeof(word);
	for (;;) {
		if (get_user(word, (unsigned long __user *)p))
			return -EFAULT;
		p += sizeof(word);
		if (!word)
			break;
	}
	for (;;) {
		unsigned long val;

		if (get_user(word, (unsigned long __user *)p) ||
		    get_user(val, (unsigned long __user *)(p + sizeof(word))))
			return -EFAULT;
		if (word == AT_NULL)
			return -ENOENT;
		if (word == AT_ENTRY) {
			*entry_addr = p + sizeof(word);
			*entry_value = val;
			return 0;
		}
		p += 2 * sizeof(word);
	}
}

static int zp_write_stack_at_entry(unsigned long addr, unsigned long value,
				   bool compat)
{
#ifdef CONFIG_COMPAT
	if (compat)
		return put_user((compat_ulong_t)value,
				(compat_ulong_t __user *)addr);
#else
	(void)compat;
#endif // #ifdef CONFIG_COMPAT
	return put_user(value, (unsigned long __user *)addr);
}

static int zp_read_stack_at_entry(unsigned long addr, unsigned long *value,
				  bool compat)
{
#ifdef CONFIG_COMPAT
	if (compat) {
		compat_ulong_t cvalue;
		int ret = get_user(cvalue, (compat_ulong_t __user *)addr);

		*value = cvalue;
		return ret;
	}
#else
	(void)compat;
#endif // #ifdef CONFIG_COMPAT
	return get_user(*value, (unsigned long __user *)addr);
}

static void zp_read_saved_auxv(struct mm_struct *mm, bool compat,
			       unsigned long *entry, unsigned long *base)
{
	size_t k;

	*entry = 0;
	*base = 0;
#ifdef CONFIG_COMPAT
	if (compat) {
		const compat_ulong_t *auxv =
		    (const compat_ulong_t *)mm->saved_auxv;
		const size_t auxv_bytes = sizeof(mm->saved_auxv);
		const size_t words = auxv_bytes / sizeof(*auxv);

		for (k = 0; k + 1 < words; k += 2) {
			compat_ulong_t type = auxv[k];

			if (type == AT_NULL)
				break;
			if (type == AT_ENTRY)
				*entry = auxv[k + 1];
			else if (type == AT_BASE)
				*base = auxv[k + 1];
		}
		return;
	}
#else
	(void)compat;
#endif

	for (k = 0; k + 1 < AT_VECTOR_SIZE; k += 2) {
		unsigned long type = mm->saved_auxv[k];

		if (type == AT_NULL)
			break;
		if (type == AT_ENTRY)
			*entry = mm->saved_auxv[k + 1];
		else if (type == AT_BASE)
			*base = mm->saved_auxv[k + 1];
	}
}

/* AT_ENTRY rewrite task_work. */
static void zp_inject_tw_func(struct callback_head *cb)
{
	struct zp_inject_tw *tw = container_of(cb, struct zp_inject_tw, cb);
	struct mm_struct *mm = current->mm;
	struct pt_regs *uregs;
	unsigned long saved = 0, at_entry_uaddr = 0, at_entry_uval = 0;
	unsigned long at_base = 0;
	u64 dlopen_off, dlsym_off;
	char socket_name[64];
	bool native = tw->kind == ZP_INJECT_NATIVE;
	bool compat = false;

	if (!mm)
		goto out;
	if (native) {
		zp_copy_name(socket_name, sizeof(socket_name),
			     tw->label[0] ? tw->label : "native");
		if (zp_safemode_is_active()) {
			pr_info("zygote_probe: safemode active, skip native "
				"pid=%d target=%s\n",
				current->pid, socket_name);
			goto out;
		}
	} else {
		if (!zp_parse_zygote_args(mm, socket_name, sizeof(socket_name)))
			goto out;
	}

#ifdef CONFIG_COMPAT
	compat = is_compat_task();
#endif // #ifdef CONFIG_COMPAT
	dlopen_off = compat ? zp_dlopen32_off : zp_dlopen_off;
	dlsym_off = compat ? zp_dlsym32_off : zp_dlsym_off;

	if (!native && zp_zygote_safemode_should_skip(socket_name))
		goto out;

	zp_read_saved_auxv(mm, compat, &saved, &at_base);

	uregs = task_pt_regs(current);
	if (zp_find_stack_at_entry(uregs, compat, &at_entry_uaddr,
				   &at_entry_uval))
		goto out;

	pr_info("zygote_probe: [1a] pid=%d socket=%s AT_ENTRY saved=0x%lx "
		"stack@0x%lx "
		"val=0x%lx %s\n",
		current->pid, socket_name, saved, at_entry_uaddr, at_entry_uval,
		(at_entry_uaddr && at_entry_uval == saved) ? "MATCH"
							   : "MISMATCH");

	if (at_base && dlopen_off)
		pr_info("zygote_probe: [2c-2] pid=%d socket=%s AT_BASE=0x%lx "
			"off=0x%llx -> "
			"dlopen=0x%llx\n",
			current->pid, socket_name, at_base, dlopen_off,
			(u64)at_base + dlopen_off);

	if (at_entry_uaddr && at_entry_uval == saved) {
		unsigned long check = ~saved;
		int werr =
		    zp_write_stack_at_entry(at_entry_uaddr, saved, compat);
		int rerr =
		    zp_read_stack_at_entry(at_entry_uaddr, &check, compat);

		pr_info("zygote_probe: [1b] pid=%d socket=%s wrote "
			"AT_ENTRY@0x%lx=0x%lx "
			"(put=%d get=%d readback=0x%lx) %s\n",
			current->pid, socket_name, at_entry_uaddr, saved, werr,
			rerr, check,
			(!werr && !rerr && check == saved) ? "WRITE-OK"
							   : "WRITE-FAIL");
	}

	/* Redirect only after the stub is staged. */
	if ((yukizygisk_enabled || (native && tw->early_native)) &&
	    at_entry_uaddr && at_entry_uval == saved && saved) {
		/* Native-ABI AT_ENTRY stub. */
		static const u32 tmpl[] = {
		    0x10000013, 0xd10103ff, 0xd2800014, 0xf2a00014, 0xf2c00014,
		    0xf2e00014, 0xd2800015, 0xf2a00015, 0xf2c00015, 0xf2e00015,
		    0xd2800017, 0xf2a00017, 0xf2c00017, 0xf2e00017, 0xf90003f3,
		    0xf90007f4, 0xf9000bf7, 0xf9000fe0, 0x5289c430, 0x72aa4830,
		    0xb9080270, 0x91300260, 0xd2800041, 0x91280262, 0xaa1403e3,
		    0xd63f02a0, 0xf94003f3, 0xf9040660, 0xf90013e0, 0xb94a1e60,
		    0xd2800728, 0xd4000001, 0xf94003f3, 0xf94013e0, 0xb40000c0,
		    0x91340261, 0xf94007e2, 0xf9400bf7, 0xd63f02e0, 0xb50000a0,
		    0xd2800000, 0xd2800728, 0xd4000001, 0x14000005, 0xaa0003f9,
		    0xd2800000, 0xd2800001, 0xd63f0320, 0xf9400fe0, 0xf94007f4,
		    0x910103ff, 0xaa1403f0, 0xd61f0200,
		};
		static const u8 compat_tmpl[] = {
		    0x2d, 0xe9, 0xf7, 0x43, 0xf8, 0x46, 0xa8, 0xf1, 0x08, 0x08,
		    0x11, 0x4c, 0x11, 0x4d, 0x12, 0x4e, 0x08, 0xf6, 0x00, 0x40,
		    0x02, 0x21, 0x08, 0xf6, 0x00, 0x22, 0x23, 0x46, 0xa8, 0x47,
		    0x81, 0x46, 0x0e, 0x48, 0x06, 0x27, 0x00, 0xdf, 0x48, 0x46,
		    0x48, 0xb1, 0x08, 0xf6, 0x00, 0x51, 0x22, 0x46, 0xb0, 0x47,
		    0x20, 0xb1, 0x03, 0x46, 0x0a, 0x48, 0x0a, 0x49, 0x98, 0x47,
		    0x04, 0xe0, 0x08, 0x48, 0x00, 0x28, 0x01, 0xdb, 0x06, 0x27,
		    0x00, 0xdf, 0xa4, 0x46, 0xbd, 0xe8, 0xf7, 0x43, 0x60, 0x47,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00,
		};
		static_assert(sizeof(compat_tmpl) == 0x68);
		u32 code[ARRAY_SIZE(tmpl)];
		u8 compat_code[ARRAY_SIZE(compat_tmpl)];
		struct zp_dlextinfo extinfo;
		struct zp_compat_dlextinfo compat_extinfo;
		struct ksu_file_load_policy native_policy = {};
		struct zp_early_packet_state early_packet;
		unsigned long stub, dlopen_addr, dlsym_addr;
		unsigned long redirected_entry;
		int loader_fd, core_fd, stub_core_fd;
		int early_packet_arg, werr;
		bool copy_failed, yuki;
		const char *lib_str, *entry_str;
		const char *loader_path, *core_path;
		size_t lib_len, entry_len;
		char loader_name[ZP_VMA_NAME_LEN], core_name[ZP_VMA_NAME_LEN];

		zp_early_packet_state_init(&early_packet);
		if (!at_base || !dlopen_off || !dlsym_off) {
			pr_info("zygote_probe: [2c-3b] pid=%d socket=%s no "
				"dlopen/dlsym addr yet, skipping\n",
				current->pid, socket_name);
			goto out;
		}
		dlopen_addr = at_base + dlopen_off;
		dlsym_addr = at_base + dlsym_off;

		/* Stage loader/core fds in the target. */
		yuki = native || zp_yukilinker_enabled;
		loader_path =
		    native && tw->early_native
			? zp_early_loader_path(compat)
			: (compat ? ZP_LOADER32_PATH : ZP_LOADER64_PATH);
		if (native)
			core_path = tw->early_native
					? zp_early_native_core_path(compat)
					: (compat ? ZP_NATIVE_CORE32_PATH
						  : ZP_NATIVE_CORE64_PATH);
		else
			core_path = compat ? ZP_CORE32_PATH : ZP_CORE64_PATH;
		zp_cache_name(loader_name, sizeof(loader_name));
		zp_cache_name(core_name, sizeof(core_name));
		if (yuki)
			loader_fd = zp_stage_fd(loader_path, loader_name,
						&native_policy);
		else if (native)
			loader_fd = zp_stage_file_fd(core_path, &native_policy);
		else
			loader_fd =
			    zp_stage_fd(core_path, core_name, &native_policy);
		if (loader_fd < 0) {
			pr_info("zygote_probe: [2c-3b] pid=%d socket=%s stage "
				"loader "
				"failed: %d, skipping\n",
				current->pid, socket_name, loader_fd);
			goto out;
		}
		if (yuki) {
			core_fd = zp_stage_fd(core_path, core_name, NULL);
		} else {
			core_fd = loader_fd; /* dlopen the core directly */
		}
		if (yuki && core_fd < 0) {
			pr_info("zygote_probe: [2c-3b] pid=%d socket=%s stage "
				"core failed: %d, skipping\n",
				current->pid, socket_name, core_fd);
			zp_close_current_fd(loader_fd);
			zp_restore_native_policy_state(&native_policy);
			goto out;
		}

		early_packet_arg = 0;
		if (native && tw->early_native) {
			int ret = zp_stage_early_native_packet(
			    tw->native_target_type, tw->label, compat,
			    &native_policy, &early_packet);

			if (ret < 0 || early_packet.packet_fd < 0 ||
			    early_packet.packet_fd >= 0xffff) {
				pr_info(
				    "zygote_probe: [2c-3b] pid=%d socket=%s "
				    "early packet failed: %d\n",
				    current->pid, socket_name, ret);
				zp_close_early_packet_state(&early_packet);
				zp_close_current_fd(loader_fd);
				if (yuki)
					zp_close_current_fd(core_fd);
				zp_restore_native_policy_state(&native_policy);
				goto out;
			}
			early_packet_arg = early_packet.packet_fd + 1;
		}
		{
			int ret = ksu_file_load_policy_allow_execmem_current(
			    &native_policy);

			if (ret < 0) {
				pr_info("zygote_probe: [2c-3b] pid=%d "
					"socket=%s execmem policy failed: %d\n",
					current->pid, socket_name, ret);
				zp_close_current_fd(loader_fd);
				if (yuki)
					zp_close_current_fd(core_fd);
				zp_close_early_packet_state(&early_packet);
				zp_restore_native_policy_state(&native_policy);
				goto out;
			}
		}

		stub = vm_mmap(NULL, 0, PAGE_SIZE,
			       PROT_READ | PROT_WRITE | PROT_EXEC,
			       MAP_PRIVATE | MAP_ANONYMOUS, 0);
		if (IS_ERR_VALUE(stub)) {
			pr_info("zygote_probe: [2c-3b] pid=%d socket=%s "
				"vm_mmap failed: %ld\n",
				current->pid, socket_name, (long)stub);
			zp_close_current_fd(loader_fd);
			if (yuki)
				zp_close_current_fd(core_fd);
			zp_close_early_packet_state(&early_packet);
			zp_restore_native_policy_state(&native_policy);
			goto out;
		}

		memcpy(code, tmpl, sizeof(code));
		zp_patch_imm64(&code[2], saved); /* x20 = real entry */
		zp_patch_imm64(&code[6], dlopen_addr); /* x21 = dlopen */
		zp_patch_imm64(&code[10], dlsym_addr); /* x23 = dlsym */
		/* core fd argument */
		stub_core_fd = yuki ? core_fd : -1;
		code[40] = 0xd2800000u | (((u32)stub_core_fd & 0xffff) << 5);
		code[45] = 0xd2800000u | (((u32)stub_core_fd & 0xffff) << 5);
		code[46] =
		    0xd2800001u | (((u32)early_packet_arg & 0xffff) << 5);
		memcpy(compat_code, compat_tmpl, sizeof(compat_code));
		{
			u32 value = (u32)saved;

			memcpy(&compat_code[0x50], &value, sizeof(value));
			value = (u32)dlopen_addr;
			memcpy(&compat_code[0x54], &value, sizeof(value));
			value = (u32)dlsym_addr;
			memcpy(&compat_code[0x58], &value, sizeof(value));
			value = (u32)loader_fd;
			memcpy(&compat_code[0x5c], &value, sizeof(value));
			value = (u32)stub_core_fd;
			memcpy(&compat_code[0x60], &value, sizeof(value));
			value = (u32)early_packet_arg;
			memcpy(&compat_code[0x64], &value, sizeof(value));
		}

		/* Choose first-stage entry. */
		if (yuki) {
			lib_str = compat ? ZP_LOADER32_NAME : ZP_LOADER64_NAME;
			lib_len = compat ? sizeof(ZP_LOADER32_NAME)
					 : sizeof(ZP_LOADER64_NAME);
			entry_str = "yuki_bootstrap";
			entry_len = sizeof("yuki_bootstrap");
		} else {
			if (native) {
				lib_str = compat ? ZP_NATIVE_CORE32_NAME
						 : ZP_NATIVE_CORE64_NAME;
				lib_len = compat
					      ? sizeof(ZP_NATIVE_CORE32_NAME)
					      : sizeof(ZP_NATIVE_CORE64_NAME);
			} else {
				lib_str =
				    compat ? ZP_CORE32_NAME : ZP_CORE64_NAME;
				lib_len = compat ? sizeof(ZP_CORE32_NAME)
						 : sizeof(ZP_CORE64_NAME);
			}
			entry_str = "zygisk_core_entry_direct";
			entry_len = sizeof("zygisk_core_entry_direct");
		}

		memset(&extinfo, 0, sizeof(extinfo));
		extinfo.flags = ZP_DLEXT_USE_LIBRARY_FD |
				(native ? ZP_DLEXT_FORCE_LOAD : 0);
		extinfo.library_fd = loader_fd;
		memset(&compat_extinfo, 0, sizeof(compat_extinfo));
		compat_extinfo.flags = extinfo.flags;
		compat_extinfo.library_fd = loader_fd;

		if (compat) {
			copy_failed =
			    copy_to_user((void __user *)stub, compat_code,
					 sizeof(compat_code)) ||
			    copy_to_user(
				(void __user *)(stub + ZP_STUB_EXTINFO_OFF),
				&compat_extinfo, sizeof(compat_extinfo));
		} else {
			copy_failed =
			    copy_to_user((void __user *)stub, code,
					 sizeof(code)) ||
			    copy_to_user(
				(void __user *)(stub + ZP_STUB_EXTINFO_OFF),
				&extinfo, sizeof(extinfo));
		}
		if (copy_failed ||
		    copy_to_user((void __user *)(stub + ZP_STUB_STR_OFF),
				 lib_str, lib_len) ||
		    copy_to_user((void __user *)(stub + ZP_STUB_ENTRY_STR_OFF),
				 entry_str, entry_len)) {
			pr_info("zygote_probe: [2c-3b] pid=%d socket=%s "
				"copy_to_user "
				"failed\n",
				current->pid, socket_name);
			vm_munmap(stub, PAGE_SIZE);
			zp_close_current_fd(loader_fd);
			if (yuki)
				zp_close_current_fd(core_fd);
			zp_close_early_packet_state(&early_packet);
			zp_restore_native_policy_state(&native_policy);
			goto out;
		}
		{
			u32 marker = 0x52414e21u;

			if (copy_to_user((void __user *)(stub + 0x800), &marker,
					 sizeof(marker))) {
				vm_munmap(stub, PAGE_SIZE);
				zp_close_current_fd(loader_fd);
				if (yuki)
					zp_close_current_fd(core_fd);
				zp_close_early_packet_state(&early_packet);
				zp_restore_native_policy_state(&native_policy);
				goto out;
			}
		}

		flush_icache_range(
		    stub, stub + (compat ? sizeof(compat_code) : sizeof(code)));

		redirected_entry = compat ? stub | 1UL : stub;
		werr = zp_write_stack_at_entry(at_entry_uaddr, redirected_entry,
					       compat);
		pr_info(
		    "zygote_probe: [2c-3b] pid=%d socket=%s abi=%s stub@0x%lx "
		    "loader_fd=%d "
		    "core_fd=%d dlopen@0x%lx dlsym@0x%lx -> entry 0x%lx %s\n",
		    current->pid, socket_name, compat ? "arm" : "arm64", stub,
		    loader_fd, core_fd, dlopen_addr, dlsym_addr, saved,
		    werr ? "FAIL" : "REDIRECTED");
		if (werr) {
			vm_munmap(stub, PAGE_SIZE);
			zp_close_current_fd(loader_fd);
			if (yuki)
				zp_close_current_fd(core_fd);
			zp_close_early_packet_state(&early_packet);
			zp_restore_native_policy_state(&native_policy);
		} else {
			zp_publish_native_policy_state(current->tgid,
						       &native_policy);
		}
	}
out:
	kfree(tw);
}

static void __nocfi my_bprm_committed_creds(zp_bprm_arg_t *bprm)
{
	const char *filename = bprm ? bprm->filename : NULL;
	char native_label[64] = {};
	u8 native_target_type = 0;
	bool early_native = false;
	bool live_enabled;
	bool early_enabled;
	bool by_sid;
	bool by_path;
	bool by_native;
	bool live_native;

	((bprm_committed_creds_fn)zygote_probe_hook.original)(bprm);
	live_enabled = READ_ONCE(yukizygisk_enabled);
	early_enabled = zp_early_native_active();
	if (unlikely(!live_enabled && !early_enabled))
		return;
	if (unlikely(zp_safemode_is_active()))
		return;

	by_sid = live_enabled && is_zygote(current_cred());
	by_path = live_enabled && zp_is_app_process_path(filename);
	live_native = live_enabled && !by_path &&
		      zp_match_live_native_target(filename, native_label,
						  sizeof(native_label),
						  &native_target_type);
	by_native = live_native && zp_is_init_child();
	if (!by_path && !by_native && early_enabled &&
	    zp_match_early_native_target(filename, native_label,
					 sizeof(native_label),
					 &native_target_type)) {
		by_native = true;
		early_native = true;
	}
	if (unlikely(by_sid || by_path || by_native)) {
		if (by_native)
			pr_info("zygote_probe: native exec pid=%d tgid=%d "
				"comm=%s file=%s target=%s early=%d\n",
				current->pid, current->tgid, current->comm,
				filename ?: "(null)", native_label,
				early_native ? 1 : 0);

		pr_debug("zygote_probe: exec pid=%d tgid=%d comm=%s "
			 "file=%s [sid=%d path=%d native=%d]\n",
			 current->pid, current->tgid, current->comm,
			 filename ?: "(null)", by_sid, by_path, by_native);

		/* Defer auxv rewrite to task_work. */
		if (by_path || by_native) {
			struct zp_inject_tw *tw =
			    kzalloc(sizeof(*tw), GFP_ATOMIC);

			if (tw) {
				tw->kind = by_native ? ZP_INJECT_NATIVE
						     : ZP_INJECT_ZYGOTE;
				if (by_native) {
					tw->native_target_type =
					    native_target_type;
					tw->early_native = early_native;
					zp_copy_name(tw->label,
						     sizeof(tw->label),
						     native_label);
				}
				init_task_work(&tw->cb, zp_inject_tw_func);
				if (task_work_add(current, &tw->cb, TWA_RESUME))
					kfree(tw);
			}
		}
	}
}

void ksu_zygote_probe_init(void)
{
#if ZP_ENABLE_LSM_INJECTOR
	int ret = ksu_register_lsm_hook(&zygote_probe_hook);

	if (ret)
		pr_err("zygote_probe: failed to register bprm hook: %d\n", ret);
	else {
		pr_info("zygote_probe: bprm hook ABI=%s resolver=%s\n",
			ZP_BPRM_HOOK_ABI, ZP_BPRM_HOOK_CFI);
		pr_info("zygote_probe: armed (lazy side effects)\n");
	}
#else
	pr_info("zygote_probe: LSM injector disabled for bootloop isolation\n");
#endif // #if ZP_ENABLE_LSM_INJECTOR

	if (ksu_register_feature_handler(&yukizygisk_feature_handler))
		pr_err("zygote_probe: failed to register YukiZygisk feature\n");
	else
		pr_info("zygote_probe: feature registered\n");
}

void ksu_zygote_probe_exit(void)
{
	zp_cleanup_module_policies();
	ksu_unregister_feature_handler(KSU_FEATURE_YUKIZYGISK);
	WRITE_ONCE(yukizygisk_enabled, false);
#if ZP_ENABLE_LSM_INJECTOR
	ksu_unregister_lsm_hook(&zygote_probe_hook);
#endif // #if ZP_ENABLE_LSM_INJECTOR
}
