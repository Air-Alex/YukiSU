#include <linux/build_bug.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/rwsem.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/utsname.h>
#include <linux/wait.h>

#include "policy/allowlist.h"
#include "extension/uts_view.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "selinux/selinux.h"

static_assert(sizeof(struct ksu_uts_template) == 400,
	      "ksu_uts_template ABI drift");
static_assert(sizeof(struct ksu_uts_view_config) == 816,
	      "ksu_uts_view_config ABI drift");
static_assert(sizeof(struct ksu_uts_view_status) == 832,
	      "ksu_uts_view_status ABI drift");
static_assert(offsetof(struct ksu_uts_view_config, global) == 16,
	      "UTS config ABI drift");
static_assert(offsetof(struct ksu_uts_view_status, original) == 32,
	      "UTS status ABI drift");

static DEFINE_MUTEX(uts_view_lock);

static struct rw_semaphore *uts_sem_ptr;
static struct uts_namespace *init_uts_ns_ptr;

static struct new_utsname boot_original_uts;
static bool boot_original_valid;

static struct ksu_uts_template global_cfg;
static struct ksu_uts_template deny_cfg;

static struct new_utsname global_restore_uts;
static struct new_utsname global_last_applied;
static u32 global_owned_mask;

static u64 uts_view_mode;
static enum ksu_uts_view_source uts_view_source;
static u32 uts_view_status_flags;
static u32 detached_task_count;
static bool runtime_audit_done;
static bool deny_scoped_active;
static bool uts_view_stopping;
static atomic_t uts_view_active_callbacks = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(uts_view_callback_waitq);

#define KSU_UTS_BOOT_PARAM_LEN (KSU_UTS_NAME_LEN * 2 + 4)

static bool uts_boot_global;
static uint uts_boot_mask;
static char uts_boot_sysname[KSU_UTS_BOOT_PARAM_LEN];
static char uts_boot_nodename[KSU_UTS_BOOT_PARAM_LEN];
static char uts_boot_release[KSU_UTS_BOOT_PARAM_LEN];
static char uts_boot_version[KSU_UTS_BOOT_PARAM_LEN];
static char uts_boot_machine[KSU_UTS_BOOT_PARAM_LEN];
static char uts_boot_domainname[KSU_UTS_BOOT_PARAM_LEN];

module_param_named(uts_boot_global, uts_boot_global, bool, 0);
module_param_named(uts_boot_mask, uts_boot_mask, uint, 0);
module_param_string(uts_boot_sysname, uts_boot_sysname,
		    sizeof(uts_boot_sysname), 0);
module_param_string(uts_boot_nodename, uts_boot_nodename,
		    sizeof(uts_boot_nodename), 0);
module_param_string(uts_boot_release, uts_boot_release,
		    sizeof(uts_boot_release), 0);
module_param_string(uts_boot_version, uts_boot_version,
		    sizeof(uts_boot_version), 0);
module_param_string(uts_boot_machine, uts_boot_machine,
		    sizeof(uts_boot_machine), 0);
module_param_string(uts_boot_domainname, uts_boot_domainname,
		    sizeof(uts_boot_domainname), 0);

static bool uts_field_terminated(const char field[KSU_UTS_NAME_LEN])
{
	return memchr(field, '\0', KSU_UTS_NAME_LEN) != NULL;
}

static void normalize_template(struct ksu_uts_template *tmpl)
{
	if (!tmpl)
		return;
	if ((tmpl->field_mask & KSU_UTS_FIELD_SYSNAME) && !tmpl->sysname[0])
		tmpl->field_mask &= ~KSU_UTS_FIELD_SYSNAME;
	if ((tmpl->field_mask & KSU_UTS_FIELD_NODENAME) && !tmpl->nodename[0])
		tmpl->field_mask &= ~KSU_UTS_FIELD_NODENAME;
	if ((tmpl->field_mask & KSU_UTS_FIELD_RELEASE) && !tmpl->release[0])
		tmpl->field_mask &= ~KSU_UTS_FIELD_RELEASE;
	if ((tmpl->field_mask & KSU_UTS_FIELD_VERSION) && !tmpl->version[0])
		tmpl->field_mask &= ~KSU_UTS_FIELD_VERSION;
	if ((tmpl->field_mask & KSU_UTS_FIELD_MACHINE) && !tmpl->machine[0])
		tmpl->field_mask &= ~KSU_UTS_FIELD_MACHINE;
	if ((tmpl->field_mask & KSU_UTS_FIELD_DOMAINNAME) &&
	    !tmpl->domainname[0])
		tmpl->field_mask &= ~KSU_UTS_FIELD_DOMAINNAME;
}

static int validate_template(const struct ksu_uts_template *tmpl)
{
	if (!tmpl || tmpl->reserved)
		return -EINVAL;
	if (tmpl->field_mask & ~KSU_UTS_FIELD_VALID_MASK)
		return -EINVAL;
	if ((tmpl->field_mask & KSU_UTS_FIELD_SYSNAME) &&
	    !uts_field_terminated(tmpl->sysname))
		return -EINVAL;
	if ((tmpl->field_mask & KSU_UTS_FIELD_NODENAME) &&
	    !uts_field_terminated(tmpl->nodename))
		return -EINVAL;
	if ((tmpl->field_mask & KSU_UTS_FIELD_RELEASE) &&
	    !uts_field_terminated(tmpl->release))
		return -EINVAL;
	if ((tmpl->field_mask & KSU_UTS_FIELD_VERSION) &&
	    !uts_field_terminated(tmpl->version))
		return -EINVAL;
	if ((tmpl->field_mask & KSU_UTS_FIELD_MACHINE) &&
	    !uts_field_terminated(tmpl->machine))
		return -EINVAL;
	if ((tmpl->field_mask & KSU_UTS_FIELD_DOMAINNAME) &&
	    !uts_field_terminated(tmpl->domainname))
		return -EINVAL;
	return 0;
}

static int validate_config(const struct ksu_uts_view_config *config)
{
	int ret;

	if (!config || config->version != KSU_UTS_VIEW_ABI_VERSION ||
	    config->size != sizeof(*config) ||
	    (config->mode & ~KSU_UTS_VIEW_MODE_VALID_MASK))
		return -EINVAL;
	if (config->update_mask & ~KSU_UTS_CONFIG_UPDATE_VALID_MASK)
		return -EINVAL;

	ret = validate_template(&config->global);
	if (ret)
		return ret;
	return validate_template(&config->deny);
}

static void uts_to_template(struct ksu_uts_template *dst,
			    const struct new_utsname *src)
{
	memset(dst, 0, sizeof(*dst));
	dst->field_mask = KSU_UTS_FIELD_VALID_MASK;
	strscpy(dst->sysname, src->sysname, sizeof(dst->sysname));
	strscpy(dst->nodename, src->nodename, sizeof(dst->nodename));
	strscpy(dst->release, src->release, sizeof(dst->release));
	strscpy(dst->version, src->version, sizeof(dst->version));
	strscpy(dst->machine, src->machine, sizeof(dst->machine));
	strscpy(dst->domainname, src->domainname, sizeof(dst->domainname));
}

#define KSU_UTS_UPDATE_FIELD(bit, field)                                       \
	do {                                                                   \
		if (new_mask & (bit)) {                                        \
			if (!(old_mask & (bit)) ||                             \
			    strncmp(active_name->field,                        \
				    global_last_applied.field,                 \
				    sizeof(active_name->field)))               \
				strscpy(global_restore_uts.field,              \
					active_name->field,                    \
					sizeof(global_restore_uts.field));     \
			strscpy(active_name->field, tmpl->field,               \
				sizeof(active_name->field));                   \
			strscpy(global_last_applied.field, tmpl->field,        \
				sizeof(global_last_applied.field));            \
		} else if (old_mask & (bit)) {                                 \
			if (!strncmp(active_name->field,                       \
				     global_last_applied.field,                \
				     sizeof(active_name->field)))              \
				strscpy(active_name->field,                    \
					global_restore_uts.field,              \
					sizeof(active_name->field));           \
		}                                                              \
	} while (0)

static void apply_global_locked(const struct ksu_uts_template *tmpl)
{
	struct new_utsname *active_name = &init_uts_ns_ptr->name;
	u32 old_mask = global_owned_mask;
	u32 new_mask = tmpl->field_mask;

	KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_SYSNAME, sysname);
	KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_NODENAME, nodename);
	KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_RELEASE, release);
	KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_VERSION, version);
	KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_MACHINE, machine);
	KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_DOMAINNAME, domainname);
	global_owned_mask = new_mask;
}

#undef KSU_UTS_UPDATE_FIELD

static void restore_global_locked(void)
{
	struct ksu_uts_template empty = {};

	apply_global_locked(&empty);
	memset(&global_restore_uts, 0, sizeof(global_restore_uts));
	memset(&global_last_applied, 0, sizeof(global_last_applied));
}

static void merge_template_locked(struct new_utsname *dst,
				  const struct ksu_uts_template *tmpl)
{
	if (tmpl->field_mask & KSU_UTS_FIELD_SYSNAME)
		strscpy(dst->sysname, tmpl->sysname, sizeof(dst->sysname));
	if (tmpl->field_mask & KSU_UTS_FIELD_NODENAME)
		strscpy(dst->nodename, tmpl->nodename, sizeof(dst->nodename));
	if (tmpl->field_mask & KSU_UTS_FIELD_RELEASE)
		strscpy(dst->release, tmpl->release, sizeof(dst->release));
	if (tmpl->field_mask & KSU_UTS_FIELD_VERSION)
		strscpy(dst->version, tmpl->version, sizeof(dst->version));
	if (tmpl->field_mask & KSU_UTS_FIELD_MACHINE)
		strscpy(dst->machine, tmpl->machine, sizeof(dst->machine));
	if (tmpl->field_mask & KSU_UTS_FIELD_DOMAINNAME)
		strscpy(dst->domainname, tmpl->domainname,
			sizeof(dst->domainname));
}

static u32 audit_detached_tasks(void)
{
	struct task_struct *task;
	u32 count = 0;

	rcu_read_lock();
	for_each_process(task)
	{
		task_lock(task);
		if (task->mm && task->nsproxy && task->nsproxy->uts_ns &&
		    task->nsproxy->uts_ns != init_uts_ns_ptr)
			count++;
		task_unlock(task);
	}
	rcu_read_unlock();
	return count;
}

static void update_deny_active_locked(void)
{
	WRITE_ONCE(deny_scoped_active,
		   !uts_view_stopping && deny_cfg.field_mask &&
		       (uts_view_mode & KSU_UTS_VIEW_MODE_DENY_SCOPED));
}

static bool uts_view_callback_enter(void)
{
	bool entered = false;

	mutex_lock(&uts_view_lock);
	if (!uts_view_stopping) {
		atomic_inc(&uts_view_active_callbacks);
		entered = true;
	}
	mutex_unlock(&uts_view_lock);
	return entered;
}

static void uts_view_callback_exit(void)
{
	if (atomic_dec_and_test(&uts_view_active_callbacks))
		wake_up(&uts_view_callback_waitq);
}

static int set_mode_locked(u64 value)
{
	bool change_global;

	if (value & ~KSU_UTS_VIEW_MODE_VALID_MASK)
		return -EINVAL;

	if (uts_view_stopping || !uts_sem_ptr || !init_uts_ns_ptr)
		return -ENODEV;
	if ((value & KSU_UTS_VIEW_MODE_DENY_SCOPED) && !deny_cfg.field_mask)
		return -ENODATA;

	change_global = (value ^ uts_view_mode) & KSU_UTS_VIEW_MODE_GLOBAL;
	if ((uts_view_status_flags & KSU_UTS_STATUS_BOOT_LOCKED) &&
	    change_global)
		return -EPERM;

	if (change_global && (value & KSU_UTS_VIEW_MODE_GLOBAL)) {
		if (!global_cfg.field_mask)
			return -ENODATA;
		if (!runtime_audit_done) {
			detached_task_count = audit_detached_tasks();
			runtime_audit_done = true;
			if (detached_task_count)
				uts_view_status_flags |=
				    KSU_UTS_STATUS_LATE_GAPS;
		}
		down_write(uts_sem_ptr);
		apply_global_locked(&global_cfg);
		up_write(uts_sem_ptr);
		uts_view_source = KSU_UTS_SOURCE_RUNTIME;
	} else if (change_global) {
		down_write(uts_sem_ptr);
		restore_global_locked();
		up_write(uts_sem_ptr);
		uts_view_source = KSU_UTS_SOURCE_NONE;
	}

	uts_view_mode = value;
	update_deny_active_locked();
	return 0;
}

bool ksu_uts_view_boot_requested(void)
{
	/*
	 * A late-loaded module has already missed real init. Treat any stale
	 * uts_boot_* parameters as inapplicable instead of making the entire
	 * module load fatal.
	 */
	return READ_ONCE(uts_boot_global) && !READ_ONCE(ksu_late_loaded);
}

static void clear_boot_params(void)
{
	uts_boot_global = false;
	uts_boot_mask = 0;
	memzero_explicit(uts_boot_sysname, sizeof(uts_boot_sysname));
	memzero_explicit(uts_boot_nodename, sizeof(uts_boot_nodename));
	memzero_explicit(uts_boot_release, sizeof(uts_boot_release));
	memzero_explicit(uts_boot_version, sizeof(uts_boot_version));
	memzero_explicit(uts_boot_machine, sizeof(uts_boot_machine));
	memzero_explicit(uts_boot_domainname, sizeof(uts_boot_domainname));
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -EINVAL;
}

static int decode_boot_field(char dst[KSU_UTS_NAME_LEN], const char *src)
{
	size_t src_len;
	size_t i;

	if (strncmp(src, "hex:", 4)) {
		if (strscpy(dst, src, KSU_UTS_NAME_LEN) < 0)
			return -E2BIG;
		return 0;
	}

	src += 4;
	src_len = strlen(src);
	if ((src_len & 1) || src_len > (KSU_UTS_NAME_LEN - 1) * 2)
		return -EINVAL;
	for (i = 0; i < src_len; i += 2) {
		int high = hex_value(src[i]);
		int low = hex_value(src[i + 1]);
		unsigned char value;

		if (high < 0 || low < 0)
			return -EINVAL;
		value = (high << 4) | low;
		if (!value)
			return -EINVAL;
		dst[i / 2] = value;
	}
	dst[src_len / 2] = '\0';
	return 0;
}

static int build_boot_template(struct ksu_uts_template *tmpl)
{
	int ret;

	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->field_mask = uts_boot_mask;

	if (!tmpl->field_mask)
		return -ENODATA;
	if (tmpl->field_mask & KSU_UTS_FIELD_SYSNAME) {
		ret = decode_boot_field(tmpl->sysname, uts_boot_sysname);
		if (ret)
			return ret;
	}
	if (tmpl->field_mask & KSU_UTS_FIELD_NODENAME) {
		ret = decode_boot_field(tmpl->nodename, uts_boot_nodename);
		if (ret)
			return ret;
	}
	if (tmpl->field_mask & KSU_UTS_FIELD_RELEASE) {
		ret = decode_boot_field(tmpl->release, uts_boot_release);
		if (ret)
			return ret;
	}
	if (tmpl->field_mask & KSU_UTS_FIELD_VERSION) {
		ret = decode_boot_field(tmpl->version, uts_boot_version);
		if (ret)
			return ret;
	}
	if (tmpl->field_mask & KSU_UTS_FIELD_MACHINE) {
		ret = decode_boot_field(tmpl->machine, uts_boot_machine);
		if (ret)
			return ret;
	}
	if (tmpl->field_mask & KSU_UTS_FIELD_DOMAINNAME) {
		ret = decode_boot_field(tmpl->domainname, uts_boot_domainname);
		if (ret)
			return ret;
	}
	normalize_template(tmpl);
	if (!tmpl->field_mask)
		return -ENODATA;
	return validate_template(tmpl);
}

int ksu_uts_view_init(void)
{
	struct ksu_uts_template boot_cfg;
	bool late_boot_ignored = uts_boot_global && ksu_late_loaded;
	bool boot_requested = uts_boot_global && !ksu_late_loaded;
	int ret = 0;

	memset(&boot_cfg, 0, sizeof(boot_cfg));
	if (late_boot_ignored) {
		pr_warn("uts_view: ignoring boot-global parameters during "
			"late-load\n");
		clear_boot_params();
	}
	if (boot_requested) {
		ret = build_boot_template(&boot_cfg);
		if (ret)
			goto out_clear_boot;
	}

	uts_sem_ptr = (struct rw_semaphore *)ksu_lookup_symbol("uts_sem");
	init_uts_ns_ptr =
	    (struct uts_namespace *)ksu_lookup_symbol("init_uts_ns");
	if (!uts_sem_ptr || !init_uts_ns_ptr) {
		pr_warn("uts_view: uts_sem/init_uts_ns unavailable\n");
		ret = -ENOENT;
		goto out_clear_symbols;
	}

	mutex_lock(&uts_view_lock);
	uts_view_stopping = false;
	down_write(uts_sem_ptr);
	memcpy(&boot_original_uts, &init_uts_ns_ptr->name,
	       sizeof(boot_original_uts));
	boot_original_valid = true;
	uts_view_status_flags = KSU_UTS_STATUS_ORIGINAL_VALID;
	if (ksu_late_loaded)
		uts_view_status_flags |= KSU_UTS_STATUS_LATE_CAPTURE;

	if (boot_requested) {
		memcpy(&global_cfg, &boot_cfg, sizeof(global_cfg));
		apply_global_locked(&global_cfg);
		uts_view_mode |= KSU_UTS_VIEW_MODE_GLOBAL;
		uts_view_source = KSU_UTS_SOURCE_BOOT;
		uts_view_status_flags |= KSU_UTS_STATUS_BOOT_LOCKED;
	}
	up_write(uts_sem_ptr);
	mutex_unlock(&uts_view_lock);

	clear_boot_params();
	pr_info("uts_view: initialized%s\n",
		boot_requested ? " with boot-global identity" : "");
	return 0;

out_clear_symbols:
	uts_sem_ptr = NULL;
	init_uts_ns_ptr = NULL;
out_clear_boot:
	clear_boot_params();
	return ret;
}

void ksu_uts_view_exit(void)
{
	mutex_lock(&uts_view_lock);
	uts_view_stopping = true;
	WRITE_ONCE(deny_scoped_active, false);
	mutex_unlock(&uts_view_lock);

	wait_event(uts_view_callback_waitq,
		   atomic_read(&uts_view_active_callbacks) == 0);

	mutex_lock(&uts_view_lock);
	if (uts_sem_ptr && init_uts_ns_ptr && global_owned_mask) {
		down_write(uts_sem_ptr);
		restore_global_locked();
		up_write(uts_sem_ptr);
	}
	memset(&global_cfg, 0, sizeof(global_cfg));
	memset(&deny_cfg, 0, sizeof(deny_cfg));
	memset(&boot_original_uts, 0, sizeof(boot_original_uts));
	boot_original_valid = false;
	uts_view_mode = 0;
	uts_view_source = KSU_UTS_SOURCE_NONE;
	uts_view_status_flags = 0;
	detached_task_count = 0;
	runtime_audit_done = false;
	uts_sem_ptr = NULL;
	init_uts_ns_ptr = NULL;
	mutex_unlock(&uts_view_lock);
	clear_boot_params();
}

int ksu_uts_view_get_config(struct ksu_uts_view_config *config)
{
	if (!config)
		return -EINVAL;

	mutex_lock(&uts_view_lock);
	if (!boot_original_valid || uts_view_stopping) {
		mutex_unlock(&uts_view_lock);
		return -ENODEV;
	}
	memset(config, 0, sizeof(*config));
	config->version = KSU_UTS_VIEW_ABI_VERSION;
	config->size = sizeof(*config);
	config->mode = uts_view_mode;
	memcpy(&config->global, &global_cfg, sizeof(config->global));
	memcpy(&config->deny, &deny_cfg, sizeof(config->deny));
	mutex_unlock(&uts_view_lock);
	return 0;
}

int ksu_uts_view_set_config(const struct ksu_uts_view_config *config)
{
	struct ksu_uts_view_config normalized_config;
	bool apply_mode;
	u64 target_mode;
	int ret;

	if (!config)
		return -EINVAL;
	memcpy(&normalized_config, config, sizeof(normalized_config));
	normalize_template(&normalized_config.global);
	normalize_template(&normalized_config.deny);
	config = &normalized_config;

	ret = validate_config(config);
	if (ret)
		return ret;

	mutex_lock(&uts_view_lock);
	if (!boot_original_valid || uts_view_stopping) {
		ret = -ENODEV;
		goto out;
	}

	if ((config->update_mask & KSU_UTS_CONFIG_UPDATE_GLOBAL) &&
	    (uts_view_status_flags & KSU_UTS_STATUS_BOOT_LOCKED)) {
		ret = -EPERM;
		goto out;
	}

	target_mode = uts_view_mode;
	if (config->update_mask & KSU_UTS_CONFIG_UPDATE_MODE) {
		target_mode = config->mode;
		if ((uts_view_status_flags & KSU_UTS_STATUS_BOOT_LOCKED) &&
		    ((target_mode ^ uts_view_mode) &
		     KSU_UTS_VIEW_MODE_GLOBAL)) {
			ret = -EPERM;
			goto out;
		}
	}
	if ((config->update_mask & KSU_UTS_CONFIG_UPDATE_GLOBAL) &&
	    !config->global.field_mask)
		target_mode &= ~KSU_UTS_VIEW_MODE_GLOBAL;
	if ((config->update_mask & KSU_UTS_CONFIG_UPDATE_DENY) &&
	    !config->deny.field_mask)
		target_mode &= ~KSU_UTS_VIEW_MODE_DENY_SCOPED;
	apply_mode = (config->update_mask & KSU_UTS_CONFIG_UPDATE_MODE) ||
		     target_mode != uts_view_mode;

	if ((target_mode & KSU_UTS_VIEW_MODE_GLOBAL) &&
	    ((config->update_mask & KSU_UTS_CONFIG_UPDATE_GLOBAL)
		 ? !config->global.field_mask
		 : !global_cfg.field_mask)) {
		ret = -ENODATA;
		goto out;
	}
	if ((target_mode & KSU_UTS_VIEW_MODE_DENY_SCOPED) &&
	    ((config->update_mask & KSU_UTS_CONFIG_UPDATE_DENY)
		 ? !config->deny.field_mask
		 : !deny_cfg.field_mask)) {
		ret = -ENODATA;
		goto out;
	}

	if (config->update_mask & KSU_UTS_CONFIG_UPDATE_GLOBAL) {
		memcpy(&global_cfg, &config->global, sizeof(global_cfg));
		if ((uts_view_mode & KSU_UTS_VIEW_MODE_GLOBAL) &&
		    (target_mode & KSU_UTS_VIEW_MODE_GLOBAL)) {
			down_write(uts_sem_ptr);
			apply_global_locked(&global_cfg);
			up_write(uts_sem_ptr);
			uts_view_source = KSU_UTS_SOURCE_RUNTIME;
		}
	}
	if (config->update_mask & KSU_UTS_CONFIG_UPDATE_DENY)
		memcpy(&deny_cfg, &config->deny, sizeof(deny_cfg));
	ret = apply_mode ? set_mode_locked(target_mode) : 0;
	if (!apply_mode)
		update_deny_active_locked();
out:
	mutex_unlock(&uts_view_lock);
	return ret;
}

int ksu_uts_view_get_status(struct ksu_uts_view_status *status)
{
	if (!status)
		return -EINVAL;

	mutex_lock(&uts_view_lock);
	if (!boot_original_valid || uts_view_stopping) {
		mutex_unlock(&uts_view_lock);
		return -ENODEV;
	}
	memset(status, 0, sizeof(*status));
	status->version = KSU_UTS_VIEW_ABI_VERSION;
	status->size = sizeof(*status);
	status->source = uts_view_source;
	status->status_flags = uts_view_status_flags;
	status->mode = uts_view_mode;
	status->detached_task_count = detached_task_count;
	uts_to_template(&status->original, &boot_original_uts);
	down_read(uts_sem_ptr);
	uts_to_template(&status->effective_global, &init_uts_ns_ptr->name);
	up_read(uts_sem_ptr);
	mutex_unlock(&uts_view_lock);
	return 0;
}

void ksu_uts_view_on_setresuid(uid_t old_uid, uid_t new_uid)
{
	struct ksu_uts_template scoped;
	struct uts_namespace *current_uts;
	const struct cred *old_cred;
	long ret;

	(void)old_uid;
	if (!is_appuid(new_uid) && !is_isolated_process(new_uid))
		return;
	if (!READ_ONCE(deny_scoped_active))
		return;
	if (!uts_view_callback_enter())
		return;
	if (!is_isolated_process(new_uid) && !ksu_uid_should_umount(new_uid))
		goto out;
	if (!is_zygote(get_current_cred()))
		goto out;
	if (!current || (current->flags & PF_KTHREAD) || !current->fs ||
	    !current->nsproxy || !current->nsproxy->uts_ns)
		goto out;

	mutex_lock(&uts_view_lock);
	if (uts_view_stopping ||
	    !(uts_view_mode & KSU_UTS_VIEW_MODE_DENY_SCOPED) ||
	    !deny_cfg.field_mask || !uts_sem_ptr || !init_uts_ns_ptr ||
	    !ksu_cred) {
		mutex_unlock(&uts_view_lock);
		goto out;
	}
	current_uts = current->nsproxy->uts_ns;
	if (current_uts != init_uts_ns_ptr) {
		mutex_unlock(&uts_view_lock);
		goto out;
	}
	memcpy(&scoped, &deny_cfg, sizeof(scoped));
	mutex_unlock(&uts_view_lock);

	old_cred = override_creds(ksu_cred);
	ret = ksys_unshare(CLONE_NEWUTS);
	revert_creds(old_cred);
	if (ret) {
		pr_warn("uts_view: CLONE_NEWUTS failed for pid %d: %ld\n",
			current->pid, ret);
		goto out;
	}

	mutex_lock(&uts_view_lock);
	if (!uts_view_stopping && uts_sem_ptr && current->nsproxy &&
	    current->nsproxy->uts_ns &&
	    current->nsproxy->uts_ns != init_uts_ns_ptr) {
		down_write(uts_sem_ptr);
		merge_template_locked(&current->nsproxy->uts_ns->name, &scoped);
		up_write(uts_sem_ptr);
	}
	mutex_unlock(&uts_view_lock);

out:
	uts_view_callback_exit();
}
