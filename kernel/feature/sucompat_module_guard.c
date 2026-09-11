#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/string.h>

#include "feature/sucompat_module_guard.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

#define KSU_CONFLICTING_MODULE "kasumi_lkm"

static struct mutex *loader_mutex;
static struct list_head *loaded_modules;
static bool guard_registered;
static bool kasumi_blocked;

static int sucompat_module_notify(struct notifier_block *nb,
				  unsigned long action, void *data)
{
	const struct module *mod = data;

	(void)nb;
	if (action != MODULE_STATE_COMING ||
	    strcmp(mod->name, KSU_CONFLICTING_MODULE) ||
	    !READ_ONCE(kasumi_blocked))
		return NOTIFY_DONE;

	pr_warn("kasumi: sucompact: refusing kasumi_lkm while KSM owns the VFS "
		"view\n");
	return notifier_from_errno(-EBUSY);
}

static struct notifier_block sucompat_module_notifier = {
    .notifier_call = sucompat_module_notify,
    .priority = INT_MAX,
};

int ksu_sucompat_module_guard_acquire(void)
{
	struct module *mod;
	int ret = 0;

	if (!guard_registered)
		return -EOPNOTSUPP;
	mutex_lock(loader_mutex);
	if (kasumi_blocked)
		goto out;
	/* Include UNFORMED and GOING modules: both can still race VFS setup. */
	list_for_each_entry (mod, loaded_modules, list) {
		if (!strcmp(mod->name, KSU_CONFLICTING_MODULE)) {
			pr_warn("kasumi: sucompact: kasumi_lkm must be "
				"unloaded before "
				"enabling KSM\n");
			ret = -EBUSY;
			goto out;
		}
	}
	/* Module-list insertion uses this mutex before the COMING notification.
	 */
	WRITE_ONCE(kasumi_blocked, true);
out:
	mutex_unlock(loader_mutex);
	return ret;
}

void ksu_sucompat_module_guard_release(void)
{
	if (!guard_registered)
		return;
	mutex_lock(loader_mutex);
	WRITE_ONCE(kasumi_blocked, false);
	mutex_unlock(loader_mutex);
}

int ksu_sucompat_module_guard_init(void)
{
	int ret;

	loader_mutex = ksu_lookup_symbol("module_mutex");
	loaded_modules = ksu_lookup_symbol("modules");
	if (!loader_mutex || !loaded_modules)
		return -EOPNOTSUPP;
	ret = register_module_notifier(&sucompat_module_notifier);
	if (!ret)
		guard_registered = true;
	return ret;
}

void ksu_sucompat_module_guard_exit(void)
{
	if (!guard_registered)
		return;
	unregister_module_notifier(&sucompat_module_notifier);
	guard_registered = false;
}
