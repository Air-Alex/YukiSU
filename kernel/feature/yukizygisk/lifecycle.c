#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/types.h>

#include <trace/events/sched.h>

#include "api.h"
#include "internal.h"
#include "selinux/selinux.h"
#include "klog.h" // IWYU pragma: keep

enum yz_lifecycle_state {
	YZ_LIFECYCLE_FORKED,
	YZ_LIFECYCLE_SPECIALIZED,
};

struct yz_lifecycle_child {
	pid_t pid; /* tgid of the app process; 0 == free slot */
	uid_t uid;
	enum yz_lifecycle_state state;
};

#define YZ_LIFECYCLE_MAX_CHILDREN 512
static struct yz_lifecycle_child
    yz_lifecycle_children[YZ_LIFECYCLE_MAX_CHILDREN];
static DEFINE_SPINLOCK(yz_lifecycle_lock);

/* yz_lifecycle_lock must be held. */
static int yz_lifecycle_slot_of(pid_t pid)
{
	int i;

	for (i = 0; i < YZ_LIFECYCLE_MAX_CHILDREN; i++)
		if (yz_lifecycle_children[i].pid == pid)
			return i;
	return -1;
}

static void yz_lifecycle_track(pid_t pid)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&yz_lifecycle_lock, flags);
	if (yz_lifecycle_slot_of(pid) < 0) {
		i = yz_lifecycle_slot_of(0);
		if (i >= 0) {
			yz_lifecycle_children[i].pid = pid;
			yz_lifecycle_children[i].uid = (uid_t)-1;
			yz_lifecycle_children[i].state = YZ_LIFECYCLE_FORKED;
		}
	}
	spin_unlock_irqrestore(&yz_lifecycle_lock, flags);
}

#ifdef CONFIG_TRACEPOINTS

static void yz_lifecycle_on_fork(void *data, struct task_struct *parent,
				 struct task_struct *child)
{
	bool from_zygote;

	(void)data;

	/* Track process leaders, not zygote worker threads. */
	if (child->pid != child->tgid)
		return;

	rcu_read_lock();
	from_zygote = is_zygote(__task_cred(parent));
	rcu_read_unlock();
	if (!from_zygote)
		return;

	yz_lifecycle_track(child->pid);
	pr_info("yukizygisk: app forked pid=%d zygote=%d\n", child->pid,
		parent->pid);
}

static void yz_lifecycle_on_free(void *data, struct task_struct *p)
{
	unsigned long flags;
	bool tracked = false;
	uid_t uid = 0;
	int i;

	(void)data;

	if (p->pid != p->tgid)
		return;

	spin_lock_irqsave(&yz_lifecycle_lock, flags);
	i = yz_lifecycle_slot_of(p->pid);
	if (i >= 0) {
		tracked = true;
		uid = yz_lifecycle_children[i].uid;
		yz_lifecycle_children[i].pid = 0;
	}
	spin_unlock_irqrestore(&yz_lifecycle_lock, flags);

	if (tracked) {
		pr_info("yukizygisk: app exited pid=%d uid=%u\n", p->pid, uid);
		yz_fd_handoff_release(p->pid);
	}
}

void yz_lifecycle_init(void)
{
	int ret = register_trace_sched_process_fork(yz_lifecycle_on_fork, NULL);

	if (ret) {
		pr_err(
		    "yukizygisk: fork tracepoint registration failed err=%d\n",
		    ret);
		return;
	}

	ret = register_trace_sched_process_free(yz_lifecycle_on_free, NULL);
	if (ret) {
		pr_err(
		    "yukizygisk: free tracepoint registration failed err=%d\n",
		    ret);
		unregister_trace_sched_process_fork(yz_lifecycle_on_fork, NULL);
		tracepoint_synchronize_unregister();
		return;
	}

	pr_info("yukizygisk: lifecycle tracking enabled\n");
}

void yz_lifecycle_exit(void)
{
	unregister_trace_sched_process_fork(yz_lifecycle_on_fork, NULL);
	unregister_trace_sched_process_free(yz_lifecycle_on_free, NULL);
	tracepoint_synchronize_unregister();
}

#else /* !CONFIG_TRACEPOINTS */

void yz_lifecycle_init(void)
{
	pr_warn("yukizygisk: lifecycle tracking requires CONFIG_TRACEPOINTS\n");
}

void yz_lifecycle_exit(void)
{
}

#endif /* CONFIG_TRACEPOINTS */

/* A successful UID transition identifies a tracked app child. */
void ksu_yukizygisk_on_setresuid(uid_t old_uid, uid_t new_uid)
{
	unsigned long flags;
	pid_t pid = current->pid;
	bool specialized = false;
	int i;

	(void)old_uid;

	if (new_uid < 10000) /* app uids only */
		return;

	/* Isolated app IDs 90000-99999 must not receive module FDs. */
	if (new_uid % 100000 >= 90000)
		return;

	spin_lock_irqsave(&yz_lifecycle_lock, flags);
	i = yz_lifecycle_slot_of(pid);
	if (i >= 0 && yz_lifecycle_children[i].state == YZ_LIFECYCLE_FORKED) {
		yz_lifecycle_children[i].uid = new_uid;
		yz_lifecycle_children[i].state = YZ_LIFECYCLE_SPECIALIZED;
		specialized = true;
	}
	spin_unlock_irqrestore(&yz_lifecycle_lock, flags);

	if (specialized) {
		pr_info("yukizygisk: app specialized pid=%d uid=%u appid=%u\n",
			pid, new_uid, new_uid % 100000);
		yz_emit_specialize(pid, new_uid % 100000);
	}
}
