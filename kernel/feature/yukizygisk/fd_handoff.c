#include <linux/file.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>

#include "api.h"
#include "internal.h"
#include "uapi/yukizygisk.h"
#include "klog.h" // IWYU pragma: keep

struct yz_fd_handoff {
	pid_t pid; /* 0 marks a free slot. */
	uid_t appid;
	u32 flags;
	int n;
	struct file *files[YZ_MAX_MODULE_FDS];
	struct callback_head twork;
};

#define YZ_MAX_PENDING 64
static struct yz_fd_handoff yz_handoffs[YZ_MAX_PENDING];
static DEFINE_SPINLOCK(yz_handoff_lock);

/* yz_handoff_lock must be held. */
static struct yz_fd_handoff *yz_handoff_slot(pid_t pid)
{
	int i;

	for (i = 0; i < YZ_MAX_PENDING; i++)
		if (yz_handoffs[i].pid == pid)
			return &yz_handoffs[i];
	return NULL;
}

/* Runs in target context and installs held files into its fd table. */
static void yz_handoff_deliver(struct callback_head *head)
{
	struct yz_fd_handoff *p =
	    container_of(head, struct yz_fd_handoff, twork);
	struct file *files[YZ_MAX_MODULE_FDS];
	unsigned long flags;
	pid_t pid;
	int n, i, fd, done = 0;

	spin_lock_irqsave(&yz_handoff_lock, flags);
	n = p->n;
	pid = p->pid;
	for (i = 0; i < n; i++)
		files[i] = p->files[i];
	memset(p, 0, sizeof(*p));
	spin_unlock_irqrestore(&yz_handoff_lock, flags);

	if (current->flags & PF_EXITING) {
		for (i = 0; i < n; i++)
			if (files[i])
				fput(files[i]);
		return;
	}

	for (i = 0; i < n; i++) {
		if (!files[i])
			continue;
		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0) {
			fput(files[i]);
			continue;
		}
		fd_install(fd, files[i]); /* consumes our reference */
		done++;
	}

	pr_info("yukizygisk: module fds installed pid=%d installed=%d "
		"requested=%d\n",
		pid, done, n);
}

int ksu_yukizygisk_handoff_module_fds(void __user *arg)
{
	struct yz_handoff_cmd cmd;
	struct file *files[YZ_MAX_MODULE_FDS] = {NULL};
	struct file *old[YZ_MAX_MODULE_FDS];
	int n_old = 0;
	struct yz_fd_handoff *p;
	struct task_struct *task;
	bool target_found;
	unsigned long flags;
	int i, ret = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.n_fds > YZ_MAX_MODULE_FDS)
		return -EINVAL;

	/* Hold file references independently of zygiskd. */
	for (i = 0; i < cmd.n_fds; i++) {
		files[i] = fget(cmd.fds[i]);
		if (!files[i]) {
			ret = -EBADF;
			goto err;
		}
	}

	/* Hold the target through task_work queueing. */
	rcu_read_lock();
	task = find_task_by_vpid(cmd.pid);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	target_found = task != NULL;

	spin_lock_irqsave(&yz_handoff_lock, flags);
	p = yz_handoff_slot(cmd.pid);
	if (!p)
		p = yz_handoff_slot(0);
	if (!p) {
		spin_unlock_irqrestore(&yz_handoff_lock, flags);
		if (task)
			put_task_struct(task);
		ret = -ENOSPC;
		goto err;
	}
	for (i = 0; i < p->n; i++)
		old[n_old++] = p->files[i];
	p->pid = cmd.pid;
	p->appid = cmd.appid;
	p->flags = cmd.flags;
	p->n = cmd.n_fds;
	for (i = 0; i < cmd.n_fds; i++)
		p->files[i] = files[i];
	if (task) {
		init_task_work(&p->twork, yz_handoff_deliver);
		task_work_add(task, &p->twork, TWA_RESUME);
	}
	spin_unlock_irqrestore(&yz_handoff_lock, flags);

	if (task)
		put_task_struct(task);

	/* fput outside the lock -- __fput may sleep/queue work */
	for (i = 0; i < n_old; i++)
		if (old[i])
			fput(old[i]);

	pr_info("yukizygisk: module fd handoff updated pid=%u appid=%u "
		"count=%u target=%d\n",
		cmd.pid, cmd.appid, cmd.n_fds, target_found ? 1 : 0);
	return 0;

err:
	for (i = 0; i < cmd.n_fds; i++)
		if (files[i])
			fput(files[i]);
	return ret;
}

void yz_fd_handoff_release(pid_t pid)
{
	struct file *to_put[YZ_MAX_MODULE_FDS];
	int n = 0, i;
	unsigned long flags;
	struct yz_fd_handoff *p;

	spin_lock_irqsave(&yz_handoff_lock, flags);
	p = yz_handoff_slot(pid);
	if (p) {
		for (i = 0; i < p->n; i++)
			to_put[n++] = p->files[i];
		memset(p, 0, sizeof(*p));
	}
	spin_unlock_irqrestore(&yz_handoff_lock, flags);

	for (i = 0; i < n; i++)
		if (to_put[i])
			fput(to_put[i]);
}

void yz_fd_handoff_init(void)
{
	pr_info("yukizygisk: module fd delivery initialized\n");
}

void yz_fd_handoff_exit(void)
{
	int i, j;

	/* Release references held by undelivered slots. */
	for (i = 0; i < YZ_MAX_PENDING; i++) {
		for (j = 0; j < yz_handoffs[i].n; j++)
			if (yz_handoffs[i].files[j])
				fput(yz_handoffs[i].files[j]);
		yz_handoffs[i].n = 0;
		yz_handoffs[i].pid = 0;
	}
}
