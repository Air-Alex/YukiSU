#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "feature/sucompat_prompt.h"
#include "feature/sucompat_vfs.h"
#include "policy/allowlist.h"
#include "uapi/supercall.h"

#define KSU_SU_PROMPT_QUEUE_TIMEOUT (12 * HZ)
#define KSU_SU_PROMPT_START_TIMEOUT (12 * HZ)
#define KSU_SU_PROMPT_TIMEOUT (12 * HZ)
#define KSU_SU_PROMPT_MAX_PENDING 16
#define KSU_SU_PROMPT_MAX_PER_UID 4

struct ksu_su_prompt_state {
	struct list_head node;
	struct ksu_su_prompt_request request;
	u64 generation;
	unsigned long deadline;
	unsigned int sequence;
	bool delivered;
	bool ready;
	bool decided;
	u32 choice;
	int result;
};

static DEFINE_MUTEX(prompt_lock);
static DECLARE_WAIT_QUEUE_HEAD(prompt_wait);
static atomic64_t prompt_next_id = ATOMIC64_INIT(0);
static atomic64_t prompt_generation = ATOMIC64_INIT(1);
static LIST_HEAD(prompt_requests);
static struct ksu_su_prompt_state *prompt_active;
static unsigned int prompt_count;
static bool prompt_readable;
static bool prompt_consumer_active;

static void prompt_changed_locked(struct ksu_su_prompt_state *state)
{
	WRITE_ONCE(state->sequence, state->sequence + 1);
	wake_up_all(&prompt_wait);
}

static void prompt_finish_locked(struct ksu_su_prompt_state *state, int result)
{
	state->result = result;
	state->decided = true;
	prompt_changed_locked(state);
}

static void prompt_activate_locked(void)
{
	struct ksu_su_prompt_state *state;

	if (prompt_active && !prompt_active->decided &&
	    time_after_eq(jiffies, prompt_active->deadline))
		prompt_finish_locked(prompt_active, -ETIMEDOUT);
	if (prompt_active && !prompt_active->decided)
		goto out;
	prompt_active = NULL;
	if (!prompt_consumer_active)
		goto out;
	list_for_each_entry (state, &prompt_requests, node) {
		if (state->decided)
			continue;
		if (time_after_eq(jiffies, state->deadline)) {
			prompt_finish_locked(state, -ETIMEDOUT);
			continue;
		}
		prompt_active = state;
		state->deadline = jiffies + KSU_SU_PROMPT_START_TIMEOUT;
		prompt_changed_locked(state);
		break;
	}
out:
	WRITE_ONCE(prompt_readable, prompt_active &&
					!prompt_active->delivered &&
					!prompt_active->decided);
	wake_up_all(&prompt_wait);
}

static void prompt_revoke_locked(int error)
{
	struct ksu_su_prompt_state *state;

	atomic64_inc(&prompt_generation);
	list_for_each_entry (state, &prompt_requests, node) {
		if (!state->decided || !state->result)
			prompt_finish_locked(state,
					     error < 0 ? error : -ECANCELED);
	}
	prompt_active = NULL;
	WRITE_ONCE(prompt_readable, false);
	wake_up_all(&prompt_wait);
}

bool ksu_sucompat_prompt_consumer_ready(void)
{
	return READ_ONCE(prompt_consumer_active);
}

int ksu_sucompat_prompt_set_gate(bool enabled)
{
	int ret;

	mutex_lock(&prompt_lock);
	if (enabled && !prompt_consumer_active) {
		ret = -ENOTCONN;
		goto out;
	}
	ret = ksu_sucompat_vfs_set_prompt_enabled(enabled);
	if (!ret && !enabled)
		prompt_revoke_locked(-ECANCELED);
out:
	mutex_unlock(&prompt_lock);
	return ret;
}

void ksu_sucompat_prompt_cancel(int error)
{
	mutex_lock(&prompt_lock);
	prompt_revoke_locked(error);
	mutex_unlock(&prompt_lock);
}

static ssize_t prompt_read(struct file *file, char __user *buf, size_t count,
			   loff_t *ppos)
{
	struct ksu_su_prompt_request request;
	int ret;

	(void)file;
	(void)ppos;
	if (!count)
		return 0;
	if (count < sizeof(request))
		return -EMSGSIZE;
retry:
	mutex_lock(&prompt_lock);
	if (!prompt_consumer_active) {
		ret = -EPIPE;
		goto out;
	}
	prompt_activate_locked();
	if (!prompt_readable) {
		mutex_unlock(&prompt_lock);
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(
		    prompt_wait, !READ_ONCE(prompt_consumer_active) ||
				     READ_ONCE(prompt_readable));
		if (ret)
			return ret;
		goto retry;
	}
	request = prompt_active->request;
	if (copy_to_user(buf, &request, sizeof(request))) {
		ret = -EFAULT;
		goto out;
	}
	prompt_active->delivered = true;
	WRITE_ONCE(prompt_readable, false);
	ret = sizeof(request);
out:
	mutex_unlock(&prompt_lock);
	return ret;
}

static __poll_t prompt_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;

	poll_wait(file, &prompt_wait, wait);
	mutex_lock(&prompt_lock);
	if (!prompt_consumer_active)
		mask |= EPOLLHUP | EPOLLERR;
	else if (prompt_readable)
		mask |= EPOLLIN | EPOLLRDNORM;
	mutex_unlock(&prompt_lock);
	return mask;
}

static bool prompt_key_matches(const struct ksu_su_prompt_key *key)
{
	return prompt_active && !prompt_active->decided &&
	       key->request_id == prompt_active->request.request_id &&
	       key->nonce == prompt_active->request.nonce;
}

int ksu_sucompat_prompt_ready(const struct ksu_su_prompt_key *key)
{
	long remaining;
	int ret;

	mutex_lock(&prompt_lock);
	prompt_activate_locked();
	if (!prompt_key_matches(key) || !prompt_active->delivered) {
		ret = -ESTALE;
		goto out;
	}
	if (!prompt_active->ready) {
		prompt_active->ready = true;
		prompt_active->deadline = jiffies + KSU_SU_PROMPT_TIMEOUT;
		prompt_changed_locked(prompt_active);
	}
	remaining = (long)(prompt_active->deadline - jiffies);
	if (remaining <= 0) {
		prompt_finish_locked(prompt_active, -ETIMEDOUT);
		prompt_activate_locked();
		ret = -ESTALE;
	} else {
		ret = jiffies_to_msecs(remaining);
	}
out:
	mutex_unlock(&prompt_lock);
	return ret;
}

static long prompt_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ksu_su_prompt_key key;
	int ret = 0;

	(void)file;
	if (cmd != KSU_IOCTL_CANCEL_SU_PROMPT)
		return -ENOTTY;
	if (copy_from_user(&key, (void __user *)arg, sizeof(key)))
		return -EFAULT;
	mutex_lock(&prompt_lock);
	if (!prompt_key_matches(&key)) {
		ret = -ESTALE;
	} else {
		prompt_finish_locked(prompt_active, -ECANCELED);
		prompt_activate_locked();
	}
	mutex_unlock(&prompt_lock);
	return ret;
}

static int prompt_release(struct inode *inode, struct file *file)
{
	(void)inode;
	(void)file;
	mutex_lock(&prompt_lock);
	prompt_consumer_active = false;
	prompt_revoke_locked(-EPIPE);
	wake_up_all(&prompt_wait);
	mutex_unlock(&prompt_lock);
	return 0;
}

static const struct file_operations prompt_fops = {
    .owner = THIS_MODULE,
    .read = prompt_read,
    .poll = prompt_poll,
    .unlocked_ioctl = prompt_ioctl,
    .release = prompt_release,
    .llseek = noop_llseek,
};

int ksu_sucompat_prompt_install_fd(void)
{
	struct file *file;
	int fd;

	mutex_lock(&prompt_lock);
	if (prompt_consumer_active) {
		fd = -EBUSY;
		goto out;
	}
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		goto out;
	file = anon_inode_getfile("[ksu_su_prompt]", &prompt_fops, NULL,
				  O_RDONLY | O_CLOEXEC);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		fd = PTR_ERR(file);
		goto out;
	}
	prompt_consumer_active = true;
	fd_install(fd, file);
out:
	mutex_unlock(&prompt_lock);
	return fd;
}

static int prompt_persist_locked(const struct ksu_su_prompt_state *state,
				 const struct ksu_su_prompt_verdict *verdict,
				 struct app_profile *profile)
{
	memset(profile, 0, sizeof(*profile));
	profile->version = KSU_APP_PROFILE_VER;
	profile->curr_uid = state->request.uid;
	strscpy(profile->key, verdict->package, sizeof(profile->key));
	if (!profile->key[0])
		return -EINVAL;
	if (verdict->choice == KSU_SU_CHOICE_ALLOW_FOREVER) {
		profile->allow_su = true;
		profile->rp_config.use_default = true;
	} else {
		profile->allow_su = false;
		profile->nrp_config.use_default = false;
		profile->nrp_config.profile.umount_modules = true;
	}
	return ksu_set_app_profile(profile, true) ? 0 : -EIO;
}

int ksu_sucompat_prompt_submit(const struct ksu_su_prompt_verdict *verdict)
{
	struct app_profile profile;
	struct ksu_su_prompt_state *state;
	int ret = 0;

	if (!verdict)
		return -EINVAL;
	if (strnlen(verdict->package, sizeof(verdict->package)) >=
	    sizeof(verdict->package))
		return -EINVAL;
	if (verdict->choice < KSU_SU_CHOICE_ALLOW_FOREVER ||
	    verdict->choice > KSU_SU_CHOICE_DENY_HIDE)
		return -EINVAL;
	if (verdict->reserved)
		return -EINVAL;
	mutex_lock(&prompt_lock);
	prompt_activate_locked();
	state = prompt_active;
	if (!prompt_consumer_active || !state) {
		ret = -ENOENT;
		goto out;
	}
	if (state->decided) {
		ret = -EALREADY;
		goto out;
	}
	if (!state->delivered) {
		ret = -EAGAIN;
		goto out;
	}
	if (verdict->request_id != state->request.request_id ||
	    verdict->nonce != state->request.nonce) {
		ret = -ESTALE;
		goto out;
	}
	if (!ksu_sucompat_vfs_enabled() || !ksu_sucompat_vfs_prompt_enabled() ||
	    !is_appuid(state->request.uid) ||
	    is_isolated_process(state->request.uid) ||
	    ksu_uid_should_umount(state->request.uid)) {
		ret = -EACCES;
		goto reject;
	}
	if (verdict->choice == KSU_SU_CHOICE_ALLOW_FOREVER ||
	    verdict->choice == KSU_SU_CHOICE_DENY_HIDE) {
		ret = prompt_persist_locked(state, verdict, &profile);
		if (ret)
			goto reject;
	}
	if (verdict->choice == KSU_SU_CHOICE_ALLOW_FOREVER ||
	    verdict->choice == KSU_SU_CHOICE_ALLOW_ONCE)
		state->result = 0;
	else if (verdict->choice == KSU_SU_CHOICE_DENY)
		state->result = -EPERM;
	else
		state->result = -EACCES;
	state->choice = verdict->choice;
	prompt_finish_locked(state, state->result);
	prompt_activate_locked();
	goto out;
reject:
	state->choice = KSU_SU_CHOICE_DENY;
	prompt_finish_locked(state, ret);
	prompt_activate_locked();
out:
	mutex_unlock(&prompt_lock);
	return ret;
}

int ksu_sucompat_prompt_request(u32 *choice, u64 *generation)
{
	struct ksu_su_prompt_state *state, *other;
	unsigned int same_uid = 0;
	u64 id;
	u64 nonce;
	int ret;

	if (!choice || !generation)
		return -EINVAL;
	*choice = 0;
	*generation = 0;
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	mutex_lock(&prompt_lock);
	if (!ksu_sucompat_vfs_prompt_visible()) {
		ret = -EACCES;
		goto out_unlock;
	}
	if (!prompt_consumer_active) {
		ret = -ENOTCONN;
		goto out_unlock;
	}
	list_for_each_entry (other, &prompt_requests, node) {
		if (other->request.uid == current_uid().val)
			same_uid++;
	}
	if (prompt_count >= KSU_SU_PROMPT_MAX_PENDING ||
	    same_uid >= KSU_SU_PROMPT_MAX_PER_UID) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	state->request.version = KSU_SU_PROMPT_VERSION;
	state->request.size = sizeof(state->request);
	do {
		id = atomic64_inc_return(&prompt_next_id) &
		     0x7fffffffffffffffULL;
	} while (!id);
	state->request.request_id = id;
	do {
		nonce = get_random_u64() & 0x7fffffffffffffffULL;
	} while (!nonce);
	state->request.nonce = nonce;
	state->request.uid = current_uid().val;
	state->request.pid = task_pid_nr(current);
	state->request.tgid = task_tgid_nr(current);
	get_task_comm(state->request.comm, current);
	state->generation = atomic64_read(&prompt_generation);
	state->deadline = jiffies + KSU_SU_PROMPT_QUEUE_TIMEOUT;
	list_add_tail(&state->node, &prompt_requests);
	prompt_count++;
	prompt_activate_locked();

	for (;;) {
		unsigned int sequence = state->sequence;
		unsigned long now = jiffies;
		unsigned long timeout;
		long waited;

		if (state->decided) {
			ret = state->result;
			if (!ret) {
				*choice = state->choice;
				*generation = state->generation;
			}
			break;
		}
		if (time_after_eq(now, state->deadline)) {
			ret = -ETIMEDOUT;
			break;
		}
		timeout = state->deadline - now;
		mutex_unlock(&prompt_lock);
		waited = wait_event_killable_timeout(
		    prompt_wait, READ_ONCE(state->sequence) != sequence,
		    timeout);
		mutex_lock(&prompt_lock);
		if (waited < 0) {
			ret = (int)waited;
			break;
		}
	}
	if (prompt_active == state)
		prompt_active = NULL;
	list_del(&state->node);
	prompt_count--;
	prompt_activate_locked();

out_unlock:
	mutex_unlock(&prompt_lock);
	kfree(state);
	return ret;
}

bool ksu_sucompat_prompt_grant_valid(u64 generation)
{
	return generation && generation == atomic64_read(&prompt_generation);
}

void ksu_sucompat_prompt_init(void)
{
	BUILD_BUG_ON(sizeof(struct ksu_su_prompt_request) != 56);
	BUILD_BUG_ON(sizeof(struct ksu_su_prompt_verdict) != 280);
	mutex_lock(&prompt_lock);
	INIT_LIST_HEAD(&prompt_requests);
	prompt_active = NULL;
	prompt_count = 0;
	prompt_readable = false;
	atomic64_set(&prompt_generation, 1);
	prompt_consumer_active = false;
	mutex_unlock(&prompt_lock);
}

void ksu_sucompat_prompt_exit(void)
{
	mutex_lock(&prompt_lock);
	(void)ksu_sucompat_vfs_set_prompt_enabled(false);
	prompt_consumer_active = false;
	prompt_revoke_locked(-ESHUTDOWN);
	wake_up_all(&prompt_wait);
	mutex_unlock(&prompt_lock);
}
