#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/tracepoint.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "feature/sucompat_vfs.h"
#include "feature/sucompat_exec.h"
#include "feature/sucompat_prompt.h"
#include "feature/sucompat_module_guard.h"
#include "infra/symbol_resolver.h"
#include "ksu.h"
#include "policy/allowlist.h"
#include "selinux/selinux.h"

/*
 * A source-less vnode supplies the traditional su path and a stable exec
 * marker. The exec LSM bridge owns direct and prompted authorization.
 */
#define KSU_SUCOMPAT_PARENT "/system/bin"
#define KSU_SUCOMPAT_NAME "su"
#define KSU_SUVFS_DOP_HASH_BITS 6
#define KSU_SUVFS_FOP_HASH_BITS 4
#define KSU_SUVFS_SYNTH_DOP_HASH_BITS 4
#define KSU_SUVFS_DOP_AUTO_RETIRE 0
#define KSU_SUVFS_POS_SIG 0x7973ULL

#define KSU_SUVFS_DOP_FLAGS                                                    \
	(DCACHE_OP_HASH | DCACHE_OP_COMPARE | DCACHE_OP_REVALIDATE |           \
	 DCACHE_OP_WEAK_REVALIDATE | DCACHE_OP_DELETE | DCACHE_OP_PRUNE |      \
	 DCACHE_OP_REAL)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KSU_SUVFS_IDMAP_ARG struct mnt_idmap *idmap,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define KSU_SUVFS_IDMAP_ARG struct user_namespace *userns,
#else
#define KSU_SUVFS_IDMAP_ARG
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define KSU_SUVFS_ACTOR_RET bool
#define KSU_SUVFS_ACTOR_CONTINUE true
#else
#define KSU_SUVFS_ACTOR_RET int
#define KSU_SUVFS_ACTOR_CONTINUE 0
#endif

enum ksu_suvfs_view {
	KSU_SUVFS_VIEW_NONE,
	KSU_SUVFS_VIEW_DIRECT,
	KSU_SUVFS_VIEW_BROKER,
};

struct ksu_suvfs_fop_template {
	const struct file_operations *orig_fop;
	struct file_operations ingress_fop;
	struct file_operations shadow_fop;
	struct hlist_node orig_node;
	struct hlist_node ingress_node;
};

struct ksu_suvfs_synth_dop_template {
	const struct dentry_operations *orig_dop;
	struct dentry_operations active_dop;
	struct dentry_operations terminal_dop;
	struct hlist_node node;
};

struct ksu_suvfs_dop_meta {
	struct dentry_operations shadow_dop;
	const struct dentry_operations *orig_dop;
	struct dentry *dentry;
	struct ksu_suvfs_synth_dop_template *synth_template;
	unsigned int orig_op_flags;
	unsigned long state;
	bool synthetic;
	struct hlist_node hash_node;
	struct list_head node;
	struct list_head retire_node;
};

struct ksu_suvfs_state {
	struct inode *parent_inode;
	struct super_block *sb;
	const struct inode_operations *orig_iop;
	struct inode_operations parent_shadow_iop;
	struct ksu_suvfs_fop_template *active_fop_template;
	const struct super_operations *orig_sop;
	struct super_operations shadow_sop;
	unsigned long marker_ino;
	bool ready;
	bool enabled;
	bool retiring;
	bool parent_iop_installed;
	bool parent_fop_installed;
	bool accepting_vnodes;
	bool s_active_held;
	bool module_pin_held;
	atomic_t sop_callbacks;
	atomic_t vnode_live;
	atomic_t synth_dentry_live;
	bool prompt_enabled;
};

static struct ksu_suvfs_state suvfs;
static struct lock_class_key suvfs_vnode_i_mutex_key;
static DEFINE_MUTEX(suvfs_lock);
static DEFINE_MUTEX(suvfs_transition_lock);
static DEFINE_SPINLOCK(suvfs_sop_lock);
static DECLARE_WAIT_QUEUE_HEAD(suvfs_wait);
static DEFINE_HASHTABLE(suvfs_dops, KSU_SUVFS_DOP_HASH_BITS);
static DEFINE_HASHTABLE(suvfs_fops_by_orig, KSU_SUVFS_FOP_HASH_BITS);
static DEFINE_HASHTABLE(suvfs_fops_by_ingress, KSU_SUVFS_FOP_HASH_BITS);
static DEFINE_HASHTABLE(suvfs_synth_dops, KSU_SUVFS_SYNTH_DOP_HASH_BITS);
static LIST_HEAD(suvfs_dop_list);
DEFINE_STATIC_SRCU(suvfs_srcu);

static void suvfs_reap_dops_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(suvfs_reap_dops_work, suvfs_reap_dops_workfn);

static void (*suvfs_synchronize_rcu_tasks_ptr)(void);
static struct dentry *(*suvfs_d_lookup_ptr)(const struct dentry *,
					    const struct qstr *);
static void (*suvfs_shrink_dcache_sb_ptr)(struct super_block *);
static void (*suvfs_free_inode_nonrcu_ptr)(struct inode *);
static struct module *(*suvfs_module_address_ptr)(unsigned long);

static const struct inode_operations suvfs_vnode_iops;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static struct tracepoint *suvfs_check_file_open_tp;
static bool suvfs_fop_bridge_registered;
#endif

static struct dentry *suvfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags);
static bool suvfs_is_su_name(const struct qstr *name);
static bool suvfs_current_visible(void);
static bool suvfs_dops_owned_locked(void);
static bool suvfs_detach_all_dops_locked(struct list_head *retired);
static int suvfs_disable(void);
static int __nocfi suvfs_parent_iterate_shared(struct file *file,
					       struct dir_context *ctx);

static noinline __nocfi void suvfs_synchronize_rcu_tasks(void)
{
	suvfs_synchronize_rcu_tasks_ptr();
}

static noinline __nocfi struct dentry *
suvfs_d_lookup(const struct dentry *parent, const struct qstr *name)
{
	return suvfs_d_lookup_ptr(parent, name);
}

static noinline __nocfi void suvfs_shrink_dcache_sb(struct super_block *sb)
{
	suvfs_shrink_dcache_sb_ptr(sb);
}

static noinline __nocfi struct module *suvfs_module_address(unsigned long addr)
{
	struct module *owner;

	preempt_disable();
	owner = suvfs_module_address_ptr(addr);
	preempt_enable();
	return owner;
}

static bool suvfs_virtual_pos(loff_t pos)
{
	return (pos & 0xFFFFFFFF00000000ULL) == (KSU_SUVFS_POS_SIG << 48);
}

static loff_t suvfs_pack_pos(u32 pos)
{
	return (loff_t)((KSU_SUVFS_POS_SIG << 48) | pos);
}

struct ksu_suvfs_dir_proxy {
	struct dir_context ctx;
	struct dir_context *orig;
	bool stopped;
};

static KSU_SUVFS_ACTOR_RET __nocfi
suvfs_dir_proxy_actor(struct dir_context *ctx, const char *name, int namelen,
		      loff_t offset, u64 ino, unsigned int d_type)
{
	struct ksu_suvfs_dir_proxy *proxy =
	    container_of(ctx, struct ksu_suvfs_dir_proxy, ctx);
	KSU_SUVFS_ACTOR_RET ret;
	struct qstr qname = QSTR_INIT(name, namelen);

	if (suvfs_is_su_name(&qname)) {
		proxy->ctx.pos = offset;
		return KSU_SUVFS_ACTOR_CONTINUE;
	}
	proxy->orig->pos = proxy->ctx.pos;
	ret =
	    proxy->orig->actor(proxy->orig, name, namelen, offset, ino, d_type);
	proxy->ctx.pos = proxy->orig->pos;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	proxy->ctx.count = proxy->orig->count;
#endif
	if (ret != KSU_SUVFS_ACTOR_CONTINUE)
		proxy->stopped = true;
	return ret;
}

static void suvfs_emit_su(struct dir_context *ctx)
{
	if (!suvfs_virtual_pos(ctx->pos))
		ctx->pos = suvfs_pack_pos(0);
	if ((u32)ctx->pos != 0)
		return;
	if (dir_emit(ctx, KSU_SUCOMPAT_NAME, sizeof(KSU_SUCOMPAT_NAME) - 1,
		     READ_ONCE(suvfs.marker_ino), DT_REG))
		ctx->pos = suvfs_pack_pos(1);
}

static int __nocfi suvfs_parent_iterate_shared(struct file *file,
					       struct dir_context *ctx)
{
	struct ksu_suvfs_fop_template *template;
	const struct file_operations *live_fop;
	const struct file_operations *orig;
	struct ksu_suvfs_dir_proxy proxy = {};
	bool visible;
	int idx;
	int ret;

	live_fop = READ_ONCE(file->f_op);
	if (!live_fop ||
	    live_fop->iterate_shared != suvfs_parent_iterate_shared)
		return -ENOTDIR;
	template =
	    container_of(live_fop, struct ksu_suvfs_fop_template, shadow_fop);
	orig = template->orig_fop;
	if (!orig || !orig->iterate_shared)
		return -ENOTDIR;
	idx = srcu_read_lock(&suvfs_srcu);
	visible = READ_ONCE(suvfs.enabled) && !READ_ONCE(suvfs.retiring) &&
		  file_inode(file) == READ_ONCE(suvfs.parent_inode) &&
		  suvfs_current_visible();
	if (!visible) {
		ret = suvfs_virtual_pos(ctx->pos)
			  ? 0
			  : orig->iterate_shared(file, ctx);
		goto out;
	}
	if (suvfs_virtual_pos(ctx->pos)) {
		suvfs_emit_su(ctx);
		ret = 0;
		goto out;
	}

	proxy.ctx = *ctx;
	proxy.ctx.actor = suvfs_dir_proxy_actor;
	proxy.orig = ctx;
	ret = orig->iterate_shared(file, &proxy.ctx);
	ctx->pos = proxy.ctx.pos;
	if (ret < 0 || proxy.stopped)
		goto out;
	suvfs_emit_su(ctx);
out:
	srcu_read_unlock(&suvfs_srcu, idx);
	return ret;
}

static const struct file_operations *
suvfs_parent_installed_fop(const struct ksu_suvfs_fop_template *template)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
	return &template->ingress_fop;
#else
	return &template->shadow_fop;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static struct ksu_suvfs_fop_template *
suvfs_fop_template_by_ingress_rcu(const struct file_operations *ingress)
{
	struct ksu_suvfs_fop_template *template;

	hash_for_each_possible_rcu(suvfs_fops_by_ingress, template,
				   ingress_node, (unsigned long)ingress)
	{
		if (&template->ingress_fop == ingress)
			return template;
	}
	return NULL;
}

static void suvfs_fop_bridge_check_open(void *data,
					const struct file *const_file)
{
	struct ksu_suvfs_fop_template *template;
	struct file *file = (struct file *)const_file;
	const struct file_operations *old_fop;
	const struct file_operations *live_fop;

	(void)data;
	if (!file)
		return;
	old_fop = READ_ONCE(file->f_op);
	rcu_read_lock();
	template = suvfs_fop_template_by_ingress_rcu(old_fop);
	if (!template)
		goto out;
	live_fop = fops_get(&template->shadow_fop);
	if (likely(live_fop)) {
		WRITE_ONCE(file->f_op, live_fop);
		fops_put(old_fop);
	} else {
		WRITE_ONCE(file->f_op, template->orig_fop);
	}
out:
	rcu_read_unlock();
}

static void suvfs_find_check_file_open_tp(struct tracepoint *tp, void *data)
{
	struct tracepoint **result = data;

	if (!*result && tp->name &&
	    !strcmp(tp->name, "android_vh_check_file_open"))
		*result = tp;
}

static bool suvfs_fop_bridge_is_first(void)
{
	struct tracepoint_func *funcs;
	bool first = false;

	rcu_read_lock_sched();
	funcs = rcu_dereference_sched(suvfs_check_file_open_tp->funcs);
	if (funcs && funcs[0].func == (void *)suvfs_fop_bridge_check_open)
		first = true;
	rcu_read_unlock_sched();
	return first;
}

static int suvfs_fop_bridge_init(void)
{
	int ret;

	for_each_kernel_tracepoint(suvfs_find_check_file_open_tp,
				   &suvfs_check_file_open_tp);
	if (!suvfs_check_file_open_tp)
		return -ENOENT;
	ret = tracepoint_probe_register_prio(
	    suvfs_check_file_open_tp, (void *)suvfs_fop_bridge_check_open, NULL,
	    INT_MAX);
	if (ret)
		return ret;
	suvfs_fop_bridge_registered = true;
	if (!suvfs_fop_bridge_is_first()) {
		tracepoint_probe_unregister(suvfs_check_file_open_tp,
					    (void *)suvfs_fop_bridge_check_open,
					    NULL);
		tracepoint_synchronize_unregister();
		suvfs_fop_bridge_registered = false;
		suvfs_check_file_open_tp = NULL;
		return -EBUSY;
	}
	return 0;
}

static void suvfs_fop_bridge_exit(void)
{
	if (!suvfs_fop_bridge_registered)
		return;
	suvfs_synchronize_rcu_tasks();
	tracepoint_probe_unregister(suvfs_check_file_open_tp,
				    (void *)suvfs_fop_bridge_check_open, NULL);
	tracepoint_synchronize_unregister();
	suvfs_fop_bridge_registered = false;
	suvfs_check_file_open_tp = NULL;
}
#else
static int suvfs_fop_bridge_init(void)
{
	return 0;
}

static void suvfs_fop_bridge_exit(void)
{
}
#endif

static void suvfs_free_fop_templates(void)
{
	struct ksu_suvfs_fop_template *template;
	struct hlist_node *tmp;
	int bucket;

	synchronize_rcu();
	hash_for_each_safe(suvfs_fops_by_orig, bucket, tmp, template, orig_node)
	{
		hash_del(&template->orig_node);
		hash_del(&template->ingress_node);
		kfree(template);
	}
}

static void suvfs_free_synth_dop_templates(void)
{
	struct ksu_suvfs_synth_dop_template *template;
	struct hlist_node *tmp;
	int bucket;

	hash_for_each_safe(suvfs_synth_dops, bucket, tmp, template, node)
	{
		hash_del(&template->node);
		kfree(template);
	}
}

static bool suvfs_dop_has_module_owner(const struct dentry_operations *dop)
{
	if (!dop)
		return false;
	if (suvfs_module_address((unsigned long)dop) ||
	    (dop->d_revalidate &&
	     suvfs_module_address((unsigned long)dop->d_revalidate)) ||
	    (dop->d_weak_revalidate &&
	     suvfs_module_address((unsigned long)dop->d_weak_revalidate)) ||
	    (dop->d_hash && suvfs_module_address((unsigned long)dop->d_hash)) ||
	    (dop->d_compare &&
	     suvfs_module_address((unsigned long)dop->d_compare)) ||
	    (dop->d_delete &&
	     suvfs_module_address((unsigned long)dop->d_delete)) ||
	    (dop->d_init && suvfs_module_address((unsigned long)dop->d_init)) ||
	    (dop->d_release &&
	     suvfs_module_address((unsigned long)dop->d_release)) ||
	    (dop->d_prune &&
	     suvfs_module_address((unsigned long)dop->d_prune)) ||
	    (dop->d_iput && suvfs_module_address((unsigned long)dop->d_iput)) ||
	    (dop->d_dname &&
	     suvfs_module_address((unsigned long)dop->d_dname)) ||
	    (dop->d_automount &&
	     suvfs_module_address((unsigned long)dop->d_automount)) ||
	    (dop->d_manage &&
	     suvfs_module_address((unsigned long)dop->d_manage)) ||
	    (dop->d_real && suvfs_module_address((unsigned long)dop->d_real)) ||
	    (dop->d_canonical_path &&
	     suvfs_module_address((unsigned long)dop->d_canonical_path)))
		return true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
	if ((dop->d_unalias_trylock &&
	     suvfs_module_address((unsigned long)dop->d_unalias_trylock)) ||
	    (dop->d_unalias_unlock &&
	     suvfs_module_address((unsigned long)dop->d_unalias_unlock)))
		return true;
#endif
	return false;
}

static enum ksu_suvfs_view suvfs_current_view(void)
{
	uid_t uid;

	if (!READ_ONCE(suvfs.enabled) || READ_ONCE(suvfs.retiring))
		return KSU_SUVFS_VIEW_NONE;
#ifdef CONFIG_COMPAT
	if (is_compat_task())
		return KSU_SUVFS_VIEW_NONE;
#endif
	uid = current_uid().val;
	if (ksu_is_allow_uid_for_current(uid))
		return KSU_SUVFS_VIEW_DIRECT;
	if (READ_ONCE(suvfs.prompt_enabled) &&
	    ksu_sucompat_prompt_consumer_ready() && is_appuid(uid) &&
	    !is_isolated_process(uid) && !ksu_uid_should_umount(uid))
		return KSU_SUVFS_VIEW_BROKER;
	return KSU_SUVFS_VIEW_NONE;
}

static bool suvfs_current_visible(void)
{
	return suvfs_current_view() != KSU_SUVFS_VIEW_NONE;
}

bool ksu_sucompat_vfs_enabled(void)
{
	return READ_ONCE(suvfs.enabled);
}

bool ksu_sucompat_vfs_active(void)
{
	return READ_ONCE(suvfs.enabled) || READ_ONCE(suvfs.retiring) ||
	       READ_ONCE(suvfs.sb);
}

bool ksu_sucompat_vfs_prompt_enabled(void)
{
	return READ_ONCE(suvfs.prompt_enabled);
}

bool ksu_sucompat_vfs_prompt_visible(void)
{
	return suvfs_current_view() == KSU_SUVFS_VIEW_BROKER;
}

bool ksu_sucompat_vfs_is_inode(const struct inode *inode)
{
	return inode && inode->i_op == &suvfs_vnode_iops;
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

static bool suvfs_vnode_current(const struct inode *inode)
{
	return ksu_sucompat_vfs_is_inode(inode) && suvfs_current_visible();
}

static int suvfs_vnode_permission(KSU_SUVFS_IDMAP_ARG struct inode *inode,
				  int mask)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	(void)idmap;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	(void)userns;
#endif
	if (!suvfs_vnode_current(inode))
		return -EACCES;
	if (mask & MAY_WRITE)
		return -EROFS;
	return 0;
}

static int suvfs_vnode_open(struct inode *inode, struct file *file)
{
	(void)inode;
	return ksu_sucompat_exec_file_open(file);
}

static const struct inode_operations suvfs_vnode_iops = {
    .permission = suvfs_vnode_permission,
};

static const struct file_operations suvfs_vnode_fops = {
    .owner = THIS_MODULE,
    .open = suvfs_vnode_open,
    .release = ksu_sucompat_exec_file_release,
};

static bool suvfs_sop_vnode_get(struct super_block *sb)
{
	bool got = false;

	spin_lock(&suvfs_sop_lock);
	if (suvfs.sb == sb && suvfs.accepting_vnodes && !suvfs.retiring) {
		atomic_inc(&suvfs.vnode_live);
		got = true;
	}
	spin_unlock(&suvfs_sop_lock);
	return got;
}

static void suvfs_sop_vnode_put(struct super_block *sb)
{
	spin_lock(&suvfs_sop_lock);
	if (WARN_ON_ONCE(suvfs.sb != sb ||
			 atomic_read(&suvfs.vnode_live) <= 0)) {
		spin_unlock(&suvfs_sop_lock);
		return;
	}
	atomic_dec(&suvfs.vnode_live);
	spin_unlock(&suvfs_sop_lock);
	wake_up_all(&suvfs_wait);
}

static struct inode *suvfs_new_vnode(struct super_block *sb)
{
	struct inode *inode;
	int ret;

	if (!suvfs_sop_vnode_get(sb))
		return ERR_PTR(-ESHUTDOWN);
	inode = new_inode(sb);
	if (!inode) {
		suvfs_sop_vnode_put(sb);
		return ERR_PTR(-ENOMEM);
	}
	lockdep_set_class(&inode->i_rwsem, &suvfs_vnode_i_mutex_key);
	inode->i_op = &suvfs_vnode_iops;
	inode->i_fop = &suvfs_vnode_fops;
	inode->i_ino = READ_ONCE(suvfs.marker_ino);
	inode->i_mode = S_IFREG | 0555;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_size = 0;
	inode->i_blocks = 0;
	set_nlink(inode, 1);
	inode->i_flags |= S_NOATIME | S_NOCMTIME | S_NOSEC;
	inode->i_opflags |= IOP_XATTR | IOP_NOFOLLOW;
	inode_lock(inode);
	ret = security_inode_notifysecctx(inode, (void *)KSU_FILE_CONTEXT,
					  sizeof(KSU_FILE_CONTEXT) - 1);
	inode_unlock(inode);
	if (ret) {
		pr_err("kasumi_sucompat: vnode label init failed: %d\n", ret);
		iput(inode);
		return ERR_PTR(ret);
	}
	return inode;
}

static const struct super_operations *suvfs_sop_callback_enter(void)
{
	const struct super_operations *orig;

	atomic_inc(&suvfs.sop_callbacks);
	/* Pair callback admission with the retirement-side Tasks-RCU drain. */
	smp_mb__after_atomic();
	orig = smp_load_acquire(&suvfs.orig_sop);
	return orig;
}

static void suvfs_sop_callback_exit(void)
{
	if (atomic_dec_and_test(&suvfs.sop_callbacks))
		wake_up_all(&suvfs_wait);
}

static void suvfs_free_vnode(struct inode *inode)
{
	if (!ksu_sucompat_vfs_is_inode(inode))
		return;
	suvfs_sop_vnode_put(inode->i_sb);
}

static void __nocfi suvfs_destroy_inode(struct inode *inode)
{
	const struct super_operations *orig = suvfs_sop_callback_enter();

	suvfs_free_vnode(inode);
	if (orig && orig->destroy_inode)
		orig->destroy_inode(inode);
	suvfs_sop_callback_exit();
}

static void __nocfi suvfs_evict_inode(struct inode *inode)
{
	const struct super_operations *orig = suvfs_sop_callback_enter();

	if (ksu_sucompat_vfs_is_inode(inode)) {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
	} else if (orig && orig->evict_inode) {
		orig->evict_inode(inode);
	} else {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
	}
	suvfs_sop_callback_exit();
}

static int __nocfi suvfs_drop_inode(struct inode *inode)
{
	const struct super_operations *orig = suvfs_sop_callback_enter();
	int ret;

	if (ksu_sucompat_vfs_is_inode(inode))
		ret = !inode->i_nlink || inode_unhashed(inode);
	else if (orig && orig->drop_inode)
		ret = orig->drop_inode(inode);
	else
		ret = !inode->i_nlink || inode_unhashed(inode);
	suvfs_sop_callback_exit();
	return ret;
}

static struct ksu_suvfs_dop_meta *
suvfs_find_dop_rcu(const struct dentry *dentry)
{
	struct ksu_suvfs_dop_meta *meta;

	hash_for_each_possible_rcu(suvfs_dops, meta, hash_node,
				   (unsigned long)dentry)
	{
		if (meta->dentry == dentry)
			return meta;
	}
	return NULL;
}

static struct ksu_suvfs_dop_meta *
suvfs_find_dop_locked(const struct dentry *dentry)
{
	struct ksu_suvfs_dop_meta *meta;

	hash_for_each_possible(suvfs_dops, meta, hash_node,
			       (unsigned long)dentry)
	{
		if (meta->dentry == dentry)
			return meta;
	}
	return NULL;
}

static void suvfs_queue_dop_retire(struct ksu_suvfs_dop_meta *meta)
{
	if (!test_and_set_bit(KSU_SUVFS_DOP_AUTO_RETIRE, &meta->state))
		mod_delayed_work(system_wq, &suvfs_reap_dops_work, 0);
}

static int suvfs_revalidate_inner(struct ksu_suvfs_dop_meta *meta,
				  struct inode *dir, const struct qstr *name,
				  struct dentry *dentry, bool *chain_orig)
{
	bool is_marker;
	bool sees;

	*chain_orig = false;
	if (!meta || READ_ONCE(suvfs.retiring) ||
	    dir != READ_ONCE(suvfs.parent_inode) || !suvfs_is_su_name(name))
		return 0;
	is_marker = ksu_sucompat_vfs_is_inode(d_inode(dentry));
	sees = suvfs_current_visible();
	if (sees)
		return is_marker && suvfs_vnode_current(d_inode(dentry)) ? 1
									 : 0;
	if (is_marker)
		return 0;
	*chain_orig = true;
	return 1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
static int __nocfi suvfs_revalidate(struct inode *dir, const struct qstr *name,
				    struct dentry *dentry, unsigned int flags)
{
	struct ksu_suvfs_dop_meta *meta;
	bool chain_orig;
	int idx;
	int ret;

	idx = srcu_read_lock(&suvfs_srcu);
	rcu_read_lock();
	meta = suvfs_find_dop_rcu(dentry);
	rcu_read_unlock();
	if (!meta) {
		ret = 0;
		goto out;
	}
	ret = suvfs_revalidate_inner(meta, dir, name, dentry, &chain_orig);
	if (ret > 0 && chain_orig && meta->orig_dop &&
	    meta->orig_dop->d_revalidate)
		ret = meta->orig_dop->d_revalidate(dir, name, dentry, flags);
	if (ret == 0)
		suvfs_queue_dop_retire(meta);
out:
	srcu_read_unlock(&suvfs_srcu, idx);
	return ret;
}
#else
static int __nocfi suvfs_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct ksu_suvfs_dop_meta *meta;
	struct dentry *parent = READ_ONCE(dentry->d_parent);
	struct inode *dir = d_inode(parent);
	const struct qstr *name = &dentry->d_name;
	bool chain_orig;
	int idx;
	int ret;

	idx = srcu_read_lock(&suvfs_srcu);
	rcu_read_lock();
	meta = suvfs_find_dop_rcu(dentry);
	rcu_read_unlock();
	if (!meta) {
		ret = 0;
		goto out;
	}
	ret = suvfs_revalidate_inner(meta, dir, name, dentry, &chain_orig);
	if (ret > 0 && chain_orig && meta->orig_dop &&
	    meta->orig_dop->d_revalidate)
		ret = meta->orig_dop->d_revalidate(dentry, flags);
	if (ret == 0)
		suvfs_queue_dop_retire(meta);
out:
	srcu_read_unlock(&suvfs_srcu, idx);
	return ret;
}
#endif

static void __nocfi suvfs_synth_active_release(struct dentry *dentry)
{
	struct ksu_suvfs_synth_dop_template *template = container_of(
	    dentry->d_op, struct ksu_suvfs_synth_dop_template, active_dop);

	if (template->orig_dop && template->orig_dop->d_release)
		template->orig_dop->d_release(dentry);
	if (WARN_ON_ONCE(atomic_read(&suvfs.synth_dentry_live) <= 0))
		return;
	atomic_dec(&suvfs.synth_dentry_live);
	wake_up_all(&suvfs_wait);
}

static void __nocfi suvfs_synth_terminal_release(struct dentry *dentry)
{
	struct ksu_suvfs_synth_dop_template *template = container_of(
	    dentry->d_op, struct ksu_suvfs_synth_dop_template, terminal_dop);

	if (template->orig_dop && template->orig_dop->d_release)
		template->orig_dop->d_release(dentry);
	if (WARN_ON_ONCE(atomic_read(&suvfs.synth_dentry_live) <= 0))
		return;
	atomic_dec(&suvfs.synth_dentry_live);
	wake_up_all(&suvfs_wait);
}

static struct ksu_suvfs_synth_dop_template *
suvfs_synth_dop_template_locked(const struct dentry_operations *orig)
{
	struct ksu_suvfs_synth_dop_template *template;

	hash_for_each_possible(suvfs_synth_dops, template, node,
			       (unsigned long)orig)
	{
		if (template->orig_dop == orig)
			return template;
	}
	template = kzalloc(sizeof(*template), GFP_KERNEL);
	if (!template)
		return ERR_PTR(-ENOMEM);
	template->orig_dop = orig;
	template->active_dop.d_revalidate = suvfs_revalidate;
	template->active_dop.d_release = suvfs_synth_active_release;
	template->terminal_dop.d_revalidate = suvfs_revalidate;
	template->terminal_dop.d_release = suvfs_synth_terminal_release;
	hash_add(suvfs_synth_dops, &template->node, (unsigned long)orig);
	return template;
}

static int suvfs_set_dentry_ops(struct dentry *dentry, bool synthetic)
{
	struct ksu_suvfs_dop_meta *meta;
	struct ksu_suvfs_dop_meta *existing;
	struct ksu_suvfs_synth_dop_template *template = NULL;
	const struct dentry_operations *orig;
	int ret = 0;

	if (!dentry)
		return -EINVAL;
	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;
	meta->dentry = dget(dentry);
	INIT_LIST_HEAD(&meta->node);
	INIT_LIST_HEAD(&meta->retire_node);

	mutex_lock(&suvfs_lock);
	if (!suvfs.enabled || suvfs.retiring || !suvfs.parent_inode ||
	    d_inode(dentry->d_parent) != suvfs.parent_inode) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	existing = suvfs_find_dop_locked(dentry);
	if (existing) {
		ret = existing->synthetic != synthetic ||
			      test_bit(KSU_SUVFS_DOP_AUTO_RETIRE,
				       &existing->state)
			  ? -EAGAIN
			  : 0;
		goto out_unlock;
	}

	spin_lock(&dentry->d_lock);
	orig = READ_ONCE(dentry->d_op);
	if (suvfs_dop_has_module_owner(orig)) {
		spin_unlock(&dentry->d_lock);
		ret = -EBUSY;
		goto out_unlock;
	}
	spin_unlock(&dentry->d_lock);
	if (synthetic) {
		template = suvfs_synth_dop_template_locked(orig);
		if (IS_ERR(template)) {
			ret = PTR_ERR(template);
			goto out_unlock;
		}
	}
	spin_lock(&dentry->d_lock);
	if (READ_ONCE(dentry->d_op) != orig) {
		spin_unlock(&dentry->d_lock);
		ret = -EAGAIN;
		goto out_unlock;
	}
	meta->orig_dop = orig;
	meta->synthetic = synthetic;
	meta->synth_template = template;
	if (!synthetic && orig)
		meta->shadow_dop = *orig;
	if (!synthetic)
		meta->shadow_dop.d_revalidate = suvfs_revalidate;
	meta->orig_op_flags = READ_ONCE(dentry->d_flags) & KSU_SUVFS_DOP_FLAGS;
	hash_add_rcu(suvfs_dops, &meta->hash_node, (unsigned long)dentry);
	list_add_tail(&meta->node, &suvfs_dop_list);
	/* A callback can only be reached after its hash entry and d_op exist.
	 */
	smp_wmb();
	WRITE_ONCE(dentry->d_op,
		   synthetic ? &template->active_dop : &meta->shadow_dop);
	if (synthetic)
		atomic_inc(&suvfs.synth_dentry_live);
	/* Lockless pathwalk tests the flag before loading d_op. */
	smp_wmb();
	if (synthetic)
		WRITE_ONCE(dentry->d_flags,
			   (READ_ONCE(dentry->d_flags) & ~KSU_SUVFS_DOP_FLAGS) |
			       DCACHE_OP_REVALIDATE);
	else
		WRITE_ONCE(dentry->d_flags,
			   READ_ONCE(dentry->d_flags) | DCACHE_OP_REVALIDATE);
	spin_unlock(&dentry->d_lock);
	mutex_unlock(&suvfs_lock);
	return 0;

out_unlock:
	mutex_unlock(&suvfs_lock);
	dput(meta->dentry);
	kfree(meta);
	return ret;
}

static bool suvfs_retire_dop_locked(struct ksu_suvfs_dop_meta *meta,
				    struct list_head *retired)
{
	struct dentry *dentry = meta->dentry;

	spin_lock(&dentry->d_lock);
	if (meta->synthetic &&
	    dentry->d_op == &meta->synth_template->active_dop) {
		unsigned int flags = READ_ONCE(dentry->d_flags);

		WRITE_ONCE(dentry->d_flags, (flags & ~KSU_SUVFS_DOP_FLAGS) |
						DCACHE_OP_REVALIDATE);
		smp_wmb();
		WRITE_ONCE(dentry->d_op, &meta->synth_template->terminal_dop);
	} else if (meta->synthetic &&
		   dentry->d_op != &meta->synth_template->terminal_dop) {
		spin_unlock(&dentry->d_lock);
		return false;
	} else if (!meta->synthetic && dentry->d_op == &meta->shadow_dop) {
		unsigned int flags = READ_ONCE(dentry->d_flags);

		WRITE_ONCE(dentry->d_flags, (flags & ~KSU_SUVFS_DOP_FLAGS) |
						meta->orig_op_flags);
		smp_wmb();
		WRITE_ONCE(dentry->d_op, meta->orig_dop);
	} else if (!meta->synthetic && dentry->d_op != meta->orig_dop) {
		spin_unlock(&dentry->d_lock);
		return false;
	}
	spin_unlock(&dentry->d_lock);

	hash_del_rcu(&meta->hash_node);
	list_del_init(&meta->node);
	list_add_tail(&meta->retire_node, retired);
	d_drop(dentry);
	return true;
}

static void suvfs_drain_retired_dops(struct list_head *retired,
				     bool drain_lookup)
{
	struct ksu_suvfs_dop_meta *meta;
	struct ksu_suvfs_dop_meta *tmp;

	if (list_empty(retired) && !drain_lookup)
		return;
	suvfs_synchronize_rcu_tasks();
	synchronize_srcu(&suvfs_srcu);
	suvfs_synchronize_rcu_tasks();
	if (!list_empty(retired))
		synchronize_rcu();
	list_for_each_entry_safe (meta, tmp, retired, retire_node) {
		list_del(&meta->retire_node);
		dput(meta->dentry);
		kfree(meta);
	}
}

static void suvfs_reap_dops_workfn(struct work_struct *work)
{
	struct ksu_suvfs_dop_meta *meta;
	struct ksu_suvfs_dop_meta *tmp;
	LIST_HEAD(retired);
	struct super_block *sb;

	(void)work;
	mutex_lock(&suvfs_lock);
	list_for_each_entry_safe (meta, tmp, &suvfs_dop_list, node) {
		if (test_bit(KSU_SUVFS_DOP_AUTO_RETIRE, &meta->state))
			(void)suvfs_retire_dop_locked(meta, &retired);
	}
	sb = suvfs.sb;
	mutex_unlock(&suvfs_lock);
	suvfs_drain_retired_dops(&retired, false);
	if (sb)
		suvfs_shrink_dcache_sb(sb);
}

static bool suvfs_is_su_name(const struct qstr *name)
{
	return name && name->len == sizeof(KSU_SUCOMPAT_NAME) - 1 &&
	       !memcmp(name->name, KSU_SUCOMPAT_NAME,
		       sizeof(KSU_SUCOMPAT_NAME) - 1);
}

static struct dentry *__nocfi suvfs_lookup_inner(struct inode *dir,
						 struct dentry *dentry,
						 unsigned int flags)
{
	const struct inode_operations *orig = smp_load_acquire(&suvfs.orig_iop);
	struct dentry *res;
	bool governed;
	bool active;
	int ret;

	governed = dir == READ_ONCE(suvfs.parent_inode) &&
		   suvfs_is_su_name(&dentry->d_name);
	active = READ_ONCE(suvfs.enabled) && !READ_ONCE(suvfs.retiring);
	if (!governed)
		goto original;

	if (active && suvfs_current_visible()) {
		struct inode *inode = suvfs_new_vnode(dir->i_sb);

		if (IS_ERR(inode))
			return ERR_CAST(inode);
		ret = suvfs_set_dentry_ops(dentry, true);
		if (ret) {
			iput(inode);
			return ERR_PTR(ret);
		}
		d_add(dentry, inode);
		return NULL;
	}

original:
	if (orig && orig->lookup)
		res = orig->lookup(dir, dentry, flags);
	else {
		d_add(dentry, NULL);
		res = NULL;
	}
	if (governed && !IS_ERR(res)) {
		struct dentry *result = res ? res : dentry;

		if (!active || suvfs_set_dentry_ops(result, false))
			d_drop(result);
	}
	return res;
}

static struct dentry *suvfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct dentry *res;
	int idx = srcu_read_lock(&suvfs_srcu);

	res = suvfs_lookup_inner(dir, dentry, flags);
	srcu_read_unlock(&suvfs_srcu, idx);
	return res;
}

static void suvfs_drop_cached_su(struct inode *parent)
{
	struct dentry *parent_dentry;
	struct dentry *cached;
	struct qstr name =
	    QSTR_INIT(KSU_SUCOMPAT_NAME, sizeof(KSU_SUCOMPAT_NAME) - 1);

	if (!parent)
		return;
	parent_dentry = d_find_alias(parent);
	if (!parent_dentry)
		return;
	name.hash = full_name_hash(parent_dentry, name.name, name.len);
	cached = suvfs_d_lookup(parent_dentry, &name);
	if (cached) {
		d_drop(cached);
		dput(cached);
	}
	dput(parent_dentry);
}

int ksu_sucompat_vfs_set_prompt_enabled(bool enabled)
{
	LIST_HEAD(retired);
	int ret = 0;

	if (!READ_ONCE(suvfs.ready))
		return -ESHUTDOWN;
	mutex_lock(&suvfs_lock);
	if (suvfs.prompt_enabled != enabled) {
		if (suvfs.enabled &&
		    (!suvfs_dops_owned_locked() ||
		     !suvfs_detach_all_dops_locked(&retired))) {
			ret = -EBUSY;
			goto out_unlock;
		}
		WRITE_ONCE(suvfs.prompt_enabled, enabled);
	}
out_unlock:
	mutex_unlock(&suvfs_lock);
	suvfs_drain_retired_dops(&retired, false);
	return ret;
}

static bool suvfs_iop_has_module_owner(const struct inode_operations *iop)
{
	return suvfs_module_address((unsigned long)iop) ||
	       (iop->lookup &&
		suvfs_module_address((unsigned long)iop->lookup));
}

static bool suvfs_fop_has_module_owner(const struct file_operations *fop)
{
	if (!fop)
		return false;
	return fop->owner || suvfs_module_address((unsigned long)fop) ||
	       (fop->open && suvfs_module_address((unsigned long)fop->open)) ||
	       (fop->release &&
		suvfs_module_address((unsigned long)fop->release)) ||
	       (fop->iterate_shared &&
		suvfs_module_address((unsigned long)fop->iterate_shared));
}

static struct ksu_suvfs_fop_template *
suvfs_fop_template_by_orig_locked(const struct file_operations *orig)
{
	struct ksu_suvfs_fop_template *template;

	hash_for_each_possible(suvfs_fops_by_orig, template, orig_node,
			       (unsigned long)orig)
	{
		if (template->orig_fop == orig)
			return template;
	}
	return NULL;
}

static struct ksu_suvfs_fop_template *
suvfs_get_fop_template_locked(const struct file_operations *orig)
{
	struct ksu_suvfs_fop_template *template;

	template = suvfs_fop_template_by_orig_locked(orig);
	if (template)
		return template;
	template = kzalloc(sizeof(*template), GFP_KERNEL);
	if (!template)
		return ERR_PTR(-ENOMEM);
	template->orig_fop = orig;
	template->ingress_fop = *orig;
	template->shadow_fop = *orig;
	template->shadow_fop.owner = THIS_MODULE;
	template->shadow_fop.iterate_shared = suvfs_parent_iterate_shared;
	hash_add_rcu(suvfs_fops_by_orig, &template->orig_node,
		     (unsigned long)orig);
	hash_add_rcu(suvfs_fops_by_ingress, &template->ingress_node,
		     (unsigned long)&template->ingress_fop);
	return template;
}

static int suvfs_install_parent_fop(struct inode *parent)
{
	struct ksu_suvfs_fop_template *template;
	const struct file_operations *installed;
	const struct file_operations *orig;

	orig = READ_ONCE(parent->i_fop);
	if (!orig || !orig->iterate_shared)
		return -EOPNOTSUPP;
	if (suvfs_fop_has_module_owner(orig))
		return -EBUSY;
	if (suvfs.active_fop_template)
		return -EBUSY;
	template = suvfs_get_fop_template_locked(orig);
	if (IS_ERR(template))
		return PTR_ERR(template);
	installed = suvfs_parent_installed_fop(template);
	if (cmpxchg((const struct file_operations **)&parent->i_fop, orig,
		    installed) != orig)
		return -EAGAIN;
	suvfs.active_fop_template = template;
	suvfs.parent_fop_installed = true;
	return 0;
}

static int suvfs_detach_parent_fop(struct inode *parent)
{
	struct ksu_suvfs_fop_template *template = suvfs.active_fop_template;
	const struct file_operations *installed;
	const struct file_operations *current_fop = READ_ONCE(parent->i_fop);

	if (!template)
		return -EINVAL;
	installed = suvfs_parent_installed_fop(template);
	if (current_fop == template->orig_fop)
		return 0;
	if (current_fop != installed)
		return -EBUSY;
	if (cmpxchg((const struct file_operations **)&parent->i_fop, installed,
		    template->orig_fop) != installed)
		return -EBUSY;
	return 0;
}

static bool suvfs_sop_has_module_owner(const struct super_operations *sop)
{
	return suvfs_module_address((unsigned long)sop) ||
	       (sop->alloc_inode &&
		suvfs_module_address((unsigned long)sop->alloc_inode)) ||
	       (sop->destroy_inode &&
		suvfs_module_address((unsigned long)sop->destroy_inode)) ||
	       (sop->free_inode &&
		suvfs_module_address((unsigned long)sop->free_inode)) ||
	       (sop->drop_inode &&
		suvfs_module_address((unsigned long)sop->drop_inode)) ||
	       (sop->evict_inode &&
		suvfs_module_address((unsigned long)sop->evict_inode)) ||
	       (sop->put_super &&
		suvfs_module_address((unsigned long)sop->put_super));
}

static int suvfs_validate_unowned_ops(const struct inode *parent)
{
	const struct inode_operations *iop = READ_ONCE(parent->i_op);
	const struct super_operations *sop = READ_ONCE(parent->i_sb->s_op);

	if (!iop || !iop->lookup || !sop)
		return -EOPNOTSUPP;
	if (suvfs_iop_has_module_owner(iop) || suvfs_sop_has_module_owner(sop))
		return -EBUSY;
	return 0;
}

static int suvfs_install_sop(struct super_block *sb)
{
	const struct super_operations *orig;
	bool active_held = false;
	bool module_held = false;
	int ret = 0;

	down_read(&sb->s_umount);
	if (!(READ_ONCE(sb->s_flags) & SB_BORN) ||
	    !atomic_inc_not_zero(&sb->s_active)) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	active_held = true;
	if (!try_module_get(THIS_MODULE)) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	module_held = true;
	orig = READ_ONCE(sb->s_op);
	if (!orig) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	if (suvfs_sop_has_module_owner(orig)) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (!orig->destroy_inode && !orig->free_inode &&
	    !suvfs_free_inode_nonrcu_ptr) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	suvfs.sb = sb;
	smp_store_release(&suvfs.orig_sop, orig);
	suvfs.shadow_sop = *orig;
	suvfs.shadow_sop.destroy_inode = suvfs_destroy_inode;
	suvfs.shadow_sop.evict_inode = suvfs_evict_inode;
	suvfs.shadow_sop.drop_inode = suvfs_drop_inode;
	if (!orig->destroy_inode && !orig->free_inode)
		suvfs.shadow_sop.free_inode = suvfs_free_inode_nonrcu_ptr;
	suvfs.s_active_held = true;
	suvfs.module_pin_held = true;
	suvfs.accepting_vnodes = true;
	if (cmpxchg((const struct super_operations **)&sb->s_op, orig,
		    &suvfs.shadow_sop) != orig) {
		ret = -EAGAIN;
		suvfs.accepting_vnodes = false;
		suvfs.s_active_held = false;
		suvfs.module_pin_held = false;
		suvfs.orig_sop = NULL;
		suvfs.sb = NULL;
		goto out_unlock;
	}
	active_held = false;
	module_held = false;

out_unlock:
	up_read(&sb->s_umount);
	if (active_held)
		deactivate_super(sb);
	if (module_held)
		module_put(THIS_MODULE);
	return ret;
}

static int suvfs_restore_sop(void)
{
	struct super_block *sb = suvfs.sb;
	const struct super_operations *orig = suvfs.orig_sop;
	const struct super_operations *current_sop;

	if (!sb || !orig)
		return -EINVAL;
	down_read(&sb->s_umount);
	current_sop = READ_ONCE(sb->s_op);
	if (current_sop != orig &&
	    (current_sop != &suvfs.shadow_sop ||
	     cmpxchg((const struct super_operations **)&sb->s_op,
		     &suvfs.shadow_sop, orig) != &suvfs.shadow_sop)) {
		up_read(&sb->s_umount);
		return -EBUSY;
	}
	up_read(&sb->s_umount);

	suvfs_synchronize_rcu_tasks();
	wait_event(suvfs_wait, !atomic_read(&suvfs.sop_callbacks));
	suvfs_synchronize_rcu_tasks();
	synchronize_rcu();
	return 0;
}

static int suvfs_enable(void)
{
	const struct cred *old_cred;
	const struct inode_operations *orig_iop;
	struct inode *cleanup_parent = NULL;
	struct super_block *cleanup_sb = NULL;
	struct inode *parent;
	struct path parent_path;
	bool cleanup_active = false;
	bool cleanup_module = false;
	int rebind_attempts = 0;
	int ret;

resolve_parent:
	if (!READ_ONCE(suvfs.ready))
		return -ESHUTDOWN;
	if (!ksu_cred)
		return -EAGAIN;
	old_cred = override_creds(ksu_cred);
	ret = kern_path(KSU_SUCOMPAT_PARENT, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&parent_path);
	revert_creds(old_cred);
	if (ret)
		return ret;
	parent = d_inode(parent_path.dentry);
	if (!parent || !S_ISDIR(parent->i_mode)) {
		path_put(&parent_path);
		return -ENOTDIR;
	}

	mutex_lock(&suvfs_lock);
	if (suvfs.enabled) {
		bool same_parent = suvfs.parent_inode == parent;

		mutex_unlock(&suvfs_lock);
		path_put(&parent_path);
		if (same_parent)
			return 0;
		ret = suvfs_disable();
		if (ret)
			return ret;
		if (++rebind_attempts > 2)
			return -EAGAIN;
		goto resolve_parent;
	}
	if (suvfs.retiring || suvfs.sb || suvfs.parent_inode) {
		ret = -EBUSY;
		goto out_unlock;
	}
	ret = suvfs_validate_unowned_ops(parent);
	if (ret)
		goto out_unlock;
	ret = suvfs_install_sop(parent->i_sb);
	if (ret)
		goto out_unlock;

	suvfs.parent_inode = igrab(parent);
	if (!suvfs.parent_inode) {
		ret = -ESTALE;
		goto out_failed_install;
	}
	suvfs.marker_ino = parent->i_ino ^ 0x53550000UL;
	if (!suvfs.marker_ino)
		suvfs.marker_ino = 1;
	ret = suvfs_install_parent_fop(parent);
	if (ret)
		goto out_failed_install;
	orig_iop = READ_ONCE(parent->i_op);
	if (!orig_iop || !orig_iop->lookup ||
	    suvfs_iop_has_module_owner(orig_iop)) {
		ret = -EBUSY;
		goto out_failed_install;
	}
	smp_store_release(&suvfs.orig_iop, orig_iop);
	suvfs.parent_shadow_iop = *suvfs.orig_iop;
	suvfs.parent_shadow_iop.lookup = suvfs_lookup;
	if (cmpxchg((const struct inode_operations **)&parent->i_op,
		    suvfs.orig_iop,
		    &suvfs.parent_shadow_iop) != suvfs.orig_iop) {
		ret = -EAGAIN;
		goto out_failed_install;
	}
	suvfs.parent_iop_installed = true;
	/* Drain callers that fetched the original lookup before the CAS. */
	suvfs_synchronize_rcu_tasks();
	suvfs_drop_cached_su(parent);
	suvfs_shrink_dcache_sb(parent->i_sb);
	WRITE_ONCE(suvfs.retiring, false);
	WRITE_ONCE(suvfs.enabled, true);
	pr_info("kasumi_sucompat: VFS provider enabled\n");
	goto out_unlock;

out_failed_install:
	spin_lock(&suvfs_sop_lock);
	suvfs.accepting_vnodes = false;
	spin_unlock(&suvfs_sop_lock);
	if (suvfs.parent_fop_installed) {
		int fop_ret = suvfs_detach_parent_fop(parent);

		if (fop_ret) {
			WRITE_ONCE(suvfs.enabled, false);
			WRITE_ONCE(suvfs.retiring, true);
			ret = fop_ret;
			goto out_unlock;
		}
		suvfs.parent_fop_installed = false;
	}
	if (suvfs_restore_sop()) {
		WRITE_ONCE(suvfs.enabled, false);
		WRITE_ONCE(suvfs.retiring, true);
		goto out_unlock;
	}
	cleanup_parent = suvfs.parent_inode;
	cleanup_sb = suvfs.sb;
	cleanup_active = suvfs.s_active_held;
	cleanup_module = suvfs.module_pin_held;
	suvfs.parent_inode = NULL;
	suvfs.parent_iop_installed = false;
	suvfs.parent_fop_installed = false;
	suvfs.active_fop_template = NULL;
	suvfs.orig_iop = NULL;
	suvfs.orig_sop = NULL;
	suvfs.sb = NULL;
	suvfs.marker_ino = 0;
	suvfs.s_active_held = false;
	suvfs.module_pin_held = false;
out_unlock:
	mutex_unlock(&suvfs_lock);
	if (cleanup_parent)
		iput(cleanup_parent);
	path_put(&parent_path);
	if (cleanup_active)
		deactivate_super(cleanup_sb);
	if (cleanup_module)
		module_put(THIS_MODULE);
	return ret;
}

static bool suvfs_dops_owned_locked(void)
{
	struct ksu_suvfs_dop_meta *meta;
	bool owned = true;

	list_for_each_entry (meta, &suvfs_dop_list, node) {
		spin_lock(&meta->dentry->d_lock);
		if (meta->synthetic) {
			if (meta->dentry->d_op !=
				&meta->synth_template->active_dop &&
			    meta->dentry->d_op !=
				&meta->synth_template->terminal_dop)
				owned = false;
		} else if (meta->dentry->d_op != &meta->shadow_dop &&
			   meta->dentry->d_op != meta->orig_dop) {
			owned = false;
		}
		spin_unlock(&meta->dentry->d_lock);
		if (!owned)
			break;
	}
	return owned;
}

static bool suvfs_detach_all_dops_locked(struct list_head *retired)
{
	struct ksu_suvfs_dop_meta *meta;
	struct ksu_suvfs_dop_meta *tmp;
	bool detached = true;

	list_for_each_entry_safe (meta, tmp, &suvfs_dop_list, node)
		if (!suvfs_retire_dop_locked(meta, retired))
			detached = false;
	return detached;
}

static int suvfs_rollback_disable(struct inode *parent)
{
	struct ksu_suvfs_fop_template *template = suvfs.active_fop_template;
	const struct inode_operations *current_iop;
	const struct file_operations *installed_fop;
	const struct file_operations *current_fop;
	bool iop_restored = false;

	if (!parent || !suvfs.sb || !template ||
	    READ_ONCE(suvfs.sb->s_op) != &suvfs.shadow_sop)
		return -EBUSY;
	current_iop = READ_ONCE(parent->i_op);
	installed_fop = suvfs_parent_installed_fop(template);
	current_fop = READ_ONCE(parent->i_fop);
	if ((current_iop != &suvfs.parent_shadow_iop &&
	     current_iop != suvfs.orig_iop) ||
	    (current_fop != installed_fop && current_fop != template->orig_fop))
		return -EBUSY;
	if (current_iop == suvfs.orig_iop) {
		if (cmpxchg((const struct inode_operations **)&parent->i_op,
			    suvfs.orig_iop,
			    &suvfs.parent_shadow_iop) != suvfs.orig_iop)
			return -EBUSY;
		iop_restored = true;
	}
	if (current_fop == template->orig_fop &&
	    cmpxchg((const struct file_operations **)&parent->i_fop,
		    template->orig_fop, installed_fop) != template->orig_fop) {
		if (iop_restored)
			(void)cmpxchg(
			    (const struct inode_operations **)&parent->i_op,
			    &suvfs.parent_shadow_iop, suvfs.orig_iop);
		return -EBUSY;
	}
	suvfs.parent_iop_installed = true;
	suvfs.parent_fop_installed = true;
	spin_lock(&suvfs_sop_lock);
	suvfs.accepting_vnodes = true;
	spin_unlock(&suvfs_sop_lock);
	suvfs_synchronize_rcu_tasks();
	suvfs_drop_cached_su(parent);
	suvfs_shrink_dcache_sb(parent->i_sb);
	WRITE_ONCE(suvfs.retiring, false);
	WRITE_ONCE(suvfs.enabled, true);
	return -EBUSY;
}

static int suvfs_detach_parent_iop(struct inode *parent)
{
	const struct inode_operations *current_iop;

	current_iop = READ_ONCE(parent->i_op);
	if (current_iop == suvfs.orig_iop)
		return 0;
	if (current_iop != &suvfs.parent_shadow_iop)
		return -EBUSY;
	if (cmpxchg((const struct inode_operations **)&parent->i_op,
		    &suvfs.parent_shadow_iop,
		    suvfs.orig_iop) != &suvfs.parent_shadow_iop)
		return -EBUSY;
	return 0;
}

static int suvfs_disable(void)
{
	LIST_HEAD(retired);
	struct ksu_suvfs_fop_template *template;
	struct super_block *sb;
	struct inode *parent;
	bool active_held;
	bool module_held;
	bool dops_detached;
	bool was_retiring;
	int ret;

	mutex_lock(&suvfs_lock);
	if (!suvfs.enabled && !suvfs.retiring) {
		mutex_unlock(&suvfs_lock);
		return 0;
	}
	was_retiring = suvfs.retiring;
	parent = suvfs.parent_inode;
	template = suvfs.active_fop_template;
	if (!suvfs.sb ||
	    (!was_retiring && (!parent || !suvfs.parent_iop_installed ||
			       !suvfs.parent_fop_installed || !template)) ||
	    (!was_retiring &&
	     READ_ONCE(parent->i_op) != &suvfs.parent_shadow_iop) ||
	    (!was_retiring && READ_ONCE(parent->i_fop) !=
				  suvfs_parent_installed_fop(template)) ||
	    (was_retiring && suvfs.parent_iop_installed && parent &&
	     READ_ONCE(parent->i_op) != suvfs.orig_iop &&
	     READ_ONCE(parent->i_op) != &suvfs.parent_shadow_iop) ||
	    (was_retiring && suvfs.parent_fop_installed && parent && template &&
	     READ_ONCE(parent->i_fop) != template->orig_fop &&
	     READ_ONCE(parent->i_fop) !=
		 suvfs_parent_installed_fop(template)) ||
	    READ_ONCE(suvfs.sb->s_op) != &suvfs.shadow_sop ||
	    !suvfs_dops_owned_locked()) {
		mutex_unlock(&suvfs_lock);
		return -EBUSY;
	}
	WRITE_ONCE(suvfs.enabled, false);
	WRITE_ONCE(suvfs.retiring, true);
	spin_lock(&suvfs_sop_lock);
	suvfs.accepting_vnodes = false;
	spin_unlock(&suvfs_sop_lock);
	ret = suvfs.parent_iop_installed ? suvfs_detach_parent_iop(parent) : 0;
	if (ret) {
		if (!was_retiring)
			ret = suvfs_rollback_disable(parent);
		mutex_unlock(&suvfs_lock);
		return ret;
	}
	suvfs.parent_iop_installed = false;
	ret = suvfs.parent_fop_installed ? suvfs_detach_parent_fop(parent) : 0;
	if (ret) {
		if (!was_retiring)
			ret = suvfs_rollback_disable(parent);
		mutex_unlock(&suvfs_lock);
		return ret;
	}
	suvfs.parent_fop_installed = false;
	dops_detached = suvfs_detach_all_dops_locked(&retired);
	sb = suvfs.sb;
	mutex_unlock(&suvfs_lock);

	suvfs_drain_retired_dops(&retired, true);
	flush_delayed_work(&suvfs_reap_dops_work);
	if (!dops_detached) {
		pr_err("kasumi_sucompat: dentry op stack changed during "
		       "disable\n");
		return -EBUSY;
	}
	suvfs_drop_cached_su(parent);
	suvfs_shrink_dcache_sb(sb);
	wait_event_timeout(suvfs_wait,
			   !atomic_read(&suvfs.vnode_live) &&
			       !atomic_read(&suvfs.synth_dentry_live),
			   HZ);

	mutex_lock(&suvfs_lock);
	if (atomic_read(&suvfs.vnode_live) ||
	    atomic_read(&suvfs.synth_dentry_live)) {
		ret = was_retiring ? -EBUSY : suvfs_rollback_disable(parent);
		mutex_unlock(&suvfs_lock);
		pr_warn(
		    "kasumi_sucompat: live vnode/dentry refs block disable\n");
		return ret;
	}
	ret = suvfs_restore_sop();
	if (ret) {
		mutex_unlock(&suvfs_lock);
		pr_err("kasumi_sucompat: op stack changed during disable\n");
		return ret;
	}

	active_held = suvfs.s_active_held;
	module_held = suvfs.module_pin_held;
	suvfs.s_active_held = false;
	suvfs.module_pin_held = false;
	suvfs.parent_inode = NULL;
	suvfs.parent_iop_installed = false;
	suvfs.parent_fop_installed = false;
	suvfs.active_fop_template = NULL;
	suvfs.orig_iop = NULL;
	suvfs.orig_sop = NULL;
	suvfs.sb = NULL;
	suvfs.marker_ino = 0;
	WRITE_ONCE(suvfs.retiring, false);
	mutex_unlock(&suvfs_lock);

	if (parent)
		iput(parent);
	if (active_held)
		deactivate_super(sb);
	if (module_held)
		module_put(THIS_MODULE);
	pr_info("kasumi_sucompat: VFS provider disabled\n");
	return 0;
}

int ksu_sucompat_vfs_set_enabled(bool enabled)
{
	int ret;

	mutex_lock(&suvfs_transition_lock);
	if (enabled) {
		ret = ksu_sucompat_module_guard_acquire();
		if (ret)
			goto out;
	}
	ret = enabled ? suvfs_enable() : suvfs_disable();
	if (!ksu_sucompat_vfs_active())
		ksu_sucompat_module_guard_release();
out:
	mutex_unlock(&suvfs_transition_lock);
	return ret;
}

int ksu_sucompat_vfs_init(void)
{
	int ret;

	if (READ_ONCE(suvfs.ready))
		return 0;
	suvfs_synchronize_rcu_tasks_ptr =
	    (void *)ksu_lookup_symbol("synchronize_rcu_tasks");
	suvfs_d_lookup_ptr = (void *)ksu_lookup_symbol("d_lookup");
	suvfs_shrink_dcache_sb_ptr =
	    (void *)ksu_lookup_symbol("shrink_dcache_sb");
	suvfs_free_inode_nonrcu_ptr =
	    (void *)ksu_lookup_symbol("free_inode_nonrcu");
	suvfs_module_address_ptr =
	    (void *)ksu_lookup_symbol("__module_address");
	if (!suvfs_synchronize_rcu_tasks_ptr || !suvfs_d_lookup_ptr ||
	    !suvfs_shrink_dcache_sb_ptr || !suvfs_module_address_ptr)
		return -EOPNOTSUPP;
	hash_init(suvfs_fops_by_orig);
	hash_init(suvfs_fops_by_ingress);
	hash_init(suvfs_synth_dops);
	ret = ksu_sucompat_module_guard_init();
	if (ret)
		return ret;
	ret = suvfs_fop_bridge_init();
	if (ret) {
		ksu_sucompat_module_guard_exit();
		return ret;
	}

	hash_init(suvfs_dops);
	INIT_LIST_HEAD(&suvfs_dop_list);
	atomic_set(&suvfs.sop_callbacks, 0);
	atomic_set(&suvfs.vnode_live, 0);
	atomic_set(&suvfs.synth_dentry_live, 0);
	WRITE_ONCE(suvfs.prompt_enabled, false);
	WRITE_ONCE(suvfs.ready, true);
	return 0;
}

void ksu_sucompat_vfs_exit(void)
{
	int ret;

	WRITE_ONCE(suvfs.ready, false);
	ret = ksu_sucompat_vfs_set_enabled(false);
	flush_delayed_work(&suvfs_reap_dops_work);
	if (!ret) {
		suvfs_fop_bridge_exit();
		suvfs_free_fop_templates();
		suvfs_free_synth_dop_templates();
		mutex_lock(&suvfs_lock);
		WRITE_ONCE(suvfs.prompt_enabled, false);
		suvfs.active_fop_template = NULL;
		mutex_unlock(&suvfs_lock);
		ksu_sucompat_module_guard_exit();
	}
	WARN_ON_ONCE(ret || suvfs.enabled || suvfs.retiring || suvfs.sb ||
		     suvfs.parent_fop_installed || suvfs.active_fop_template ||
		     atomic_read(&suvfs.sop_callbacks) ||
		     atomic_read(&suvfs.vnode_live) ||
		     atomic_read(&suvfs.synth_dentry_live));
}
