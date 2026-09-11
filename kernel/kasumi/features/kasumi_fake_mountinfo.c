#include "infra/mount_policy.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_entrypoints.h"
#include "kasumi_runtime.h"

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/nsproxy.h>
#include <linux/fs_struct.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/version.h>
#include <linux/bitops.h>

/* Match the per-open proc proxy ceiling so a large but accepted mount table
 * can also supply the statx/statfs identity cache from the exact same bytes. */
#define FAKE_MI_BUF_MAX (1024 * 1024)
#define FAKE_MI_SCRATCH FAKE_MI_BUF_MAX
#define FAKE_MI_BUF_SLOTS 2
#define MAX_MOUNTS 4096

struct fake_mi_id_entry {
	int real_id;
	int fake_id;
	bool visible;
	bool projected_mount_root;
};

struct fake_mi_cache {
	char *scratch;
	struct {
		struct nsproxy *nsproxy;
		struct mnt_namespace *mnt_ns;
		struct path root;
		u64 generation;
		u64 mount_policy_generation;
		struct fake_mi_id_entry *id_map;
		int id_count;
	} slots[FAKE_MI_BUF_SLOTS];
	int active_slot;
	bool valid;
	struct mutex lock;
};

static struct fake_mi_cache g_cache = {
    .active_slot = 0,
    .valid = false,
};

static bool fake_mi_initialized;

static u64 g_cache_gen;
static atomic64_t fake_mi_view_gen = ATOMIC64_INIT(1);
static DECLARE_WAIT_QUEUE_HEAD(fake_mi_view_wait);

/* Symbols resolved via kallsyms at init. */
static void (*ptr_free_nsproxy)(struct nsproxy *);

static struct mnt_namespace *fake_mi_current_mnt_ns(void)
{
	struct nsproxy *nsproxy = current->nsproxy;

	return nsproxy ? nsproxy->mnt_ns : NULL;
}

/* put_nsproxy() calls the non-exported free_nsproxy() on the final reference.
 * Keep the inline refcount operation here and call its kallsyms-resolved body
 * without adding an exported-symbol dependency.
 */
static KASUMI_NOCFI void fake_mi_put_nsproxy(struct nsproxy *nsproxy)
{
	bool release;

	if (!nsproxy)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	release = refcount_dec_and_test(&nsproxy->count);
#else
	release = atomic_dec_and_test(&nsproxy->count);
#endif
	if (release)
		ptr_free_nsproxy(nsproxy);
}

static void fake_mi_release_slot_owner_locked(int slot)
{
	struct nsproxy *nsproxy;
	struct path root;

	if (slot < 0 || slot >= FAKE_MI_BUF_SLOTS)
		return;

	nsproxy = g_cache.slots[slot].nsproxy;
	root = g_cache.slots[slot].root;
	g_cache.slots[slot].nsproxy = NULL;
	g_cache.slots[slot].mnt_ns = NULL;
	g_cache.slots[slot].root.mnt = NULL;
	g_cache.slots[slot].root.dentry = NULL;
	g_cache.slots[slot].generation = 0;
	if (root.mnt && root.dentry)
		path_put(&root);
	fake_mi_put_nsproxy(nsproxy);
}

static bool fake_mi_root_matches_current(const struct path *root)
{
	struct fs_struct *fs = current->fs;
	struct path current_root;
	bool matches;

	if (!fs || !root || !root->mnt || !root->dentry)
		return false;
	get_fs_root(fs, &current_root);
	matches = path_equal(&current_root, root);
	path_put(&current_root);
	return matches;
}

/* Cache generations bind legacy cursors to a particular slot publication.
 * They are intentionally separate from the poll-visible view generation:
 * refreshing identical bytes or another namespace's cache is not a procfs
 * mount-change event. Both counters are serialized by g_cache.lock.
 */
static u64 fake_mi_advance_cache_generation_locked(void)
{
	return ++g_cache_gen;
}

static void fake_mi_advance_view_generation_locked(void)
{
	atomic64_inc(&fake_mi_view_gen);
	wake_up_all(&fake_mi_view_wait);
}

/* Active-slot owners, including the root path, are retained until the slot is
 * inactive and a grace period has elapsed. This identity check is therefore
 * safe in the atomic cache consumers while they hold rcu_read_lock().
 */
static bool fake_mi_slot_matches_current(int slot)
{
	struct mnt_namespace *mnt_ns;
	struct path root;

	if (slot < 0 || slot >= FAKE_MI_BUF_SLOTS)
		return false;
	mnt_ns = fake_mi_current_mnt_ns();
	if (!mnt_ns || READ_ONCE(g_cache.slots[slot].mnt_ns) != mnt_ns)
		return false;
	root.mnt = READ_ONCE(g_cache.slots[slot].root.mnt);
	root.dentry = READ_ONCE(g_cache.slots[slot].root.dentry);
	return fake_mi_root_matches_current(&root);
}

/* ------------------------------------------------------------------ */
/* Line parser                                                         */
/* ------------------------------------------------------------------ */

static inline bool is_digit(char c)
{
	return c >= '0' && c <= '9';
}

#define FAKE_MI_MAX_PROP_FIELDS 8

enum fake_mi_prop_kind {
	FAKE_MI_PROP_SHARED = 0,
	FAKE_MI_PROP_MASTER,
	FAKE_MI_PROP_PROPAGATE_FROM,
};

struct fake_mi_prop_ref {
	size_t value_start;
	size_t value_end;
	int old_id;
	enum fake_mi_prop_kind kind;
};

static bool parse_decimal_token(const char *line, size_t start, size_t end,
				int *out)
{
	long v;
	char tmp[32];
	size_t len;

	if (!out || start >= end)
		return false;

	len = end - start;
	if (len >= sizeof(tmp))
		return false;

	memcpy(tmp, line + start, len);
	tmp[len] = 0;
	if (kstrtol(tmp, 10, &v))
		return false;

	*out = (int)v;
	return true;
}

static bool token_has_prefix(const char *line, size_t start, size_t end,
			     const char *prefix)
{
	size_t plen = strlen(prefix);

	return end >= start + plen && memcmp(line + start, prefix, plen) == 0;
}

/*
 * Parse one mountinfo line and extract:
 *   - mnt_id / parent_id
 *   - root-owned mounts identified by source, mount root, or mountpoint
 *   - propagation-group numeric suffixes inside optional fields
 *
 * The returned byte ranges let us rewrite only the numeric pieces while
 * keeping the rest of the kernel-generated line byte-for-byte intact.
 *
 * mountinfo format:
 *   <mnt_id> <parent_id> <major:minor> <root> <mp> <opts> <optional_fields> -
 * <fstype> <source> <sb_opts>
 */
static bool parse_line(const char *line, size_t len, int *mnt_id,
		       int *parent_id, size_t *mi_start, size_t *mi_end,
		       size_t *pi_start, size_t *pi_end,
		       struct fake_mi_prop_ref *prop_refs, size_t *prop_count,
		       bool *is_hidden, bool *is_namespace_root,
		       size_t *mountpoint_start_out, size_t *mountpoint_end_out)
{
	size_t i = 0, token_start, token_end;
	size_t mount_root_start = 0, mount_root_end = 0;
	size_t mountpoint_start = 0, mountpoint_end = 0;
	size_t j;
	struct ksu_mount_fields fields = {.escaped = true};

	*is_hidden = false;
	*is_namespace_root = false;
	if (prop_count)
		*prop_count = 0;

	/* mnt_id */
	*mi_start = i;
	while (i < len && is_digit(line[i]))
		i++;
	if (i == *mi_start || i >= len || line[i] != ' ')
		return false;
	*mi_end = i;
	if (!parse_decimal_token(line, *mi_start, *mi_end, mnt_id))
		return false;
	i++;

	/* parent_id */
	*pi_start = i;
	while (i < len && is_digit(line[i]))
		i++;
	if (i == *pi_start || i >= len || line[i] != ' ')
		return false;
	*pi_end = i;
	if (!parse_decimal_token(line, *pi_start, *pi_end, parent_id))
		return false;
	i++;

	/* Parse major:minor, root, mountpoint, mount opts. A self-parent entry
	 * is only a legitimate graph terminator when it is mounted at namespace
	 * /.
	 */
	for (j = 0; j < 4; j++) {
		token_start = i;
		while (i < len && line[i] != ' ')
			i++;
		token_end = i;
		if (token_start == token_end || i >= len || line[i] != ' ')
			return false;
		i++;
		if (j == 0)
			fields.dev = (struct ksu_mount_field){
			    line + token_start, token_end - token_start};
		if (j == 1) {
			mount_root_start = token_start;
			mount_root_end = token_end;
		} else if (j == 2) {
			mountpoint_start = token_start;
			mountpoint_end = token_end;
		}
		if (j == 2 && token_end == token_start + 1 &&
		    line[token_start] == '/')
			*is_namespace_root = true;
	}

	fields.root = (struct ksu_mount_field){
	    line + mount_root_start, mount_root_end - mount_root_start};
	fields.target = (struct ksu_mount_field){
	    line + mountpoint_start, mountpoint_end - mountpoint_start};
	if (mountpoint_start_out)
		*mountpoint_start_out = mountpoint_start;
	if (mountpoint_end_out)
		*mountpoint_end_out = mountpoint_end;

	while (i < len) {
		int value;

		token_start = i;
		while (i < len && line[i] != ' ')
			i++;
		token_end = i;
		if (token_start == token_end)
			return false;

		if (token_end == token_start + 1 && line[token_start] == '-') {
			if (i < len && line[i] == ' ')
				i++;
			break;
		}

		if (prop_refs && prop_count &&
		    *prop_count < FAKE_MI_MAX_PROP_FIELDS) {
			size_t value_start = 0;
			const char *prefix = NULL;
			enum fake_mi_prop_kind kind = FAKE_MI_PROP_SHARED;

			if (token_has_prefix(line, token_start, token_end,
					     "shared:")) {
				prefix = "shared:";
			} else if (token_has_prefix(line, token_start,
						    token_end, "master:")) {
				prefix = "master:";
				kind = FAKE_MI_PROP_MASTER;
			} else if (token_has_prefix(line, token_start,
						    token_end,
						    "propagate_from:")) {
				prefix = "propagate_from:";
				kind = FAKE_MI_PROP_PROPAGATE_FROM;
			}

			if (prefix) {
				value_start = token_start + strlen(prefix);
				if (value_start < token_end &&
				    parse_decimal_token(line, value_start,
							token_end, &value)) {
					prop_refs[*prop_count].value_start =
					    value_start;
					prop_refs[*prop_count].value_end =
					    token_end;
					prop_refs[*prop_count].old_id = value;
					prop_refs[*prop_count].kind = kind;
					(*prop_count)++;
				}
			}
		}

		if (i < len && line[i] == ' ')
			i++;
	}

	/* Keep field slices intact for the mount-ID rewrite. */
	token_start = i;
	while (i < len && line[i] != ' ')
		i++;
	if (i == token_start || i == len)
		return false;
	fields.fstype =
	    (struct ksu_mount_field){line + token_start, i - token_start};
	i++;

	/* source */
	token_start = i;
	while (i < len && line[i] != ' ')
		i++;
	token_end = i;
	if (token_start == token_end)
		return false;
	fields.source = (struct ksu_mount_field){line + token_start,
						 token_end - token_start};
	while (i < len && line[i] == ' ')
		i++;
	fields.super = (struct ksu_mount_field){line + i, len - i};
	*is_hidden = ksu_mount_is_module(&fields);

	return true;
}

int kasumi_fake_mi_classify_mount(const char *line, size_t len, bool *hidden)
{
	int mount_id, parent_id;
	u64 policy_generation = ksu_mount_policy_generation();

	if (policy_generation & 1)
		return -EAGAIN;
	size_t mi_start, mi_end, pi_start, pi_end;
	bool namespace_root;

	if (!line || !hidden ||
	    !parse_line(line, len, &mount_id, &parent_id, &mi_start, &mi_end,
			&pi_start, &pi_end, NULL, NULL, hidden, &namespace_root,
			NULL, NULL))
		return -EINVAL;
	return policy_generation == ksu_mount_policy_generation() ? 0 : -EAGAIN;
}

/* ------------------------------------------------------------------ */
/* Cache regeneration                                                  */
/* ------------------------------------------------------------------ */

#define MAX_PROP_IDS (MAX_MOUNTS * FAKE_MI_MAX_PROP_FIELDS)

struct id_map_entry {
	int old_id;
	int new_id;
};

struct mount_map_entry {
	int old_id;
	int parent_id;
	int new_id;
	int resolved_parent_id;
	size_t mountpoint_start;
	size_t mountpoint_len;
	unsigned int walk_cookie;
	bool graph_validated;
	bool namespace_root;
};

static int map_lookup(const struct id_map_entry *map, int nmap, int old_id)
{
	int i;

	for (i = 0; i < nmap; i++) {
		if (map[i].old_id == old_id)
			return map[i].new_id;
	}
	return -1;
}

static int map_add_if_missing(struct id_map_entry *map, int *nmap,
			      int max_entries, int old_id, int *next_id)
{
	if (!map || !nmap || !next_id || old_id <= 0)
		return -EINVAL;
	if (map_lookup(map, *nmap, old_id) >= 0)
		return 0;
	if (*nmap >= max_entries)
		return -E2BIG;

	map[*nmap].old_id = old_id;
	map[*nmap].new_id = (*next_id)++;
	(*nmap)++;
	return 0;
}

static int mount_map_lookup(const struct mount_map_entry *map, int nmap,
			    int old_id)
{
	int i;

	for (i = 0; i < nmap; i++) {
		if (map[i].old_id == old_id)
			return i;
	}
	return -1;
}

static int mount_map_lookup_new_id(const struct mount_map_entry *map, int nmap,
				   int new_id)
{
	int i;

	for (i = 0; i < nmap; i++) {
		if (map[i].new_id == new_id)
			return i;
	}
	return -1;
}

static int mount_map_add(struct mount_map_entry *map, int *nmap, int old_id,
			 int parent_id, bool visible, bool namespace_root,
			 size_t mountpoint_start, size_t mountpoint_len,
			 int *next_id)
{
	if (!map || !nmap || !next_id || old_id <= 0 || parent_id <= 0)
		return -EINVAL;
	if (mount_map_lookup(map, *nmap, old_id) >= 0)
		return -EEXIST;
	if (*nmap >= MAX_MOUNTS)
		return -E2BIG;

	map[*nmap].old_id = old_id;
	map[*nmap].parent_id = parent_id;
	map[*nmap].new_id = visible ? (*next_id)++ : -1;
	map[*nmap].resolved_parent_id = 0;
	map[*nmap].mountpoint_start = mountpoint_start;
	map[*nmap].mountpoint_len = mountpoint_len;
	map[*nmap].walk_cookie = 0;
	map[*nmap].graph_validated = false;
	map[*nmap].namespace_root = namespace_root;
	(*nmap)++;
	return 0;
}

static int mount_map_validate_graph(struct mount_map_entry *map, int nmap)
{
	unsigned int cookie = 0;
	int i;

	for (i = 0; i < nmap; i++) {
		int node_idx = i;
		int hops;
		int j;

		if (map[i].graph_validated)
			continue;
		cookie++;
		for (hops = 0; hops <= nmap; hops++) {
			int parent;

			if (map[node_idx].graph_validated)
				break;
			if (map[node_idx].walk_cookie == cookie)
				return -ELOOP;
			map[node_idx].walk_cookie = cookie;
			if (map[node_idx].old_id == map[node_idx].parent_id) {
				if (!map[node_idx].namespace_root)
					return -ELOOP;
				break;
			}
			parent = mount_map_lookup(map, nmap,
						  map[node_idx].parent_id);
			if (parent < 0)
				break;
			node_idx = parent;
		}
		if (hops > nmap)
			return -ELOOP;
		for (j = 0; j < nmap; j++) {
			if (map[j].walk_cookie == cookie)
				map[j].graph_validated = true;
		}
	}

	for (i = 0; i < nmap; i++)
		map[i].walk_cookie = 0;
	return 0;
}

static int mount_map_resolve_parent(struct mount_map_entry *map, int nmap,
				    const struct id_map_entry *external_map,
				    int n_external, int old_parent_id,
				    unsigned int walk_cookie, int *resolved)
{
	int current_id = old_parent_id;
	int result = -1;
	int hops;

	if (!resolved)
		return -EINVAL;

	for (hops = 0; hops <= nmap; hops++) {
		int idx = mount_map_lookup(map, nmap, current_id);

		/* A parent outside the visible mountinfo root has no line of
		 * its own. */
		if (idx < 0) {
			result =
			    map_lookup(external_map, n_external, current_id);
			if (result < 0)
				return -ENOENT;
			break;
		}
		if (map[idx].new_id > 0) {
			result = map[idx].new_id;
			break;
		}
		if (map[idx].resolved_parent_id > 0) {
			result = map[idx].resolved_parent_id;
			break;
		}

		/* A mount tree cannot contain a parent cycle. Reject malformed
		 * input. */
		if (map[idx].walk_cookie == walk_cookie)
			return -ELOOP;

		map[idx].walk_cookie = walk_cookie;
		current_id = map[idx].parent_id;
	}

	if (result < 0)
		return -ELOOP;

	/* Cache the resolved visible/external ancestor on every hidden node in
	 * this walk. Shared hidden chains are then resolved once rather than
	 * once per visible child.
	 */
	current_id = old_parent_id;
	for (hops = 0; hops <= nmap; hops++) {
		int idx = mount_map_lookup(map, nmap, current_id);

		if (idx < 0 || map[idx].new_id > 0 ||
		    map[idx].resolved_parent_id > 0 ||
		    map[idx].walk_cookie != walk_cookie)
			break;
		map[idx].resolved_parent_id = result;
		current_id = map[idx].parent_id;
	}

	*resolved = result;
	return 0;
}

static size_t decimal_len(int value)
{
	char buf[16];

	return scnprintf(buf, sizeof(buf), "%d", value);
}

/* Build the new mountinfo buffer from the current hidden task's real
 * /proc/self/mountinfo view. If userspace namespace hiding has already removed
 * module mounts, use that view as the base; then drop remaining root-owned
 * lines and compact mount ids. Normal mode preserves propagation semantics;
 * aggressive mode additionally projects a global shared root as private.
 */
static int build_fake_buffer(const char *raw, size_t raw_len, char *out,
			     size_t out_cap, size_t *out_len,
			     struct fake_mi_id_entry *id_map, int *id_count,
			     unsigned long *visible_bitmap, size_t visible_bits,
			     size_t *raw_line_count)
{
	struct mount_map_entry *mount_map;
	struct id_map_entry *prop_map;
	struct id_map_entry *external_map;
	int n_mount_map = 0;
	int n_prop_map = 0;
	int n_external = 0;
	int next_mount_id = 1;
	int next_prop_id = 1;
	unsigned int parent_walk_cookie = 1;
	bool aggressive =
	    READ_ONCE(kasumi_mount_hide_mode) == KSM_MOUNT_HIDE_MODE_AGGRESSIVE;
	int i;
	int ret = 0;
	size_t in = 0, o = 0;
	size_t ordinal = 0;

	mount_map = kvmalloc_array(MAX_MOUNTS, sizeof(*mount_map), GFP_KERNEL);
	if (!mount_map)
		return -ENOMEM;

	prop_map = kvmalloc_array(MAX_PROP_IDS, sizeof(*prop_map), GFP_KERNEL);
	if (!prop_map) {
		kvfree(mount_map);
		return -ENOMEM;
	}
	external_map =
	    kvmalloc_array(MAX_MOUNTS, sizeof(*external_map), GFP_KERNEL);
	if (!external_map) {
		kvfree(prop_map);
		kvfree(mount_map);
		return -ENOMEM;
	}

	/* Pass 1: retain the complete parent graph and assign compact ids only
	 * to visible lines in original order.
	 */
	in = 0;
	while (in < raw_len) {
		size_t ls = in;
		int mi, pi;
		size_t ms, me, ps, pe;
		struct fake_mi_prop_ref prop_refs[FAKE_MI_MAX_PROP_FIELDS];
		size_t prop_count = 0;
		bool hidden;
		bool namespace_root;
		size_t mountpoint_start;
		size_t mountpoint_end;
		size_t j;

		while (in < raw_len && raw[in] != '\n')
			in++;
		if (!parse_line(raw + ls, in - ls, &mi, &pi, &ms, &me, &ps, &pe,
				prop_refs, &prop_count, &hidden,
				&namespace_root, &mountpoint_start,
				&mountpoint_end)) {
			ret = -EINVAL;
			goto out;
		}
		if (visible_bitmap) {
			if (ordinal >= visible_bits) {
				ret = -ENOSPC;
				goto out;
			}
			if (!hidden)
				__set_bit(ordinal, visible_bitmap);
			else
				__clear_bit(ordinal, visible_bitmap);
		}
		ordinal++;
		ret = mount_map_add(mount_map, &n_mount_map, mi, pi, !hidden,
				    namespace_root, ls + mountpoint_start,
				    mountpoint_end - mountpoint_start,
				    &next_mount_id);
		if (ret)
			goto out;
		if (!hidden) {
			for (j = 0; j < prop_count; j++) {
				ret = map_add_if_missing(
				    prop_map, &n_prop_map, MAX_PROP_IDS,
				    prop_refs[j].old_id, &next_prop_id);
				if (ret)
					goto out;
			}
		}
		if (in < raw_len)
			in++;
	}

	ret = mount_map_validate_graph(mount_map, n_mount_map);
	if (ret)
		goto out;

	/* Compact external parents after all visible IDs so a namespace-root
	 * parent cannot collide with any emitted mount ID.
	 */
	for (i = 0; i < n_mount_map; i++) {
		if (mount_map_lookup(mount_map, n_mount_map,
				     mount_map[i].parent_id) >= 0)
			continue;
		ret =
		    map_add_if_missing(external_map, &n_external, MAX_MOUNTS,
				       mount_map[i].parent_id, &next_mount_id);
		if (ret)
			goto out;
	}

	/* Pass 2: rewrite. */
	in = 0;
	while (in < raw_len) {
		size_t ls = in;
		int mi, pi;
		size_t ms, me, ps, pe;
		struct fake_mi_prop_ref prop_refs[FAKE_MI_MAX_PROP_FIELDS];
		size_t prop_count = 0;
		bool hidden;
		bool namespace_root;
		bool project_root_shared = false;
		size_t line_len;
		int new_mi, new_pi;
		size_t cursor;
		int n;
		size_t j;

		while (in < raw_len && raw[in] != '\n')
			in++;
		line_len = in - ls;

		if (!parse_line(raw + ls, line_len, &mi, &pi, &ms, &me, &ps,
				&pe, prop_refs, &prop_count, &hidden,
				&namespace_root, NULL, NULL)) {
			ret = -EINVAL;
			goto out;
		}
		if (hidden) {
			if (in < raw_len)
				in++;
			continue;
		}

		n = mount_map_lookup(mount_map, n_mount_map, mi);
		if (n < 0 || mount_map[n].new_id <= 0) {
			ret = -ENOENT;
			goto out;
		}
		new_mi = mount_map[n].new_id;
		parent_walk_cookie++;
		ret = mount_map_resolve_parent(mount_map, n_mount_map,
					       external_map, n_external, pi,
					       parent_walk_cookie, &new_pi);
		if (ret)
			goto out;

		{
			size_t rewritten_len = line_len - (me - ms) -
					       (pe - ps) + decimal_len(new_mi) +
					       decimal_len(new_pi);

			for (j = 0; j < prop_count; j++) {
				int new_prop = map_lookup(prop_map, n_prop_map,
							  prop_refs[j].old_id);

				if (new_prop < 0) {
					ret = -ENOENT;
					goto out;
				}
				rewritten_len -= prop_refs[j].value_end -
						 prop_refs[j].value_start;
				rewritten_len += decimal_len(new_prop);
			}
			if (in < raw_len)
				rewritten_len++;
			if (rewritten_len > out_cap - o) {
				ret = -ENOSPC;
				goto out;
			}
		}

		if (aggressive && namespace_root) {
			bool has_shared = false;
			bool has_master = false;

			for (j = 0; j < prop_count; j++) {
				if (prop_refs[j].kind == FAKE_MI_PROP_SHARED)
					has_shared = true;
				else if (prop_refs[j].kind ==
					 FAKE_MI_PROP_MASTER)
					has_master = true;
			}
			project_root_shared = has_shared && !has_master;
		}

		n = scnprintf(out + o, out_cap - o, "%d", new_mi);
		o += n;
		memcpy(out + o, raw + ls + me, ps - me);
		o += ps - me;
		n = scnprintf(out + o, out_cap - o, "%d", new_pi);
		o += n;
		cursor = pe;

		for (j = 0; j < prop_count; j++) {
			int new_prop = map_lookup(prop_map, n_prop_map,
						  prop_refs[j].old_id);
			size_t segment_len;

			if (new_prop < 0) {
				ret = -ENOENT;
				goto out;
			}
			segment_len = prop_refs[j].value_start - cursor;
			memcpy(out + o, raw + ls + cursor, segment_len);
			if (project_root_shared &&
			    prop_refs[j].kind == FAKE_MI_PROP_SHARED &&
			    segment_len >= sizeof("shared:") - 1)
				memcpy(out + o + segment_len -
					   (sizeof("shared:") - 1),
				       "master:", sizeof("master:") - 1);
			o += segment_len;
			n = scnprintf(out + o, out_cap - o, "%d", new_prop);
			o += n;
			cursor = prop_refs[j].value_end;
		}

		memcpy(out + o, raw + ls + cursor, line_len - cursor);
		o += line_len - cursor;

		if (in < raw_len) {
			out[o++] = '\n';
			in++;
		}
	}

	if (id_map && id_count) {
		*id_count = 0;
		for (i = 0; i < n_mount_map; i++) {
			int fake_id = mount_map[i].new_id;
			bool projected_mount_root = false;

			if (fake_id <= 0) {
				int ancestor;

				parent_walk_cookie++;
				ret = mount_map_resolve_parent(
				    mount_map, n_mount_map, external_map,
				    n_external, mount_map[i].parent_id,
				    parent_walk_cookie, &fake_id);
				if (ret)
					goto out;
				/* A path at the hidden mount's root is still a
				 * mount root in the projected view only when
				 * the visible ancestor begins at exactly the
				 * same namespace mountpoint. Mountinfo path
				 * tokens use the same escaping, so byte
				 * equality is canonical here.
				 */
				ancestor = mount_map_lookup_new_id(
				    mount_map, n_mount_map, fake_id);
				if (ancestor >= 0 &&
				    mount_map[i].mountpoint_len ==
					mount_map[ancestor].mountpoint_len &&
				    !memcmp(raw + mount_map[i].mountpoint_start,
					    raw + mount_map[ancestor]
						      .mountpoint_start,
					    mount_map[i].mountpoint_len))
					projected_mount_root = true;
			}
			id_map[*id_count].real_id = mount_map[i].old_id;
			id_map[*id_count].fake_id = fake_id;
			id_map[*id_count].visible = mount_map[i].new_id > 0;
			id_map[*id_count].projected_mount_root =
			    projected_mount_root;
			(*id_count)++;
		}
	}

	if (raw_line_count)
		*raw_line_count = ordinal;
	*out_len = o;
out:
	kvfree(external_map);
	kvfree(prop_map);
	kvfree(mount_map);
	return ret;
}

int kasumi_fake_mi_build_from_raw_visible(
    const char *raw, size_t raw_len, char *out, size_t out_cap, size_t *out_len,
    unsigned long *visible_bitmap, size_t visible_bits, size_t *raw_line_count)
{
	u64 policy_generation = ksu_mount_policy_generation();
	int ret;

	if (!visible_bitmap || !visible_bits || !raw_line_count)
		return -EINVAL;
	if (policy_generation & 1)
		return -EAGAIN;
	bitmap_zero(visible_bitmap, visible_bits);
	*raw_line_count = 0;
	ret = build_fake_buffer(raw, raw_len, out, out_cap, out_len, NULL, NULL,
				visible_bitmap, visible_bits, raw_line_count);
	return !ret && policy_generation != ksu_mount_policy_generation()
		   ? -EAGAIN
		   : ret;
}

static bool fake_mi_snapshot_matches_current(struct mnt_namespace *mnt_ns,
					     const struct path *root)
{
	if (!mnt_ns || !root || !root->dentry || !root->mnt ||
	    fake_mi_current_mnt_ns() != mnt_ns)
		return false;
	return fake_mi_root_matches_current(root);
}

int kasumi_fake_mi_publish_current_snapshot(const char *raw, size_t raw_len,
					    const char *fake, size_t fake_len,
					    struct mnt_namespace *mnt_ns,
					    const struct path *root,
					    u64 *published_generation)
{
	struct nsproxy *owner_nsproxy;
	struct path owner_root = {};
	char *new_buf;
	size_t rebuilt_len = 0;
	u64 generation;
	u64 policy_generation = ksu_mount_policy_generation();
	int id_count = 0;
	int new_slot;
	int ret = 0;

	if (published_generation)
		*published_generation = 0;
	if (!raw || !fake || !raw_len || !fake_len || !mnt_ns || !root)
		return -EINVAL;
	if (!READ_ONCE(fake_mi_initialized))
		return -EOPNOTSUPP;
	/* /proc/<other>/mountinfo may intentionally carry another root or mount
	 * namespace. It must never replace the current task's statx map. */
	if (!fake_mi_snapshot_matches_current(mnt_ns, root))
		return 0;

	owner_nsproxy = current->nsproxy;
	if (!owner_nsproxy || owner_nsproxy->mnt_ns != mnt_ns)
		return -EAGAIN;
	get_nsproxy(owner_nsproxy);
	owner_root = *root;
	path_get(&owner_root);

	mutex_lock(&g_cache.lock);
	new_slot = READ_ONCE(g_cache.active_slot) ^ 1;
	if (new_slot < 0 || new_slot >= FAKE_MI_BUF_SLOTS || !g_cache.scratch ||
	    !g_cache.slots[new_slot].id_map) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/* The inactive slot may still have atomic readers from its previous
	 * turn. */
	synchronize_rcu();
	fake_mi_release_slot_owner_locked(new_slot);
	new_buf = g_cache.scratch;
	ret = build_fake_buffer(raw, raw_len, new_buf, FAKE_MI_BUF_MAX,
				&rebuilt_len, g_cache.slots[new_slot].id_map,
				&id_count, NULL, 0, NULL);
	if (ret)
		goto out_unlock;
	/* A mode/config transition between the proxy transform and this rebuild
	 * changes the bytes. Ask the producer to retry instead of publishing an
	 * id map for a different view generation. */
	if ((policy_generation & 1) ||
	    policy_generation != ksu_mount_policy_generation() ||
	    rebuilt_len != fake_len || memcmp(new_buf, fake, fake_len)) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	/* A concurrent chroot in a shared fs_struct can move current away from
	 * the open-bound root while the rebuild sleeps. The snapshot is still
	 * valid for the proc fd, just not eligible for the current cache. */
	if (!fake_mi_snapshot_matches_current(mnt_ns, root)) {
		ret = 0;
		goto out_unlock;
	}

	WRITE_ONCE(g_cache.slots[new_slot].mount_policy_generation,
		   policy_generation);
	WRITE_ONCE(g_cache.slots[new_slot].id_count, id_count);
	g_cache.slots[new_slot].nsproxy = owner_nsproxy;
	g_cache.slots[new_slot].mnt_ns = owner_nsproxy->mnt_ns;
	g_cache.slots[new_slot].root = owner_root;
	owner_nsproxy = NULL;
	owner_root.mnt = NULL;
	owner_root.dentry = NULL;
	smp_store_release(&g_cache.active_slot, new_slot);
	smp_store_release(&g_cache.valid, true);
	generation = fake_mi_advance_cache_generation_locked();
	WRITE_ONCE(g_cache.slots[new_slot].generation, generation);
	if (published_generation)
		*published_generation =
		    (u64)atomic64_read(&fake_mi_view_gen) + policy_generation;
	kasumi_log("fake_mi: published open snapshot raw_len=%zu fake_len=%zu "
		   "gen=%llu\n",
		   raw_len, fake_len, (unsigned long long)generation);

out_unlock:
	mutex_unlock(&g_cache.lock);
	if (owner_root.mnt && owner_root.dentry)
		path_put(&owner_root);
	fake_mi_put_nsproxy(owner_nsproxy);
	return ret;
}

void kasumi_fake_mi_invalidate_all(void)
{
	int i;

	mutex_lock(&g_cache.lock);
	smp_store_release(&g_cache.valid, false);
	fake_mi_advance_view_generation_locked();
	synchronize_rcu();
	for (i = 0; i < FAKE_MI_BUF_SLOTS; i++)
		fake_mi_release_slot_owner_locked(i);
	mutex_unlock(&g_cache.lock);
}

u64 kasumi_fake_mi_generation(void)
{
	return (u64)atomic64_read(&fake_mi_view_gen) +
	       ksu_mount_policy_generation();
}

void kasumi_fake_mi_poll_wait(struct file *file, struct poll_table_struct *wait)
{
	if (file && wait)
		poll_wait(file, &fake_mi_view_wait, wait);
	if (file && wait)
		ksu_mount_policy_poll(file, wait);
}

void kasumi_fake_mi_poll_wake(void)
{
	wake_up_all(&fake_mi_view_wait);
}

int kasumi_fake_mi_mount_id_state_cached(u64 real_id, int *fake_id,
					 bool *hidden,
					 bool *projected_mount_root)
{
	const struct fake_mi_id_entry *id_map;
	int id_count;
	int slot;
	int ret = -ENOENT;
	int i;

	if (!fake_id || !hidden || !projected_mount_root)
		return -EINVAL;
	*fake_id = 0;
	*hidden = false;
	*projected_mount_root = false;
	rcu_read_lock();
	if (!smp_load_acquire(&g_cache.valid)) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	slot = smp_load_acquire(&g_cache.active_slot);
	if (slot < 0 || slot >= FAKE_MI_BUF_SLOTS) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	if (READ_ONCE(g_cache.slots[slot].mount_policy_generation) !=
		ksu_mount_policy_generation() ||
	    !fake_mi_slot_matches_current(slot)) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	id_map = READ_ONCE(g_cache.slots[slot].id_map);
	id_count = READ_ONCE(g_cache.slots[slot].id_count);
	for (i = 0; id_map && i < id_count; i++) {
		if ((u64)id_map[i].real_id == real_id) {
			*fake_id = id_map[i].fake_id;
			*hidden = !id_map[i].visible;
			*projected_mount_root = id_map[i].projected_mount_root;
			ret = 0;
			break;
		}
	}

out_unlock:
	rcu_read_unlock();
	return ret;
}

/* ------------------------------------------------------------------ */
/* Init / exit                                                         */
/* ------------------------------------------------------------------ */

int kasumi_fake_mi_init(void)
{
	int i;

	mutex_init(&g_cache.lock);
	g_cache_gen = 0;
	atomic64_set(&fake_mi_view_gen, 1);
	ptr_free_nsproxy = (void *)kasumi_lookup_callable("free_nsproxy");
	if (!ptr_free_nsproxy)
		return -ENOSYS;
	g_cache.scratch = vmalloc(FAKE_MI_BUF_MAX);
	if (!g_cache.scratch)
		return -ENOMEM;
	for (i = 0; i < FAKE_MI_BUF_SLOTS; i++) {
		g_cache.slots[i].id_map = kvmalloc_array(
		    MAX_MOUNTS, sizeof(*g_cache.slots[i].id_map), GFP_KERNEL);
		if (!g_cache.slots[i].id_map)
			goto fail;
	}
	g_cache.active_slot = 0;
	smp_store_release(&g_cache.valid, false);
	WRITE_ONCE(fake_mi_initialized, true);
	pr_info("kasumi: fake_mi: initialized (open-bound ID cache)\n");
	return 0;
fail:
	while (i-- > 0) {
		kvfree(g_cache.slots[i].id_map);
		g_cache.slots[i].id_map = NULL;
	}
	vfree(g_cache.scratch);
	g_cache.scratch = NULL;
	return -ENOMEM;
}

void kasumi_fake_mi_exit(void)
{
	int i;

	if (!READ_ONCE(fake_mi_initialized))
		return;
	WRITE_ONCE(fake_mi_initialized, false);
	kasumi_fake_mi_invalidate_all();
	mutex_lock(&g_cache.lock);
	for (i = 0; i < FAKE_MI_BUF_SLOTS; i++) {
		kvfree(g_cache.slots[i].id_map);
		g_cache.slots[i].id_map = NULL;
		g_cache.slots[i].id_count = 0;
	}
	vfree(g_cache.scratch);
	g_cache.scratch = NULL;
	mutex_unlock(&g_cache.lock);
}

bool kasumi_fake_mi_active(void)
{
	return READ_ONCE(fake_mi_initialized);
}
