#ifndef _KASUMI_FAKE_MOUNTINFO_H
#define _KASUMI_FAKE_MOUNTINFO_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/uio.h>

struct path;
struct mnt_namespace;

int kasumi_fake_mi_init(void);
void kasumi_fake_mi_exit(void);
bool kasumi_fake_mi_active(void);
int kasumi_fake_mi_classify_mount(const char *line, size_t len, bool *hidden);

/* Resolve translation, visibility, and the hidden mount root's projected
 * mount-root state from one namespace+root-keyed RCU-stable cache generation.
 */
int kasumi_fake_mi_mount_id_state_cached(u64 real_id, int *fake_id,
					 bool *hidden,
					 bool *projected_mount_root);

void kasumi_fake_mi_invalidate_all(void);
u64 kasumi_fake_mi_generation(void);
void kasumi_fake_mi_poll_wait(struct file *file,
			      struct poll_table_struct *wait);
void kasumi_fake_mi_poll_wake(void);

/* Whole-file transforms for an open-bound proc mount snapshot.  The visible
 * variant also records one visibility bit per raw mount-list ordinal so the
 * sibling mounts rendering can be filtered without collapsing stacked mounts
 * that share a mountpoint. */
int kasumi_fake_mi_build_from_raw_visible(
    const char *raw, size_t raw_len, char *out, size_t out_cap, size_t *out_len,
    unsigned long *visible_bitmap, size_t visible_bits, size_t *raw_line_count);
/* If @ns/@root are the current task's exact open-bound view, publish the
 * supplied transform as the statx/statfs cache after verifying it byte-for-byte
 * against an id-map-producing rebuild. Other target views are ignored. When a
 * cache commit occurs, @published_generation receives that exact generation;
 * it remains zero for an ignored target view.
 */
int kasumi_fake_mi_publish_current_snapshot(const char *raw, size_t raw_len,
					    const char *fake, size_t fake_len,
					    struct mnt_namespace *ns,
					    const struct path *root,
					    u64 *published_generation);
#endif /* _KASUMI_FAKE_MOUNTINFO_H */
