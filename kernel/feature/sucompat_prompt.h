#ifndef __KSU_H_SUCOMPAT_PROMPT
#define __KSU_H_SUCOMPAT_PROMPT

#include <linux/types.h>

struct ksu_su_prompt_verdict;
struct ksu_su_prompt_key;

void ksu_sucompat_prompt_init(void);
void ksu_sucompat_prompt_exit(void);
bool ksu_sucompat_prompt_consumer_ready(void);
int ksu_sucompat_prompt_set_gate(bool enabled);
int ksu_sucompat_prompt_install_fd(void);
int ksu_sucompat_prompt_submit(const struct ksu_su_prompt_verdict *verdict);
int ksu_sucompat_prompt_ready(const struct ksu_su_prompt_key *key);
int ksu_sucompat_prompt_request(u32 *choice, u64 *generation);
bool ksu_sucompat_prompt_grant_valid(u64 generation);
void ksu_sucompat_prompt_cancel(int error);

#endif // __KSU_H_SUCOMPAT_PROMPT
