#include "internal.h"

void ksu_yukizygisk_init(void)
{
	yz_exec_init();
	yz_events_init();
	yz_lifecycle_init();
	yz_fd_handoff_init();
}

void ksu_yukizygisk_exit(void)
{
	yz_exec_exit();
	yz_lifecycle_exit();
	yz_events_exit();
	yz_fd_handoff_exit();
}
