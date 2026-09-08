#pragma once

namespace ksud {

int run_msud(int ready_fd = -1);

int ensure_msud_running_locked();

bool kill_msud_locked();

void ensure_msud_running_if_enabled();

int apply_magisk_compat_now();

}  // namespace ksud
