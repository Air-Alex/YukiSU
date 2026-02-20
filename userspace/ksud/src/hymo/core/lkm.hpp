#pragma once

namespace hymo {

// LKM management for HymoFS kernel module
bool lkm_load();
bool lkm_unload();
bool lkm_is_loaded();
bool lkm_set_autoload(bool on);
bool lkm_get_autoload();  // default true if file missing

// Called from post-fs-data: detect arch, extract embedded LKM, load, cleanup (no shell)
void lkm_autoload_post_fs_data();

}  // namespace hymo
