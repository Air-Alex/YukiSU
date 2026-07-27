#pragma once

namespace ksuinit {

/**
 * Initialize KernelSU
 *
 * This function:
 * 1. Sets up kernel logging via /dev/kmsg
 * 2. Mounts /proc temporarily
 * 3. Loads the KernelSU LKM module
 * 4. Sets up the symlink for the real init
 *
 * @return true on success, false on failure
 */
bool init();

}  // namespace ksuinit
