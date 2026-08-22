#pragma once

#include <set>
#include <string>
#include <vector>

namespace ksud {

int yzctl_main(int argc, char** argv);
int yzctl_run(const std::vector<std::string>& args);

// Whether the built-in YukiZygisk kernel feature is supported and turned on.
bool yz_feature_enabled();

// Whether a module directory ships a Zygisk shared object for an ABI YukiZygisk
// loads. `module list` shares this so its tag matches the runtime inventory.
bool yz_is_zygisk_module(const std::string& module_path);

// Whether a module directory declares native (ZN) modules.
bool yz_has_native_modules(const std::string& module_path);

// Module directory ids YukiZygisk currently has loaded: its Zygisk inventory plus
// the native modules the kernel reports as injected. Empty when the kernel
// runtime query fails.
std::set<std::string> yz_loaded_module_ids();

}  // namespace ksud
