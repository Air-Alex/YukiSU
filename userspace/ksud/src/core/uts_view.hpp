#pragma once

#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "uapi/uts_view.h"
}

namespace ksud {

int uts_view_command(const std::vector<std::string>& args);
int apply_uts_view_config();

// Returns false for an incomplete/broken supported implementation. When the
// extension is unsupported, returns true with supported=false so callers may
// safely use the effective release (spoofing cannot be active).
bool get_uts_view_original_release(std::string* release, bool* supported);

bool load_uts_boot_config(const std::string& path, ksu_uts_template* config, std::string* error);
std::vector<std::string> encode_uts_boot_module_params(const ksu_uts_template& config);

}  // namespace ksud
