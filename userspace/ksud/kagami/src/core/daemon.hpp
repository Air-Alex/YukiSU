#pragma once

#include <string>
#include <vector>

namespace kagami {

int run_daemon_command(const std::vector<std::string>& args);
int run_via_daemon(const std::vector<std::string>& args);

}  // namespace kagami
