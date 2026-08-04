#pragma once

#include <string>
#include <vector>

namespace ksud {

int yzctl_main(int argc, char** argv);
int yzctl_run(const std::vector<std::string>& args);

}  // namespace ksud
