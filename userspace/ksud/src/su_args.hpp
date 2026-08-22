#pragma once

#include <optional>
#include <string>
#include <vector>

namespace ksud::su_args {

// Result of splitting a raw su command line into an option region and an optional positional
// command.
struct ParsedArgv {
    // argv[0], then every option (with its separate value), then the remaining operands.
    // Ordering options ahead of operands lets getopt stop at the first operand, so parsing does
    // not depend on whether libc permutes argv.
    std::vector<std::string> option_argv;
    // Positional command from the "su [options] user command [argument...]" form, exec'd directly.
    std::optional<std::string> executable;
    std::vector<std::string> exec_args;
};

// Whether arg is an option that consumes the following argv element as its value. A boundary scan
// must skip such a value so it is not mistaken for the target user.
bool takes_separate_value(const std::string& arg);

ParsedArgv split(const std::vector<std::string>& argv);

}  // namespace ksud::su_args
