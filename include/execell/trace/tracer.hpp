#pragma once

#include <execell/report/reporter.hpp>

namespace execell::trace {

[[nodiscard]] int run(char *const program, char *const argv[]);
[[nodiscard]] int run(
    char *const program,
    char *const argv[],
    ::execell::report::Reporter& reporter);

} // namespace execell::trace
