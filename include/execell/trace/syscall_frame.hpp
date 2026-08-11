#pragma once

#include <execell/core/types.hpp>

#include <array>

namespace execell::trace {

struct SyscallFrame {
    SyscallNumber number;
    std::array<unsigned long, 6> arguments{};
    long result{};
};

} // namespace execell::trace
