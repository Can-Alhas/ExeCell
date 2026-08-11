#pragma once

#include <execell/trace/syscall_frame.hpp>

#include <sys/user.h>

namespace execell::trace {

class X86_64Architecture final {
public:
    [[nodiscard]] static SyscallFrame decode(const user_regs_struct& registers) noexcept;
};

} // namespace execell::trace
