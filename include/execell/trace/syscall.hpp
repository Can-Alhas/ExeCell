#pragma once

#include <string_view>

namespace execell::trace {

enum class SyscallId : long {};

[[nodiscard]] constexpr  SyscallId make_syscall_id(long value) noexcept {
    return static_cast<SyscallId>(value);
}

[[nodiscard]] constexpr long syscall_number(SyscallId syscall) noexcept {
    return static_cast<long>(syscall);
}

[[nodiscard]] std::string_view syscall_name(SyscallId syscall) noexcept ;
    


} // namespace execell::trace
