#include <execell/trace/architecture.hpp>

#if !defined(__x86_64__)
#error "X86_64Architecture requires x86_64"
#endif

namespace execell::trace {

SyscallFrame X86_64Architecture::decode(
    const user_regs_struct& registers) noexcept
{
    return SyscallFrame{
        .number = SyscallNumber{static_cast<long>(registers.orig_rax)},
        .arguments = {
            registers.rdi,
            registers.rsi,
            registers.rdx,
            registers.r10,
            registers.r8,
            registers.r9
        },
        .result = static_cast<long>(registers.rax)
    };
}

} // namespace execell::trace
