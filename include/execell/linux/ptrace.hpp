#pragma once

#include <execell/core/error.hpp>

#include <cerrno>
#include <expected>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

namespace execell::linux_api {

[[nodiscard]] inline std::expected<void, Error> syscall_continue(
    pid_t pid,
    int signal = 0) noexcept
{
    if (::ptrace(PTRACE_SYSCALL, pid, nullptr, signal) == -1) {
        return std::unexpected{Error::from_errno("ptrace(PTRACE_SYSCALL)")};
    }
    return {};
}

[[nodiscard]] inline std::expected<void, Error> set_options(
    pid_t pid,
    unsigned long options) noexcept
{
    if (::ptrace(PTRACE_SETOPTIONS, pid, nullptr, options) == -1) {
        return std::unexpected{Error::from_errno("ptrace(PTRACE_SETOPTIONS)")};
    }
    return {};
}

[[nodiscard]] inline std::expected<user_regs_struct, Error> get_registers(
    pid_t pid) noexcept
{
    user_regs_struct registers{};
    if (::ptrace(PTRACE_GETREGS, pid, nullptr, &registers) == -1) {
        return std::unexpected{Error::from_errno("ptrace(PTRACE_GETREGS)")};
    }
    return registers;
}

[[nodiscard]] inline std::expected<unsigned long, Error> event_message(
    pid_t pid) noexcept
{
    unsigned long message{};
    if (::ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &message) == -1) {
        return std::unexpected{Error::from_errno("ptrace(PTRACE_GETEVENTMSG)")};
    }
    return message;
}

} // namespace execell::linux_api
