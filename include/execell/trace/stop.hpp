#pragma once

#include <sys/types.h>

namespace execell::trace {

enum class StopKind {
    exited,
    signaled,
    syscall,
    ptrace_event,
    signal,
    group_stop,
    unknown
};

struct Stop {
    pid_t pid{};
    int raw_status{};
    StopKind kind{StopKind::unknown};
    int signal{};
    unsigned ptrace_event{};
    int exit_status{};
};

[[nodiscard]] Stop classify_stop(pid_t pid, int status) noexcept;
[[nodiscard]] int resume_signal(const Stop& stop) noexcept;

} // namespace execell::trace
