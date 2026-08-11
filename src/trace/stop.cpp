#include <execell/trace/stop.hpp>

#include <signal.h>
#include <sys/wait.h>

namespace execell::trace {

Stop classify_stop(pid_t pid, int status) noexcept
{
    Stop result{
        .pid = pid,
        .raw_status = status
    };

    if (WIFEXITED(status)) {
        result.kind = StopKind::exited;
        result.exit_status = WEXITSTATUS(status);
        return result;
    }
    if (WIFSIGNALED(status)) {
        result.kind = StopKind::signaled;
        result.signal = WTERMSIG(status);
        return result;
    }
    if (!WIFSTOPPED(status)) {
        return result;
    }

    result.signal = WSTOPSIG(status);
    if (result.signal == (SIGTRAP | 0x80)) {
        result.kind = StopKind::syscall;
        return result;
    }
    if (result.signal == SIGTRAP && (static_cast<unsigned>(status) >> 16U) != 0U) {
        result.kind = StopKind::ptrace_event;
        result.ptrace_event = static_cast<unsigned>(status) >> 16U;
        return result;
    }
    if (result.signal == SIGSTOP || result.signal == SIGTSTP ||
        result.signal == SIGTTIN || result.signal == SIGTTOU) {
        result.kind = StopKind::group_stop;
        return result;
    }
    result.kind = StopKind::signal;
    return result;
}

int resume_signal(const Stop& stop) noexcept
{
    if (stop.kind == StopKind::signal) {
        return stop.signal == SIGTRAP ? 0 : stop.signal;
    }
    return 0;
}

} // namespace execell::trace
