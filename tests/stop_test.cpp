#include <execell/trace/stop.hpp>
#include <execell/linux/ptrace.hpp>
#include <execell/linux/wait.hpp>

#include <cassert>
#include <signal.h>
#include <sys/ptrace.h>

int main()
{
    using execell::trace::StopKind;
    using execell::trace::classify_stop;

    assert(classify_stop(1, 7 << 8).kind == StopKind::exited);
    assert(classify_stop(1, SIGTERM).kind == StopKind::signaled);

    const int syscall_stop = ((SIGTRAP | 0x80) << 8) | 0x7f;
    assert(classify_stop(1, syscall_stop).kind == StopKind::syscall);

    const int event_stop =
        (static_cast<int>(PTRACE_EVENT_CLONE) << 16) | (SIGTRAP << 8) | 0x7f;
    assert(classify_stop(1, event_stop).kind == StopKind::ptrace_event);
}
