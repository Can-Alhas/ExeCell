#include <execell/event/event.hpp>
#include <execell/report/terminal_reporter.hpp>
#include <execell/report/reporter.hpp>
#include <execell/trace/stop.hpp>
#include <execell/trace/task_registry.hpp>
#include <execell/trace/trace_session.hpp>
#include <execell/linux/ptrace.hpp>
#include <execell/linux/wait.hpp>
#include <execell/trace/tracer.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <iostream>

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__linux__)
#error "ExeCell currently supports Linux only"
#endif

#if !defined(__x86_64__)
#error "ExeCell tracer currently supports x86_64 only"
#endif

namespace execell::trace {

namespace {

} // namespace

int run(char* const program, char* const argv[], ::execell::report::Reporter& reporter)
{
    const pid_t root_pid = ::fork();
    if (root_pid < 0) {
        std::cerr << "execell: fork failed: " << std::strerror(errno) << '\n';
        return EXIT_FAILURE;
    }

    if (root_pid == 0) {
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            std::cerr << "execell: PTRACE_TRACEME failed: "
                      << std::strerror(errno) << '\n';
            ::_exit(127);
        }

        ::execvp(program, argv);
        std::cerr << "execell: execvp failed: " << std::strerror(errno) << '\n';
        ::_exit(127);
    }

    int status{};
    const auto initial_wait = ::execell::linux_api::wait_for(root_pid);
    if (!initial_wait) {
        std::cerr << "execell: initial waitpid failed: "
                  << initial_wait.error().message() << '\n';
        return EXIT_FAILURE;
    }
    status = initial_wait->status;
    TraceSession session{root_pid};

    constexpr auto options = PTRACE_O_TRACESYSGOOD |
                             PTRACE_O_EXITKILL |
                             PTRACE_O_TRACECLONE |
                             PTRACE_O_TRACEFORK |
                             PTRACE_O_TRACEVFORK |
                             PTRACE_O_TRACEEXEC;
    if (const auto result = ::execell::linux_api::set_options(root_pid, options); !result) {
        std::cerr << "execell: PTRACE_SETOPTIONS failed: "
                  << result.error().message() << '\n';
        return EXIT_FAILURE;
    }

    TaskRegistry tasks;
    tasks.insert_root(root_pid);
    std::uint64_t sequence{};
    int pending_signal{};
    const auto emit = [&](event::Event payload, pid_t pid) {
        std::visit([&](auto& value) {
            value.context = event::EventContext{.pid = pid, .sequence = sequence++};
        }, payload);
        reporter.report(payload);
        if (reporter.stop_requested()) {
            pending_signal = SIGKILL;
        }
    };

    std::cerr << "[execell] tracing pid " << root_pid << '\n';
    emit(event::TraceStarted{.pid = root_pid, .context = {}}, root_pid);
    pid_t current_pid = root_pid;
    bool resume_current = true;

    while (!tasks.empty()) {
        if (resume_current) {
            const auto continued = ::execell::linux_api::syscall_continue(
                current_pid,
                pending_signal);
            pending_signal = 0;
            resume_current = false;
            if (!continued && continued.error().code.value() != ESRCH) {
                std::cerr << "execell: PTRACE_SYSCALL failed: "
                          << continued.error().message() << '\n';
                return EXIT_FAILURE;
            }
        }

        const auto waited = ::execell::linux_api::wait_for(-1, __WALL);
        if (!waited) {
            std::cerr << "execell: waitpid failed: "
                      << waited.error().message() << '\n';
            return EXIT_FAILURE;
        }
        const pid_t stopped_pid = waited->pid;
        status = waited->status;
        current_pid = stopped_pid;
        const Stop stop = classify_stop(stopped_pid, status);

        if (stop.kind == StopKind::exited || stop.kind == StopKind::signaled) {
            const bool signaled = stop.kind == StopKind::signaled;
            const int result = signaled ? stop.signal : stop.exit_status;
            emit(event::ProcessExited{
                .pid = stopped_pid,
                .status = result,
                .signaled = signaled,
                .context = {}
            }, stopped_pid);
            tasks.erase(stopped_pid);
            if (stopped_pid == root_pid) {
                emit(event::TraceFinished{
                    .pid = stopped_pid,
                    .status = result,
                    .signaled = signaled,
                    .context = {}
                }, stopped_pid);
                return signaled ? 128 + result : result;
            }
            continue;
        }

        if (stop.kind == StopKind::ptrace_event) {
            const unsigned event = stop.ptrace_event;
            const auto message_result = ::execell::linux_api::event_message(stopped_pid);
            if (!message_result) {
                std::cerr << "execell: PTRACE_GETEVENTMSG failed: "
                          << message_result.error().message() << '\n';
                return EXIT_FAILURE;
            }
            const unsigned long message = *message_result;

            if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK ||
                event == PTRACE_EVENT_VFORK) {
                const pid_t child_pid = static_cast<pid_t>(message);
                const auto* parent = tasks.find(stopped_pid);
                if (parent != nullptr) {
                    tasks.insert_child(child_pid, stopped_pid, parent->fd_table);
                    emit(event::ProcessSpawned{
                        .pid = child_pid,
                        .parent_pid = stopped_pid,
                        .context = {}
                    }, stopped_pid);
                }
            }
            if (event == PTRACE_EVENT_EXEC) {
                if (auto* task = tasks.find(stopped_pid); task != nullptr) {
                    task->phase = SyscallPhase::entry;
                }
            }
            resume_current = true;
            continue;
        }

        if (stop.kind != StopKind::syscall) {
            pending_signal = resume_signal(stop);
            resume_current = true;
            continue;
        }

        auto* task = tasks.find(stopped_pid);
        if (task == nullptr) {
            resume_current = true;
            continue;
        }

        const auto registers_result = ::execell::linux_api::get_registers(stopped_pid);
        if (!registers_result) {
            if (registers_result.error().code.value() == ESRCH) {
                tasks.erase(stopped_pid);
                resume_current = true;
                continue;
            }
            std::cerr << "execell: PTRACE_GETREGS failed: "
                      << registers_result.error().message() << '\n';
            return EXIT_FAILURE;
        }
        const user_regs_struct registers = *registers_result;

        if (task->phase == SyscallPhase::entry) {
            if (auto event = task->decoder.on_entry(stopped_pid, registers)) {
                emit(*event, stopped_pid);
            }
            task->phase = SyscallPhase::exit;
        } else if (task->phase == SyscallPhase::exit) {
            if (auto event = task->decoder.on_exit(stopped_pid, registers)) {
                emit(*event, stopped_pid);
            }
            task->phase = SyscallPhase::entry;
        } else {
            task->phase = SyscallPhase::entry;
        }
        resume_current = true;
    }

    return EXIT_FAILURE;
}

int run(char* const program, char* const argv[])
{
    ::execell::report::TerminalReporter reporter;
    return run(program, argv, reporter);
}

} // namespace execell::trace
