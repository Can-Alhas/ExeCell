#pragma once

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace execell::trace {

class TraceSession final {
public:
    explicit TraceSession(pid_t root_pid) noexcept : root_pid_{root_pid} {}

    TraceSession(const TraceSession&) = delete;
    TraceSession& operator=(const TraceSession&) = delete;
    TraceSession(TraceSession&&) = delete;
    TraceSession& operator=(TraceSession&&) = delete;

    ~TraceSession() noexcept
    {
        if (root_pid_ < 0) {
            return;
        }
        if (::kill(root_pid_, 0) == 0) {
            (void)::kill(root_pid_, SIGKILL);
            (void)::waitpid(root_pid_, nullptr, WNOHANG | __WALL);
        }
    }

    [[nodiscard]] pid_t root_pid() const noexcept { return root_pid_; }

private:
    pid_t root_pid_{-1};
};

} // namespace execell::trace
