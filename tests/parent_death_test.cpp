#include <execell/sandbox/sandbox.hpp>

#include <cassert>
#include <chrono>
#include <thread>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

int main()
{
    int pipe_fds[2]{};
    if (::pipe(pipe_fds) < 0) {
        return 1;
    }
    const pid_t supervisor = ::fork();
    if (supervisor < 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        return 1;
    }
    if (supervisor == 0) {
        ::close(pipe_fds[0]);
        const pid_t target = ::fork();
        if (target == 0) {
            if (!execell::sandbox::set_parent_death_signal()) {
                ::_exit(127);
            }
            const pid_t self = ::getpid();
            (void)::write(pipe_fds[1], &self, sizeof(self));
            for (;;) {
                ::pause();
            }
        }
        ::pause();
        ::_exit(target < 0 ? 127 : 0);
    }

    ::close(pipe_fds[1]);
    pid_t target{};
    if (::read(pipe_fds[0], &target, sizeof(target)) != sizeof(target)) {
        (void)::kill(supervisor, SIGKILL);
        (void)::waitpid(supervisor, nullptr, 0);
        return 1;
    }
    ::kill(supervisor, SIGKILL);
    (void)::waitpid(supervisor, nullptr, 0);

    bool dead{};
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (::kill(target, 0) < 0) {
            dead = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    ::kill(target, SIGKILL);
    return dead ? 0 : 1;
}
