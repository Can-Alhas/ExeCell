#pragma once

#include <execell/core/error.hpp>

#include <expected>
#include <sys/types.h>
#include <sys/wait.h>

namespace execell::linux_api {

struct WaitResult {
    pid_t pid{};
    int status{};
};

[[nodiscard]] inline std::expected<WaitResult, Error> wait_for(
    pid_t pid,
    int options = 0) noexcept
{
    int status{};
    pid_t result{};
    do {
        result = ::waitpid(pid, &status, options);
    } while (result < 0 && errno == EINTR);

    if (result < 0) {
        return std::unexpected{Error::from_errno("waitpid")};
    }
    return WaitResult{.pid = result, .status = status};
}

} // namespace execell::linux_api
