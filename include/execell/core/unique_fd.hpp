#pragma once

#include <unistd.h>

namespace execell {

class UniqueFd {
public:
    constexpr UniqueFd() noexcept = default;
    explicit constexpr UniqueFd(int fd) noexcept : fd_{fd} {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : fd_{other.release()} {}

    UniqueFd& operator=(UniqueFd&& other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    [[nodiscard]] constexpr int get() const noexcept { return fd_; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return fd_ >= 0; }

    [[nodiscard]] constexpr int release() noexcept
    {
        const int result = fd_;
        fd_ = -1;
        return result;
    }

    void reset(int fd = -1) noexcept
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_{-1};
};

} // namespace execell
