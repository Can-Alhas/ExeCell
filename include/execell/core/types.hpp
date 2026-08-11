#pragma once

#include <compare>
#include <sys/types.h>

namespace execell {

struct ProcessId {
    pid_t value{};
    friend auto operator<=>(ProcessId, ProcessId) = default;
};

struct FileDescriptor {
    int value{-1};
    friend auto operator<=>(FileDescriptor, FileDescriptor) = default;
};

struct SyscallNumber {
    long value{-1};
    friend auto operator<=>(SyscallNumber, SyscallNumber) = default;
};

} // namespace execell
