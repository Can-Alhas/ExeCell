#pragma once

#include <execell/event/event.hpp>
#include <execell/trace/fd_table.hpp>
#include <execell/trace/syscall.hpp>

#include <optional>
#include <string>

#include <sys/types.h>
#include <sys/user.h>

namespace execell::trace {

class SyscallDecoder {

public:
    explicit SyscallDecoder(FdTable &fd_table) noexcept;
    
    [[nodiscard]] std::optional<event::Event> on_entry(
        pid_t pid,
        const user_regs_struct& registers);

    [[nodiscard]] std::optional<event::Event> on_exit(
        pid_t pid,
        const user_regs_struct& registers);

  private:
    FdTable &fd_table_;

    SyscallId current_syscall_{make_syscall_id(-1L)};

    std::string pending_path_;
    std::string pending_path_two_;
    std::string pending_endpoint_;
    int pending_socket_domain_{};
    int pending_socket_type_{};
    int pending_socket_protocol_{};
    unsigned pending_mode_{};
    int pending_fd_{-1};
    int pending_dirfd_{-100};

    int pending_target_fd_{-1};
    unsigned pending_close_range_end_{};
};
    
} // namespace execell::trace
