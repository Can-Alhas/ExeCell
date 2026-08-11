#include <execell/trace/syscall_decoder.hpp>

#include <execell/trace/memory.hpp>
#include <execell/trace/architecture.hpp>

#include <cstddef>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <filesystem>
#include <unistd.h>
#include <utility>

#include <sys/syscall.h>

namespace execell::trace {

namespace {

[[nodiscard]] std::string read_process_string(pid_t pid, unsigned long address)
{
    return execell::trace::read_process_memory_string(pid, address).value;
}

[[nodiscard]] std::string resolve_path(pid_t pid, int dirfd, std::string path)
{
    if (path.empty() || path.front() == '/') {
        return path;
    }
    std::filesystem::path base;
    if (dirfd == AT_FDCWD) {
        base = "/proc/" + std::to_string(pid) + "/cwd";
    } else {
        base = "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(dirfd);
    }
    return (base / path).lexically_normal().string();
}

[[nodiscard]] std::string read_endpoint(
    pid_t pid,
    unsigned long address,
    unsigned long length)
{
    sockaddr_storage storage{};
    const auto limit = std::min(length, static_cast<unsigned long>(sizeof(storage)));
    auto* bytes = reinterpret_cast<unsigned char*>(&storage);
    for (unsigned long offset = 0; offset < limit; offset += sizeof(long)) {
        errno = 0;
        const long word = ::ptrace(
            PTRACE_PEEKDATA,
            pid,
            address + offset,
            nullptr);
        if (word == -1 && errno != 0) {
            return {};
        }
        const auto copy_size = std::min(
            sizeof(long),
            static_cast<std::size_t>(limit - offset));
        std::memcpy(bytes + offset, &word, copy_size);
    }

    char buffer[INET6_ADDRSTRLEN]{};
    if (storage.ss_family == AF_INET) {
        const auto* address4 = reinterpret_cast<const sockaddr_in*>(&storage);
        if (::inet_ntop(AF_INET, &address4->sin_addr, buffer, sizeof(buffer)) == nullptr) {
            return {};
        }
        return std::string{buffer} + ":" + std::to_string(ntohs(address4->sin_port));
    }
    if (storage.ss_family == AF_INET6) {
        const auto* address6 = reinterpret_cast<const sockaddr_in6*>(&storage);
        if (::inet_ntop(AF_INET6, &address6->sin6_addr, buffer, sizeof(buffer)) == nullptr) {
            return {};
        }
        return "[" + std::string{buffer} + "]:" +
               std::to_string(ntohs(address6->sin6_port));
    }
    if (storage.ss_family == AF_UNIX) {
        const auto* unix_address = reinterpret_cast<const sockaddr_un*>(&storage);
        return std::string{unix_address->sun_path};
    }
    return "family=" + std::to_string(storage.ss_family);
}

} // namespace

SyscallDecoder::SyscallDecoder(FdTable& fd_table) noexcept
    : fd_table_{fd_table}
{
}

std::optional<event::Event> SyscallDecoder::on_entry(
    pid_t pid,
    const user_regs_struct& registers)
{



    
    const auto frame = X86_64Architecture::decode(registers);
    current_syscall_ = make_syscall_id(frame.number.value);

    pending_path_.clear();
    pending_path_two_.clear();
    pending_endpoint_.clear();
    pending_fd_ = -1;
    pending_target_fd_ = -1;
    pending_close_range_end_ = 0;
    pending_dirfd_ = AT_FDCWD;
    pending_socket_domain_ = 0;
    pending_socket_type_ = 0;
    pending_socket_protocol_ = 0;
    pending_mode_ = 0;

    const long syscall =
        syscall_number(current_syscall_);

#ifdef SYS_socket
    if (syscall == SYS_socket) {
        pending_socket_domain_ = static_cast<int>(registers.rdi);
        pending_socket_type_ = static_cast<int>(registers.rsi);
        pending_socket_protocol_ = static_cast<int>(registers.rdx);
        return std::nullopt;
    }
#endif

#ifdef SYS_connect
    if (syscall == SYS_connect || syscall == SYS_bind) {
        pending_fd_ = static_cast<int>(registers.rdi);
        pending_endpoint_ = read_endpoint(
            pid,
            static_cast<unsigned long>(registers.rsi),
            static_cast<unsigned long>(registers.rdx));
        return std::nullopt;
    }
#endif

#ifdef SYS_listen
    if (syscall == SYS_listen) {
        pending_fd_ = static_cast<int>(registers.rdi);
        pending_target_fd_ = static_cast<int>(registers.rsi);
        return std::nullopt;
    }
#endif

#ifdef SYS_accept
    if (syscall == SYS_accept || syscall == SYS_accept4) {
        pending_fd_ = static_cast<int>(registers.rdi);
        if (registers.rsi != 0 && registers.rdx != 0) {
            pending_endpoint_ = read_endpoint(
                pid,
                static_cast<unsigned long>(registers.rsi),
                static_cast<unsigned long>(registers.rdx));
        }
        return std::nullopt;
    }
#endif


    if (syscall == SYS_dup || syscall == SYS_dup2 || syscall == SYS_dup3) {

    pending_fd_ =
        static_cast<int>(registers.rdi);

    pending_target_fd_ =
        static_cast<int>(registers.rsi);

        return std::nullopt;
}
    
    if (syscall == SYS_openat
#ifdef SYS_open
        || syscall == SYS_open
#endif
#ifdef SYS_openat2
        || syscall == SYS_openat2
#endif
    ) {
        const auto address =
            static_cast<unsigned long>(syscall == SYS_open ? registers.rdi : registers.rsi);

        pending_path_ =
            resolve_path(
                pid,
                syscall == SYS_open ? AT_FDCWD : static_cast<int>(registers.rdi),
                read_process_string(pid, address));

        return std::nullopt;
    }

    if (syscall == SYS_rename
#ifdef SYS_renameat2
        || syscall == SYS_renameat2
#endif
    ) {
        pending_path_ = resolve_path(pid, AT_FDCWD,
            read_process_string(pid, static_cast<unsigned long>(registers.rdi)));
        pending_path_two_ = resolve_path(pid, AT_FDCWD,
            read_process_string(pid, static_cast<unsigned long>(registers.rsi)));
        return std::nullopt;
    }

#ifdef SYS_renameat
    if (syscall == SYS_renameat
#ifdef SYS_renameat2
        || syscall == SYS_renameat2
#endif
    ) {
        pending_path_ = resolve_path(pid, static_cast<int>(registers.rdi),
            read_process_string(pid, static_cast<unsigned long>(registers.rsi)));
        pending_path_two_ = resolve_path(pid, static_cast<int>(registers.rdi),
            read_process_string(pid, static_cast<unsigned long>(registers.rdx)));
        return std::nullopt;
    }
#endif

    if (syscall == SYS_unlink) {
        pending_path_ = resolve_path(pid, AT_FDCWD,
            read_process_string(pid, static_cast<unsigned long>(registers.rdi)));
        return std::nullopt;
    }

#ifdef SYS_unlinkat
    if (syscall == SYS_unlinkat) {
        pending_path_ = resolve_path(pid, static_cast<int>(registers.rdi),
            read_process_string(pid, static_cast<unsigned long>(registers.rsi)));
        return std::nullopt;
    }
#endif

    if (syscall == SYS_mkdir) {
        pending_path_ = resolve_path(pid, AT_FDCWD,
            read_process_string(pid, static_cast<unsigned long>(registers.rdi)));
        pending_fd_ = static_cast<int>(registers.rsi);
        return std::nullopt;
    }

#ifdef SYS_mkdirat
    if (syscall == SYS_mkdirat) {
        pending_path_ = resolve_path(pid, static_cast<int>(registers.rdi),
            read_process_string(pid, static_cast<unsigned long>(registers.rsi)));
        pending_fd_ = static_cast<int>(registers.rdx);
        return std::nullopt;
    }
#endif

    if (syscall == SYS_chmod) {
        pending_path_ = read_process_string(pid, static_cast<unsigned long>(registers.rdi));
        pending_mode_ = static_cast<unsigned>(registers.rsi);
        return std::nullopt;
    }

#ifdef SYS_fchmod
    if (syscall == SYS_fchmod) {
        pending_fd_ = static_cast<int>(registers.rdi);
        pending_mode_ = static_cast<unsigned>(registers.rsi);
        return std::nullopt;
    }

#endif

#ifdef SYS_fcntl
    if (syscall == SYS_fcntl &&
        (registers.rsi == F_DUPFD || registers.rsi == F_DUPFD_CLOEXEC)) {
        pending_fd_ = static_cast<int>(registers.rdi);
        return std::nullopt;
    }
#endif

#ifdef SYS_fchmodat
    if (syscall == SYS_fchmodat) {
        pending_path_ = resolve_path(pid, static_cast<int>(registers.rdi),
            read_process_string(pid, static_cast<unsigned long>(registers.rsi)));
        pending_mode_ = static_cast<unsigned>(registers.rdx);
        return std::nullopt;
    }
#endif

#ifdef SYS_close_range
    if (syscall == SYS_close_range) {
        pending_fd_ = static_cast<int>(registers.rdi);
        pending_close_range_end_ = static_cast<unsigned>(registers.rsi);
        return std::nullopt;
    }
#endif

    if (syscall == SYS_execve) {
        const auto address = static_cast<unsigned long>(registers.rdi);
        pending_path_ = read_process_string(pid, address);
        return event::ProcessExec{
            .pid = pid,
            .path = pending_path_,
            .context = {}
        };
    }

    if (syscall == SYS_read || syscall == SYS_write ||
        syscall == SYS_close
#ifdef SYS_pread64
        || syscall == SYS_pread64 || syscall == SYS_pwrite64
#endif
#ifdef SYS_readv
        || syscall == SYS_readv || syscall == SYS_writev
#endif
    ) {

        pending_fd_ =
            static_cast<int>(registers.rdi);
    }

    return std::nullopt;
}

std::optional<event::Event>
SyscallDecoder::on_exit(
    pid_t pid,
    const user_regs_struct& registers)
{
    const auto frame = X86_64Architecture::decode(registers);
    const auto result = frame.result;

    const long syscall =
        syscall_number(current_syscall_);

#ifdef SYS_socket
    if (syscall == SYS_socket && result >= 0) {
        return event::SocketCreated{
            .fd = static_cast<int>(result),
            .domain = pending_socket_domain_,
            .type = pending_socket_type_,
            .protocol = pending_socket_protocol_,
            .context = {}
        };
    }
#endif

#ifdef SYS_connect
    if (syscall == SYS_connect && result == 0) {
        return event::NetworkConnected{
            .fd = pending_fd_,
            .endpoint = pending_endpoint_,
            .context = {}
        };
    }
    if (syscall == SYS_bind && result == 0) {
        return event::NetworkBound{
            .fd = pending_fd_,
            .endpoint = pending_endpoint_,
            .context = {}
        };
    }
#endif

#ifdef SYS_listen
    if (syscall == SYS_listen && result == 0) {
        return event::NetworkListening{
            .fd = pending_fd_,
            .backlog = pending_target_fd_,
            .context = {}
        };
    }
#endif

#ifdef SYS_accept
    if ((syscall == SYS_accept || syscall == SYS_accept4) && result >= 0) {
        return event::NetworkAccepted{
            .fd = static_cast<int>(result),
            .endpoint = pending_endpoint_,
            .context = {}
        };
    }
#endif

    if ((syscall == SYS_openat
#ifdef SYS_open
         || syscall == SYS_open
#endif
#ifdef SYS_openat2
         || syscall == SYS_openat2
#endif
        ) && result >= 0) {
        const int fd =
            static_cast<int>(result);

        fd_table_.track(fd, pending_path_);

        return event::FileOpened{
            .fd = fd,
            .path = pending_path_,
            .context = {}
        };
    }

    if ((syscall == SYS_unlink
#ifdef SYS_unlinkat
         || syscall == SYS_unlinkat
#endif
        ) && result == 0) {
        return event::FileDeleted{.path = pending_path_, .context = {}};
    }

    if ((syscall == SYS_rename
#ifdef SYS_renameat
         || syscall == SYS_renameat
#endif
#ifdef SYS_renameat2
         || syscall == SYS_renameat2
#endif
        ) && result == 0) {
        return event::FileRenamed{
            .from = pending_path_,
            .to = pending_path_two_,
            .context = {}
        };
    }

    if ((syscall == SYS_mkdir
#ifdef SYS_mkdirat
         || syscall == SYS_mkdirat
#endif
        ) && result == 0) {
        return event::DirectoryCreated{.path = pending_path_, .context = {}};
    }

    if (syscall == SYS_chmod && result == 0) {
        return event::FileModeChanged{
            .path = pending_path_,
            .mode = pending_mode_,
            .context = {}
        };
    }

#ifdef SYS_fchmod
    if (syscall == SYS_fchmod && result == 0) {
        if (const auto path = fd_table_.lookup(pending_fd_)) {
            return event::FileModeChanged{
                .path = path->get(), .mode = pending_mode_, .context = {}};
        }
    }
#endif

#ifdef SYS_fchmodat
    if (syscall == SYS_fchmodat && result == 0) {
        return event::FileModeChanged{
            .path = pending_path_, .mode = pending_mode_, .context = {}};
    }
#endif

#ifdef SYS_fcntl
    if (syscall == SYS_fcntl && result >= 0 &&
        (pending_fd_ >= 0)) {
        fd_table_.duplicate(pending_fd_, static_cast<int>(result));
        return std::nullopt;
    }
#endif

#ifdef SYS_close_range
    if (syscall == SYS_close_range && result == 0) {
        fd_table_.close_range(
            static_cast<unsigned>(pending_fd_),
            pending_close_range_end_);
        return std::nullopt;
    }
#endif

    if (result < 0 &&
        (syscall == SYS_openat || syscall == SYS_read || syscall == SYS_write ||
         syscall == SYS_close || syscall == SYS_connect || syscall == SYS_bind)) {
        return event::SyscallFailed{
            .pid = pid,
            .syscall = std::string{syscall_name(current_syscall_)},
            .error = static_cast<int>(-result),
            .context = {}
        };
    }

    if ((syscall == SYS_dup || syscall == SYS_dup2 || syscall == SYS_dup3) &&
        result >= 0) {
        fd_table_.duplicate(pending_fd_, static_cast<int>(result));
        return std::nullopt;
    }

    if ((syscall == SYS_read
#ifdef SYS_pread64
         || syscall == SYS_pread64
#endif
#ifdef SYS_readv
         || syscall == SYS_readv
#endif
        ) && result >= 0) {
        const auto path =
            fd_table_.lookup(pending_fd_);

        if (!path) {
            return std::nullopt;
        }

        return event::FileRead{
            .fd = pending_fd_,
            .path = path->get(),
            .bytes = static_cast<std::size_t>(result),
            .context = {}
        };
    }

    if ((syscall == SYS_write
#ifdef SYS_pwrite64
         || syscall == SYS_pwrite64
#endif
#ifdef SYS_writev
         || syscall == SYS_writev
#endif
        ) && result >= 0) {
        const auto path =
            fd_table_.lookup(pending_fd_);

        if (!path) {
            return std::nullopt;
        }

        return event::FileWritten{
            .fd = pending_fd_,
            .path = path->get(),
            .bytes = static_cast<std::size_t>(result),
            .context = {}
        };
    }

    if (syscall == SYS_close && result == 0) {
        const auto path =
            fd_table_.lookup(pending_fd_);

        if (!path) {
            return std::nullopt;
        }

        event::FileClosed event{
            .fd = pending_fd_,
            .path = path->get(),
            .context = {}
        };

        fd_table_.close(pending_fd_);

        return event;
    }

    return std::nullopt;
}

} // namespace execell::trace
