#include <execell/trace/syscall.hpp>

#include <sys/syscall.h>

#if !defined(__linux__)
#error "ExeCell currently supports Linux only"
#endif

#if !defined(__x86_64__)
#error "ExeCell syscall decoder currently supports x86_64 only"
#endif

namespace execell::trace {

std::string_view syscall_name(SyscallId syscall) noexcept
{
    switch (syscall_number(syscall)) {
    case SYS_read:              return "read";
    case SYS_write:             return "write";
#ifdef SYS_open
    case SYS_open:              return "open";
#endif
    case SYS_close:             return "close";
    case SYS_fstat:             return "fstat";
    case SYS_lseek:             return "lseek";
    case SYS_mmap:              return "mmap";
    case SYS_mprotect:          return "mprotect";
    case SYS_munmap:            return "munmap";
    case SYS_brk:               return "brk";
    case SYS_ioctl:             return "ioctl";
    case SYS_readv:             return "readv";
    case SYS_writev:            return "writev";
    case SYS_access:            return "access";
    case SYS_sched_yield:       return "sched_yield";
    case SYS_dup:               return "dup";
    case SYS_dup2:              return "dup2";
    case SYS_nanosleep:         return "nanosleep";
    case SYS_getpid:            return "getpid";

#ifdef SYS_socket
    case SYS_socket:            return "socket";
#endif
#ifdef SYS_connect
    case SYS_connect:           return "connect";
#endif
#ifdef SYS_accept
    case SYS_accept:            return "accept";
#endif
#ifdef SYS_accept4
    case SYS_accept4:           return "accept4";
#endif
#ifdef SYS_sendto
    case SYS_sendto:            return "sendto";
#endif
#ifdef SYS_recvfrom
    case SYS_recvfrom:          return "recvfrom";
#endif
#ifdef SYS_bind
    case SYS_bind:              return "bind";
#endif
#ifdef SYS_listen
    case SYS_listen:            return "listen";
#endif

#ifdef SYS_clone
    case SYS_clone:             return "clone";
#endif
#ifdef SYS_clone3
    case SYS_clone3:            return "clone3";
#endif
#ifdef SYS_fork
    case SYS_fork:              return "fork";
#endif
#ifdef SYS_vfork
    case SYS_vfork:             return "vfork";
#endif

    case SYS_execve:            return "execve";
#ifdef SYS_execveat
    case SYS_execveat:          return "execveat";
#endif

    case SYS_exit:              return "exit";
    case SYS_exit_group:        return "exit_group";
    case SYS_wait4:             return "wait4";
    case SYS_kill:              return "kill";
    case SYS_uname:             return "uname";
    case SYS_fcntl:             return "fcntl";
    case SYS_fsync:             return "fsync";
    case SYS_fdatasync:         return "fdatasync";
    case SYS_getcwd:            return "getcwd";
    case SYS_chdir:             return "chdir";
    case SYS_fchdir:            return "fchdir";
    case SYS_rename:            return "rename";

#ifdef SYS_renameat
    case SYS_renameat:          return "renameat";
#endif
#ifdef SYS_renameat2
    case SYS_renameat2:         return "renameat2";
#endif

    case SYS_mkdir:             return "mkdir";
#ifdef SYS_mkdirat
    case SYS_mkdirat:           return "mkdirat";
#endif

    case SYS_rmdir:             return "rmdir";
    case SYS_link:              return "link";
    case SYS_unlink:            return "unlink";

#ifdef SYS_unlinkat
    case SYS_unlinkat:          return "unlinkat";
#endif

    case SYS_symlink:           return "symlink";
    case SYS_readlink:          return "readlink";
    case SYS_chmod:             return "chmod";
    case SYS_fchmod:            return "fchmod";
    case SYS_chown:             return "chown";
    case SYS_fchown:            return "fchown";
    case SYS_umask:             return "umask";

    case SYS_getuid:            return "getuid";
    case SYS_getgid:            return "getgid";
    case SYS_geteuid:           return "geteuid";
    case SYS_getegid:           return "getegid";
    case SYS_getppid:           return "getppid";

    case SYS_arch_prctl:        return "arch_prctl";
    case SYS_set_tid_address:   return "set_tid_address";
    case SYS_openat:            return "openat";

#ifdef SYS_openat2
    case SYS_openat2:           return "openat2";
#endif
#ifdef SYS_newfstatat
    case SYS_newfstatat:        return "newfstatat";
#endif
#ifdef SYS_statx
    case SYS_statx:             return "statx";
#endif

    case SYS_set_robust_list:   return "set_robust_list";

#ifdef SYS_prlimit64
    case SYS_prlimit64:         return "prlimit64";
#endif
#ifdef SYS_getrandom
    case SYS_getrandom:         return "getrandom";
#endif
#ifdef SYS_memfd_create
    case SYS_memfd_create:      return "memfd_create";
#endif
#ifdef SYS_rseq
    case SYS_rseq:              return "rseq";
#endif
#ifdef SYS_close_range
    case SYS_close_range:       return "close_range";
#endif

    default:
        return "unknown";
    }
}

} // namespace execell::trace
