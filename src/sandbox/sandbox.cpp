#include <execell/sandbox/sandbox.hpp>
#include <execell/core/unique_fd.hpp>
#include <execell/linux/wait.hpp>
#include <execell/event/event.hpp>
#include <execell/report/reporter.hpp>
#include <execell/trace/tracer.hpp>

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <array>
#include <chrono>
#include <poll.h>

#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <type_traits>

namespace execell::sandbox {

bool set_parent_death_signal(pid_t expected_parent) noexcept
{
    const pid_t parent = ::getppid();
    if (expected_parent >= 0 && parent != expected_parent) {
        return false;
    }
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
        return false;
    }
    return ::getppid() == parent;
}

std::expected<void, std::string> validate(const Config& config)
{
    if (config.mount_namespace && !config.user_namespace) {
        return std::unexpected{
            "mount namespace requires user namespace for unprivileged setup"};
    }
    if (const auto backend = validate_backend(config.backend); !backend) return backend;
    if (!config.drop_capabilities && (config.mount_namespace || config.network_namespace)) {
        return std::unexpected{"sandbox must drop capabilities before namespace setup"};
    }
    if (!config.seccomp_allowlist.empty() && !config.no_new_privileges) {
        return std::unexpected{"seccomp requires no_new_privileges"};
    }
    if (config.cpu_seconds > 86400) {
        return std::unexpected{"cpu limit exceeds 24 hours"};
    }
    if (config.address_space_bytes != 0 && config.address_space_bytes < 4096) {
        return std::unexpected{"address-space limit is below page size"};
    }
    if (config.max_processes > 0 && config.max_processes > 100000) {
        return std::unexpected{"process limit exceeds safety ceiling"};
    }
    if (const auto cgroup = validate_cgroup(config.cgroup); !cgroup) return cgroup;
    return {};
}

std::expected<void, std::string>
validate_cgroup(const Config::CgroupBudget& budget)
{
    if (budget.path.empty()) return {};
    if (!budget.path.is_absolute() || std::filesystem::is_symlink(budget.path))
        return std::unexpected{"cgroup path must be absolute and non-symlink"};
    if (budget.cpu_period_us == 0 || budget.cpu_period_us > 1000000)
        return std::unexpected{"invalid cgroup CPU period"};
    if (budget.cpu_quota_us != 0 && budget.cpu_quota_us > budget.cpu_period_us * 1024U)
        return std::unexpected{"cgroup CPU quota exceeds safety ceiling"};
    return {};
}

std::vector<int> default_package_syscalls()
{
    return {
        SYS_read, SYS_write, SYS_close, SYS_open, SYS_openat, SYS_newfstatat, SYS_fstat,
        SYS_statx, SYS_lseek, SYS_pread64, SYS_pwrite64, SYS_readv, SYS_writev,
        SYS_getdents64, SYS_dup, SYS_dup2, SYS_dup3, SYS_fcntl, SYS_ioctl,
        SYS_pipe, SYS_pipe2, SYS_poll, SYS_ppoll, SYS_mmap, SYS_mprotect,
        SYS_munmap, SYS_mremap, SYS_brk, SYS_madvise, SYS_arch_prctl,
        SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn, SYS_sigaltstack,
        SYS_futex, SYS_set_tid_address, SYS_set_robust_list, SYS_rseq, SYS_clone,
        SYS_clone3, SYS_fork, SYS_vfork, SYS_execve, SYS_execveat, SYS_ptrace,
        SYS_exit,
        SYS_exit_group, SYS_wait4, SYS_waitid, SYS_kill, SYS_tgkill, SYS_getpid,
        SYS_getppid, SYS_gettid, SYS_getuid, SYS_geteuid, SYS_getgid, SYS_getegid,
        SYS_getresuid, SYS_getresgid, SYS_setresuid, SYS_setresgid, SYS_prctl,
        SYS_prlimit64, SYS_getrlimit, SYS_setrlimit, SYS_uname, SYS_getcwd,
        SYS_readlink, SYS_readlinkat,
        SYS_access, SYS_faccessat, SYS_faccessat2, SYS_chdir, SYS_fchdir,
        SYS_mkdir, SYS_mkdirat, SYS_unlink, SYS_unlinkat, SYS_rename, SYS_renameat,
        SYS_renameat2, SYS_link, SYS_linkat, SYS_symlink, SYS_symlinkat, SYS_chmod,
        SYS_fchmod, SYS_fchmodat, SYS_chown, SYS_fchown, SYS_fchownat, SYS_utimensat,
        SYS_truncate, SYS_ftruncate, SYS_syncfs,
        SYS_getrandom, SYS_clock_gettime, SYS_nanosleep, SYS_sched_getaffinity,
        SYS_sysinfo, SYS_socket, SYS_connect, SYS_bind, SYS_listen, SYS_accept,
        SYS_accept4, SYS_sendto, SYS_recvfrom, SYS_sendmsg, SYS_recvmsg,
        SYS_shutdown, SYS_setsockopt, SYS_getsockopt, SYS_getpeername,
        SYS_getsockname, SYS_capget, SYS_capset, SYS_setpgid, SYS_getpgid, SYS_setsid,
        SYS_setxattr, SYS_lsetxattr,
        SYS_fsetxattr, SYS_listxattr, SYS_llistxattr, SYS_flistxattr,
        SYS_removexattr, SYS_lremovexattr, SYS_fremovexattr
    };
}

std::string attestation(const Config& config)
{
    std::string rootfs = config.rootfs.string();
    std::size_t position{};
    while ((position = rootfs.find_first_of("\\\"", position)) != std::string::npos) {
        rootfs.insert(position, 1U, '\\');
        position += 2U;
    }
    return "{\"schema_version\":1,\"backend\":\"" +
           std::string(config.backend == Backend::vm ? "vm" : "namespace") +
           "\",\"user_namespace\":" + (config.user_namespace ? "true" : "false") +
           ",\"mount_namespace\":" + (config.mount_namespace ? "true" : "false") +
           ",\"network_namespace\":" + (config.network_namespace ? "true" : "false") +
           ",\"no_new_privileges\":" + (config.no_new_privileges ? "true" : "false") +
           ",\"capabilities_dropped\":" + (config.drop_capabilities ? "true" : "false") +
           ",\"seccomp\":" + (!config.seccomp_allowlist.empty() ? "true" : "false") +
           ",\"clean_environment\":" + (config.clean_environment ? "true" : "false") +
           ",\"cgroup\":" + (!config.cgroup.path.empty() ? "true" : "false") +
            ",\"rootfs\":\"" + rootfs + "\"}";
}

namespace {

class StderrTraceReporter final : public execell::report::Reporter {
public:
    void report(const execell::event::Event& event) override {
        const auto line = std::visit([](const auto& value) {
            using T = std::remove_cvref_t<decltype(value)>;
            std::string kind{"event"};
            if constexpr (std::is_same_v<T, execell::event::FileOpened>) kind = "file_opened";
            else if constexpr (std::is_same_v<T, execell::event::FileRead>) kind = "file_read";
            else if constexpr (std::is_same_v<T, execell::event::FileWritten>) kind = "file_written";
            else if constexpr (std::is_same_v<T, execell::event::NetworkConnected>) kind = "network_connected";
            else if constexpr (std::is_same_v<T, execell::event::NetworkBound>) kind = "network_bound";
            else if constexpr (std::is_same_v<T, execell::event::ProcessExec>) kind = "process_exec";
            else if constexpr (std::is_same_v<T, execell::event::ProcessSpawned>) kind = "process_spawned";
            else if constexpr (std::is_same_v<T, execell::event::ProcessExited>) kind = "process_exited";
            return "EXECELL_TRACE:{\"type\":\"" + kind + "\",\"pid\":" +
                   std::to_string(value.context.pid) + ",\"sequence\":" +
                   std::to_string(value.context.sequence) + "}\n";
        }, event);
        std::size_t offset{};
        while (offset < line.size()) {
            const auto written = ::write(STDERR_FILENO, line.data() + offset, line.size() - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return;
            offset += static_cast<std::size_t>(written);
        }
    }
};

[[nodiscard]] bool write_file(const char* path, const std::string& value)
{
    const int fd = ::open(path, O_WRONLY);
    if (fd < 0) {
        return false;
    }
    std::size_t offset{};
    while (offset < value.size()) {
        const auto written = ::write(fd, value.data() + offset, value.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)::close(fd);
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    const int close_result = ::close(fd);
    return close_result == 0;
}

[[nodiscard]] bool configure_cgroup(pid_t pid, const Config::CgroupBudget& budget)
{
    if (budget.path.empty()) return true;
    const auto write = [&](const char* name, const std::string& value) {
        const auto path = budget.path / name;
        return write_file(path.c_str(), value);
    };
    if (budget.memory_max != 0 && !write("memory.max", std::to_string(budget.memory_max)))
        return false;
    if (budget.pids_max != 0 && !write("pids.max", std::to_string(budget.pids_max)))
        return false;
    if (budget.cpu_quota_us != 0 &&
        !write("cpu.max", std::to_string(budget.cpu_quota_us) + " " +
                             std::to_string(budget.cpu_period_us)))
        return false;
    return write("cgroup.procs", std::to_string(pid));
}

[[nodiscard]] bool setup_user_namespace(pid_t pid, bool map_unprivileged_user)
{
    const auto uid = static_cast<unsigned long>(::getuid());
    const auto gid = static_cast<unsigned long>(::getgid());
    const std::string prefix = "/proc/" + std::to_string(pid) + "/";
    const auto map = [pid, map_unprivileged_user](const char* tool, unsigned long host_id) {
        const pid_t mapper = ::fork();
        if (mapper < 0) {
            return false;
        }
        if (mapper == 0) {
            const std::string pid_text = std::to_string(pid);
            const std::string id_text = std::to_string(host_id);
            if (map_unprivileged_user)
                ::execlp(tool, tool, pid_text.c_str(), "0", id_text.c_str(), "1", "1000",
                         id_text.c_str(), "1", nullptr);
            else
                ::execlp(tool, tool, pid_text.c_str(), "0", id_text.c_str(), "1", nullptr);
            ::_exit(127);
        }
        int status{};
        return ::waitpid(mapper, &status, 0) == mapper &&
               WIFEXITED(status) && WEXITSTATUS(status) == 0;
    };
    if (map("newuidmap", uid) && map("newgidmap", gid)) {
        return true;
    }
    const std::string mapping = "0 " + std::to_string(uid) + " 1\n" +
                                (map_unprivileged_user ? "1000 " + std::to_string(uid) + " 1\n" : "");
    return write_file((prefix + "uid_map").c_str(), mapping) &&
           write_file((prefix + "gid_map").c_str(), mapping);
}

void drop_capabilities() noexcept
{
    __user_cap_header_struct header{
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    __user_cap_data_struct data[2]{};
    (void)::syscall(SYS_capset, &header, data);
}

[[nodiscard]] bool clean_environment() noexcept
{
    if (::clearenv() != 0) return false;
    return ::setenv("PATH", "/usr/bin:/bin", 1) == 0 &&
           ::setenv("HOME", "/tmp", 1) == 0 &&
           ::setenv("TMPDIR", "/tmp", 1) == 0 &&
           ::setenv("LANG", "C", 1) == 0 &&
           ::setenv("LC_ALL", "C", 1) == 0;
}

[[nodiscard]] bool mount_runtime_filesystems(const Config& config) noexcept
{
    if (config.rootfs.empty()) return true;
    const auto prepare = [](const char* path) {
        struct stat info {};
        if (::lstat(path, &info) == 0) return S_ISDIR(info.st_mode);
        return errno == ENOENT && ::mkdir(path, 0755) == 0;
    };
    if (config.mount_proc) {
        if (!prepare("/proc") || ::mount("proc", "/proc", "proc",
                                          MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2") != 0)
            return false;
    }
    if (config.mount_run) {
        if (!prepare("/run") || ::mount("tmpfs", "/run", "tmpfs",
                                         MS_NOSUID | MS_NODEV | MS_NOEXEC,
                                         "size=16m,mode=0755") != 0)
            return false;
    }
    return true;
}

[[nodiscard]] bool install_seccomp(const std::vector<int>& allowlist)
{
    std::vector<sock_filter> filter;
    filter.reserve(allowlist.size() * 2U + 4U);
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                              static_cast<unsigned>(offsetof(seccomp_data, arch))));
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                              AUDIT_ARCH_X86_64, 1, 0));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                              static_cast<unsigned>(offsetof(seccomp_data, nr))));
    for (const int syscall_number : allowlist) {
        filter.push_back(BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K,
            static_cast<unsigned>(syscall_number),
            0,
            1));
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }
    filter.push_back(BPF_STMT(BPF_RET | BPF_K,
                              SECCOMP_RET_ERRNO | static_cast<unsigned>(EPERM)));
    sock_fprog program{
        .len = static_cast<unsigned short>(filter.size()),
        .filter = filter.data()
    };
    return ::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0;
}

[[nodiscard]] bool set_limits(const Config& config)
{
    if (config.cpu_seconds != 0) {
        const rlimit limit{
            .rlim_cur = config.cpu_seconds,
            .rlim_max = config.cpu_seconds
        };
        if (::setrlimit(RLIMIT_CPU, &limit) < 0) {
            return false;
        }
    }
    if (config.address_space_bytes != 0) {
        const rlimit limit{
            .rlim_cur = config.address_space_bytes,
            .rlim_max = config.address_space_bytes
        };
        if (::setrlimit(RLIMIT_AS, &limit) < 0) {
            return false;
        }
    }
    if (config.max_processes != 0) {
        const rlimit limit{.rlim_cur = config.max_processes, .rlim_max = config.max_processes};
        if (::setrlimit(RLIMIT_NPROC, &limit) < 0) return false;
    }
    if (config.max_file_bytes != 0) {
        const rlimit limit{.rlim_cur = config.max_file_bytes, .rlim_max = config.max_file_bytes};
        if (::setrlimit(RLIMIT_FSIZE, &limit) < 0) return false;
    }
    return true;
}

} // namespace

int run(char* const program, char* const argv[], const Config& config)
{
    if (const auto result = validate(config); !result) {
        std::cerr << "execell: invalid sandbox: " << result.error() << '\n';
        return EXIT_FAILURE;
    }

    int raw_sync_pipe[2]{};
    if (::pipe(raw_sync_pipe) < 0) {
        return EXIT_FAILURE;
    }
    UniqueFd sync_read{raw_sync_pipe[0]};
    UniqueFd sync_write{raw_sync_pipe[1]};

    const pid_t parent_pid = ::getpid();
    const pid_t pid = ::fork();
    if (pid < 0) {
        std::cerr << "execell: sandbox fork failed: " << std::strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    if (pid == 0) {
        sync_write.reset();
        if (::setpgid(0, 0) != 0) {
            ::_exit(127);
        }
        if (!set_parent_death_signal(parent_pid)) {
            ::_exit(127);
        }
        if (config.user_namespace && ::unshare(CLONE_NEWUSER) < 0) {
            std::cerr << "execell: user namespace failed: " << std::strerror(errno) << '\n';
            ::_exit(127);
        }
        if (config.user_namespace) {
            if (!write_file("/proc/self/setgroups", "deny\n")) {
                ::_exit(127);
            }
            char ready{};
            if (::read(sync_read.get(), &ready, 1) != 1) {
                ::_exit(127);
            }
        }
        sync_read.reset();
        if (config.mount_namespace && ::unshare(CLONE_NEWNS) < 0) {
            std::cerr << "execell: mount namespace failed: " << std::strerror(errno) << '\n';
            ::_exit(127);
        }
        if (config.mount_namespace) {
            if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
                std::cerr << "execell: mount propagation setup failed: "
                          << std::strerror(errno) << '\n';
                ::_exit(127);
            }
            if (config.read_only_root &&
                (::mount("/", "/", nullptr, MS_BIND | MS_REC, nullptr) < 0 ||
                 ::mount(nullptr, "/", nullptr,
                         MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, nullptr) < 0)) {
                std::cerr << "execell: read-only root setup failed: "
                          << std::strerror(errno) << '\n';
                ::_exit(127);
            }
        }
        if (!config.rootfs.empty()) {
            if (::chroot(config.rootfs.c_str()) != 0 || ::chdir("/") != 0) ::_exit(127);
            if (!mount_runtime_filesystems(config)) {
                std::cerr << "execell: rootfs runtime mount setup failed: "
                          << std::strerror(errno) << '\n';
                ::_exit(127);
            }
        }
        if (config.mount_namespace && ::mount(
                "tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=64m,inode32") < 0) {
            std::cerr << "execell: isolated /tmp failed: " << std::strerror(errno) << '\n';
            ::_exit(127);
        }
        if (!config.working_directory.empty() &&
            ::chdir(config.working_directory.c_str()) != 0) {
            ::_exit(127);
        }
        if (config.network_namespace && ::unshare(CLONE_NEWNET) < 0) {
            std::cerr << "execell: network namespace failed: " << std::strerror(errno) << '\n';
            ::_exit(127);
        }
        if (config.drop_capabilities) {
            drop_capabilities();
        }
        if (config.no_new_privileges && ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            std::cerr << "execell: no_new_privileges failed: " << std::strerror(errno) << '\n';
            ::_exit(127);
        }
        if (!config.seccomp_allowlist.empty() && !install_seccomp(config.seccomp_allowlist)) {
            std::cerr << "execell: seccomp setup failed: " << std::strerror(errno) << '\n';
            ::_exit(127);
        }
        if (!set_limits(config)) {
            std::cerr << "execell: resource limit setup failed: "
                      << std::strerror(errno) << '\n';
            ::_exit(127);
        }
        if (config.drop_to_unprivileged_user &&
            (::setresgid(1000, 1000, 1000) != 0 || ::setresuid(1000, 1000, 1000) != 0)) {
            ::_exit(127);
        }
        if (config.clean_environment && !clean_environment()) {
            ::_exit(127);
        }
        if (config.trace_events) {
            StderrTraceReporter reporter;
            ::_exit(execell::trace::run(program, argv, reporter));
        }
        ::execvp(program, argv);
        ::_exit(127);
    }

    if (::setpgid(pid, pid) != 0 && errno != EACCES && errno != ESRCH) {
        std::cerr << "execell: sandbox process-group setup failed: " << std::strerror(errno)
                  << '\n';
        (void)::kill(pid, SIGKILL);
        (void)::execell::linux_api::wait_for(pid);
        return EXIT_FAILURE;
    }
    if (!configure_cgroup(pid, config.cgroup)) {
        std::cerr << "execell: cgroup budget setup failed: " << std::strerror(errno) << '\n';
        (void)::kill(pid, SIGKILL);
        (void)::execell::linux_api::wait_for(pid);
        return EXIT_FAILURE;
    }

    sync_read.reset();
    if (config.user_namespace && !setup_user_namespace(pid, config.drop_to_unprivileged_user)) {
        std::cerr << "execell: user mapping failed: " << std::strerror(errno) << '\n';
        ::kill(pid, SIGKILL);
        sync_write.reset();
        (void)::execell::linux_api::wait_for(pid);
        return EXIT_FAILURE;
    }
    const char ready = 1;
    struct sigaction ignore_sigpipe{};
    ignore_sigpipe.sa_handler = SIG_IGN;
    sigemptyset(&ignore_sigpipe.sa_mask);
    struct sigaction previous_sigpipe{};
    (void)::sigaction(SIGPIPE, &ignore_sigpipe, &previous_sigpipe);
    (void)::write(sync_write.get(), &ready, 1);
    (void)::sigaction(SIGPIPE, &previous_sigpipe, nullptr);
    sync_write.reset();

    const auto waited = ::execell::linux_api::wait_for(pid);
    if (!waited) {
        return EXIT_FAILURE;
    }
    const int status = waited->status;
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return EXIT_FAILURE;
}

Captured run_captured(const std::vector<std::string>& args, const Config& config,
                      std::chrono::seconds timeout, std::size_t output_limit) {
    Captured result;
    if (args.empty()) return result;
    int out_pipe[2]{};
    int err_pipe[2]{};
    if (::pipe(out_pipe) != 0) return result;
    if (::pipe(err_pipe) != 0) {
        (void)::close(out_pipe[0]);
        (void)::close(out_pipe[1]);
        return result;
    }
    const pid_t child = ::fork();
    if (child < 0) {
        (void)::close(out_pipe[0]);
        (void)::close(out_pipe[1]);
        (void)::close(err_pipe[0]);
        (void)::close(err_pipe[1]);
        return result;
    }
    if (child == 0) {
        if (::setpgid(0, 0) != 0) ::_exit(127);
        (void)::dup2(out_pipe[1], STDOUT_FILENO);
        (void)::dup2(err_pipe[1], STDERR_FILENO);
        (void)::close(out_pipe[0]); (void)::close(out_pipe[1]);
        (void)::close(err_pipe[0]); (void)::close(err_pipe[1]);
        std::vector<char*> argv;
        argv.reserve(args.size() + 1U);
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        ::_exit(run(argv[0], argv.data(), config));
    }
    (void)::close(out_pipe[1]); (void)::close(err_pipe[1]);
    (void)::fcntl(out_pipe[0], F_SETFL, O_NONBLOCK);
    (void)::fcntl(err_pipe[0], F_SETFL, O_NONBLOCK);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    bool out_open = true, err_open = true;
    std::array<char, 4096> buffer{};
    std::size_t total_output{};
    const auto drain = [&](int fd, std::string& target, bool& open) {
        for (;;) {
            const ssize_t count = ::read(fd, buffer.data(), buffer.size());
            if (count > 0) {
                const auto bytes = static_cast<std::size_t>(count);
                const auto remaining = output_limit > total_output ? output_limit - total_output : 0U;
                if (remaining != 0U) target.append(buffer.data(), std::min(remaining, bytes));
                total_output += bytes;
                if (total_output >= output_limit) result.output_limited = true;
            } else if (count == 0 || (count < 0 && errno != EAGAIN && errno != EINTR)) {
                open = false;
                (void)::close(fd);
                break;
            } else break;
        }
    };
    int status{};
    while (out_open || err_open) {
        drain(out_pipe[0], result.stdout_data, out_open);
        drain(err_pipe[0], result.stderr_data, err_open);
        if (result.output_limited) {
            (void)::kill(-child, SIGKILL);
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            result.timed_out = true;
            (void)::kill(-child, SIGKILL);
            break;
        }
        struct pollfd fds[2]{{out_pipe[0], POLLIN, 0}, {err_pipe[0], POLLIN, 0}};
        (void)::poll(fds, 2, 10);
    }
    if (out_open) (void)::close(out_pipe[0]);
    if (err_open) (void)::close(err_pipe[0]);
    while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    if (result.timed_out) result.status = 124;
    else if (WIFEXITED(status)) result.status = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) result.status = 128 + WTERMSIG(status);
    return result;
}

} // namespace execell::sandbox
