#include <execell/sandbox/sandbox.hpp>
#include <execell/core/unique_fd.hpp>
#include <execell/linux/wait.hpp>

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
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

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
    return {};
}

namespace {

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

[[nodiscard]] bool setup_user_namespace(pid_t pid)
{
    const auto uid = static_cast<unsigned long>(::getuid());
    const auto gid = static_cast<unsigned long>(::getgid());
    const std::string prefix = "/proc/" + std::to_string(pid) + "/";
    const auto map = [pid](const char* tool, unsigned long host_id) {
        const pid_t mapper = ::fork();
        if (mapper < 0) {
            return false;
        }
        if (mapper == 0) {
            const std::string pid_text = std::to_string(pid);
            const std::string id_text = std::to_string(host_id);
            ::execlp(tool, tool, pid_text.c_str(), "0", id_text.c_str(), "1", nullptr);
            ::_exit(127);
        }
        int status{};
        return ::waitpid(mapper, &status, 0) == mapper &&
               WIFEXITED(status) && WEXITSTATUS(status) == 0;
    };
    (void)prefix;
    return map("newuidmap", uid) && map("newgidmap", gid);
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
        ::execvp(program, argv);
        ::_exit(127);
    }

    sync_read.reset();
    if (config.user_namespace && !setup_user_namespace(pid)) {
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
    if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) return result;
    const pid_t child = ::fork();
    if (child < 0) return result;
    if (child == 0) {
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
    const auto drain = [&](int fd, std::string& target, bool& open) {
        for (;;) {
            const ssize_t count = ::read(fd, buffer.data(), buffer.size());
            if (count > 0) {
                if (target.size() < output_limit)
                    target.append(buffer.data(), std::min(output_limit - target.size(),
                                                          static_cast<std::size_t>(count)));
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
        if (std::chrono::steady_clock::now() >= deadline) {
            result.timed_out = true;
            (void)::kill(child, SIGKILL);
            break;
        }
        struct pollfd fds[2]{{out_pipe[0], POLLIN, 0}, {err_pipe[0], POLLIN, 0}};
        (void)::poll(fds, 2, 10);
    }
    (void)::waitpid(child, &status, 0);
    if (result.timed_out) result.status = 124;
    else if (WIFEXITED(status)) result.status = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) result.status = 128 + WTERMSIG(status);
    return result;
}

} // namespace execell::sandbox
