#include <execell/package/rootfs.hpp>

#include <cerrno>
#include <charconv>
#include <algorithm>
#include <fstream>
#include <fcntl.h>
#include <linux/btrfs.h>
#include <linux/magic.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace execell::package::rootfs {
namespace {

char *guardian_arguments[7]{};

void guardian_cleanup(int) noexcept {
    (void)::execv("/bin/rm", guardian_arguments);
    _exit(0);
}

bool btrfs(const std::filesystem::path &path) noexcept {
    struct statfs info {};
    return ::statfs(path.c_str(), &info) == 0 && info.f_type == BTRFS_SUPER_MAGIC;
}

bool enabled(const char *path) noexcept {
    std::ifstream input(path);
    long value{};
    return input >> value && value > 0;
}

bool capability(unsigned int bit) noexcept {
    std::ifstream input("/proc/self/status");
    std::string line;
    while (std::getline(input, line)) {
        if (!line.starts_with("CapEff:"))
            continue;
        unsigned long long value{};
        const auto text = line.substr(8);
        (void)std::from_chars(text.data(), text.data() + text.size(), value, 16);
        return (value & (1ULL << bit)) != 0U;
    }
    return false;
}

bool snapshot(const std::filesystem::path &source, const std::filesystem::path &parent,
              const std::string &name, bool readonly) noexcept {
    const int source_fd = ::open(source.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const int parent_fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (source_fd < 0 || parent_fd < 0) {
        if (source_fd >= 0) (void)::close(source_fd);
        if (parent_fd >= 0) (void)::close(parent_fd);
        return false;
    }
    btrfs_ioctl_vol_args_v2 args{};
    args.fd = source_fd;
    args.flags = readonly ? BTRFS_SUBVOL_RDONLY : 0U;
    args.size = name.size();
    std::copy(name.begin(), name.end(), args.name);
    const bool ok = ::ioctl(parent_fd, BTRFS_IOC_SNAP_CREATE_V2, &args) == 0;
    (void)::close(source_fd);
    (void)::close(parent_fd);
    return ok;
}

bool create_subvolume(const std::filesystem::path &parent, const std::string &name) noexcept {
    const int parent_fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd < 0)
        return false;
    btrfs_ioctl_vol_args_v2 args{};
    args.size = name.size();
    std::copy(name.begin(), name.end(), args.name);
    const bool ok = ::ioctl(parent_fd, BTRFS_IOC_SUBVOL_CREATE_V2, &args) == 0;
    (void)::close(parent_fd);
    return ok;
}

void remove_path(const std::filesystem::path &path) noexcept {
    std::error_code error;
    if (!path.empty())
        std::filesystem::remove_all(path, error);
}

pid_t launch_guardian(const std::filesystem::path &source, const std::filesystem::path &writable,
                     const std::filesystem::path &base, const std::filesystem::path &workspace) {
    const pid_t guardian = ::fork();
    if (guardian != 0)
        return guardian;
    guardian_arguments[0] = const_cast<char *>("rm");
    guardian_arguments[1] = const_cast<char *>("-rf");
    guardian_arguments[2] = const_cast<char *>(source.c_str());
    guardian_arguments[3] = const_cast<char *>(writable.c_str());
    guardian_arguments[4] = const_cast<char *>(base.c_str());
    guardian_arguments[5] = const_cast<char *>(workspace.c_str());
    guardian_arguments[6] = nullptr;
    (void)::prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (::getppid() == 1) _exit(0);
    struct sigaction action{};
    action.sa_handler = guardian_cleanup;
    sigemptyset(&action.sa_mask);
    (void)::sigaction(SIGTERM, &action, nullptr);
    for (;;) pause();
}

} // namespace

Capabilities detect(const std::filesystem::path &path) {
    const bool user = enabled("/proc/sys/user/max_user_namespaces");
    const bool mount = ::access("/proc/self/ns/mnt", R_OK) == 0;
    const bool admin = capability(21U); // CAP_SYS_ADMIN
    return {.btrfs = btrfs(path),
            .rootless = user && mount,
            .rootful = ::geteuid() == 0 && admin,
            .user_namespace = user,
            .mount_namespace = mount};
}

Session::Session(Session &&other) noexcept
    : source_(std::move(other.source_)), writable_(std::move(other.writable_)),
      workspace_(std::move(other.workspace_)),
      base_(std::move(other.base_)),
      guardian_(std::exchange(other.guardian_, -1)), mode_(other.mode_) {}

Session &Session::operator=(Session &&other) noexcept {
    if (this != &other) {
        release();
        source_ = std::move(other.source_);
        writable_ = std::move(other.writable_);
        workspace_ = std::move(other.workspace_);
        base_ = std::move(other.base_);
        guardian_ = std::exchange(other.guardian_, -1);
        mode_ = other.mode_;
    }
    return *this;
}

Session::~Session() { release(); }

std::expected<Session, std::string> Session::create(const std::filesystem::path &source,
                                                    const std::filesystem::path &workspace) {
    std::error_code error;
    if (workspace.empty() || std::filesystem::is_symlink(workspace, error))
        return std::unexpected{"rootfs workspace must not be symlink"};
    std::filesystem::create_directories(workspace, error);
    if (error)
        return std::unexpected{"rootfs workspace creation failed: " + error.message()};

    Session result;
    result.workspace_ = workspace;
    const auto base = source.empty() ? workspace : source;
    if (!std::filesystem::exists(base) || !btrfs(base)) {
        result.writable_ = workspace / ("rootfs-" + std::to_string(::getpid()));
        std::filesystem::create_directories(result.writable_, error);
        if (error)
            return std::unexpected{"temporary rootfs creation failed: " + error.message()};
        result.mode_ = Mode::degraded;
        return result;
    }

    const auto stamp = std::to_string(::getpid()) + "-" + std::to_string(::getuid());
    const auto parent = source.empty() ? workspace : source.parent_path();
    std::filesystem::path snapshot_source = source;
    if (source.empty()) {
        result.base_ = workspace / (".execell-base-" + stamp);
        if (!create_subvolume(workspace, result.base_.filename().string()))
            return std::unexpected{"Btrfs base subvolume creation failed"};
        snapshot_source = result.base_;
    }
    result.source_ = parent / (".execell-source-" + stamp);
    result.writable_ = parent / (".execell-session-" + stamp);
    if (std::filesystem::exists(result.source_) || std::filesystem::exists(result.writable_))
        return std::unexpected{"rootfs session name collision"};

    if (!snapshot(snapshot_source, parent, result.source_.filename().string(), true) ||
        !snapshot(result.source_, parent, result.writable_.filename().string(), false)) {
        remove_path(result.base_);
        remove_path(result.source_);
        remove_path(result.writable_);
        result.source_.clear();
        result.writable_.clear();
        result.writable_ = workspace / ("rootfs-" + std::to_string(::getpid()));
        std::filesystem::create_directories(result.writable_, error);
        if (error)
            return std::unexpected{"rootfs snapshot and fallback creation failed: " + error.message()};
        result.mode_ = Mode::degraded;
        result.guardian_ = launch_guardian(result.source_, result.writable_, result.base_, result.workspace_);
        return result;
    }
    result.mode_ = Mode::btrfs;
    result.guardian_ = launch_guardian(result.source_, result.writable_, result.base_, result.workspace_);
    return result;
}

std::string Session::event() const {
    return isolated() ? "{\"schema_version\":1,\"type\":\"rootfs_btrfs\"}"
                      : "{\"schema_version\":1,\"type\":\"rootfs_degraded\",\"isolated\":false}";
}

void Session::release() noexcept {
    remove_path(source_);
    remove_path(writable_);
    remove_path(base_);
    if (guardian_ > 0) {
        (void)::kill(guardian_, SIGTERM);
        (void)::waitpid(guardian_, nullptr, 0);
        guardian_ = -1;
    }
    source_.clear();
    writable_.clear();
    remove_path(workspace_);
    workspace_.clear();
    base_.clear();
}

} // namespace execell::package::rootfs
