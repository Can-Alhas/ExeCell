#include <execell/package/package.hpp>
#include <execell/package/archive.hpp>
#include <execell/package/rootfs.hpp>
#include <execell/package/observation.hpp>
#include <execell/package/network.hpp>
#include <execell/risk/risk.hpp>
#ifdef EXECELL_HAVE_SQLITE
#include <execell/package/storage.hpp>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <execell/sandbox/sandbox.hpp>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace execell::package {
namespace {

constexpr std::size_t max_command_output = 1U << 20U;

std::string value(std::string_view text, std::string_view key) {
    const std::string prefix = std::string(key) + " = ";
    const std::size_t start = text.find(prefix);
    if (start == std::string_view::npos)
        return {};
    const std::size_t begin = start + prefix.size();
    const std::size_t end = text.find('\n', begin);
    return std::string(
        text.substr(begin, end == std::string_view::npos ? text.size() - begin : end - begin));
}
std::vector<std::string> values(std::string_view text, std::string_view key) {
    std::vector<std::string> result;
    const std::string prefix = std::string(key) + " = ";
    std::size_t pos = 0;
    while ((pos = text.find(prefix, pos)) != std::string_view::npos) {
        const std::size_t begin = pos + prefix.size();
        const std::size_t end = text.find('\n', begin);
        result.emplace_back(
            text.substr(begin, end == std::string_view::npos ? text.size() - begin : end - begin));
        pos = begin;
    }
    return result;
}
std::string json_escape(std::string_view s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\')
            out += '\\';
        if (c == '\n') {
            out += "\\n";
            continue;
        }
        if (c == '\r') {
            out += "\\r";
            continue;
        }
        if (c == '\t') {
            out += "\\t";
            continue;
        }
        out += c;
    }
    return out;
}

std::string json_array(const std::vector<std::string> &values) {
    std::string out{"["};
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0U)
            out += ',';
        out += '"' + json_escape(values[i]) + '"';
    }
    return out + ']';
}

std::string json_object_array(const std::vector<std::string> &values) {
    std::string out{"["};
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0U) out += ',';
        out += values[index];
    }
    return out + ']';
}

std::string fingerprint(std::string_view value) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char character : value) {
        hash ^= static_cast<unsigned char>(character);
        hash *= 1099511628211ULL;
    }
    return std::to_string(hash);
}

std::string file_fingerprint(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::uint64_t hash = 1469598103934665603ULL;
    std::array<char, 8192> buffer{};
    while (input.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || input.gcount() > 0) {
        for (std::streamsize index = 0; index < input.gcount(); ++index) {
            hash ^= static_cast<unsigned char>(buffer[static_cast<std::size_t>(index)]);
            hash *= 1099511628211ULL;
        }
    }
    return std::to_string(hash);
}

bool write_root_file(const std::filesystem::path& root, std::string_view relative,
                     std::string_view data, bool exclusive) {
    const int root_fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) return false;
    const std::string relative_path(relative);
    const open_how how{
        .flags = static_cast<std::uint64_t>(O_WRONLY | O_CREAT | O_CLOEXEC |
                                            (exclusive ? O_EXCL : O_TRUNC)),
        .mode = 0700,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS};
    const int fd = static_cast<int>(::syscall(SYS_openat2, root_fd, relative_path.c_str(), &how,
                                              sizeof(how)));
    const int saved = errno;
    (void)::close(root_fd);
    if (fd < 0) {
        errno = saved;
        return false;
    }
    std::size_t offset{};
    while (offset < data.size()) {
        const ssize_t count = ::write(fd, data.data() + offset, data.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            (void)::close(fd);
            return false;
        }
        if (count == 0) {
            (void)::close(fd);
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    return ::close(fd) == 0;
}

bool package_name(std::string_view path) {
    return path.ends_with(".pkg.tar.zst") || path.ends_with(".pkg.tar.xz") ||
           path.ends_with(".pkg.tar.gz") || path.ends_with(".pkg.tar.bz2") ||
           path.ends_with(".pkg.tar.lrz") || path.ends_with(".pkg.tar.lzo") ||
           path.ends_with(".pkg.tar.lz4") || path.ends_with(".pkg.tar.lz");
}

Result inspect(const std::filesystem::path &package, const Options &options) {
    Result result;
    result.metadata.package = package;
    if (!package_name(package.filename().string())) {
        result.error = "unsupported package: expected .pkg.tar.*";
        return result;
    }
    if (!std::filesystem::is_regular_file(package) || std::filesystem::is_symlink(package)) {
        result.error = "package does not exist";
        return result;
    }
    const auto info = archive_adapter::read(package, ".PKGINFO", 1U << 20U);
    if (!info) {
        result.error = info.error();
        return result;
    }
    result.metadata.name = value(*info, "pkgname");
    result.metadata.version = value(*info, "pkgver");
    result.metadata.architecture = value(*info, "arch");
    result.metadata.dependencies = values(*info, "depend");
    if (result.metadata.name.empty() || result.metadata.version.empty() ||
        result.metadata.architecture.empty()) {
        result.error = "package metadata missing required identity fields";
        return result;
    }
    if (result.metadata.architecture != "x86_64" && result.metadata.architecture != "any") {
        result.error = "unsupported architecture: " + result.metadata.architecture;
        return result;
    }
    const auto listing = archive_adapter::list(package);
    if (!listing) {
        result.error = listing.error();
        return result;
    }
    for (const auto& entry : *listing) {
        const std::string &path = entry.path;
        result.metadata.files.push_back(path);
        if (path == ".INSTALL" || path.ends_with("/.INSTALL"))
            result.metadata.scripts.push_back(path);
        if (path.ends_with(".hook") || path.find("/hooks/") != std::string::npos)
            result.metadata.hooks.push_back(path);
    }
    const std::filesystem::path sig = package.string() + ".sig";
    if (!std::filesystem::exists(sig) || std::filesystem::is_symlink(sig)) {
        result.error = "signature verification failed: detached signature missing";
        return result;
    }
    if (::access("/usr/bin/gpgv", X_OK) != 0) {
        result.error = "signature verification unavailable: gpgv missing";
        return result;
    }
    const auto keyring = std::filesystem::exists("/etc/pacman.d/gnupg/pubring.gpg")
                             ? "/etc/pacman.d/gnupg/pubring.gpg"
                             : "/etc/pacman.d/gnupg/pubring.kbx";
    if (!std::filesystem::exists(keyring)) {
        result.error = "signature verification unavailable: Arch keyring missing";
        return result;
    }
    sandbox::Config verify_config;
    verify_config.user_namespace = true;
    verify_config.mount_namespace = true;
    verify_config.network_namespace = true;
    verify_config.read_only_root = true;
    verify_config.clean_environment = true;
    verify_config.cpu_seconds = static_cast<std::uint64_t>(options.timeout.count());
    verify_config.max_processes = 32;
    verify_config.max_file_bytes = 16U * 1024U * 1024U;
    verify_config.seccomp_allowlist = sandbox::default_package_syscalls();
    const auto verify = sandbox::run_captured(
        {"/usr/bin/gpgv", "--keyring", keyring, sig.string(), package.string()},
        verify_config, options.timeout);
    if (verify.timed_out || verify.status != 0) {
        result.error = verify.timed_out ? "signature verification timed out"
                                        : "signature verification failed";
        return result;
    }
    result.metadata.signature = "valid";
    result.ok = true;
    return result;
}

struct FileState {
    std::uintmax_t size{};
    std::uint32_t mode{};
    std::uint32_t uid{};
    std::uint32_t gid{};
    std::string hash;
};

std::map<std::string, FileState> snapshot(const std::filesystem::path &root) {
    std::map<std::string, FileState> result;
    if (!std::filesystem::exists(root))
        return result;
    for (const auto &entry : std::filesystem::recursive_directory_iterator(
             root, std::filesystem::directory_options::skip_permission_denied)) {
        const auto status = entry.symlink_status();
        const auto relative = std::filesystem::relative(entry.path(), root).string();
        if (std::filesystem::is_regular_file(status)) {
            const auto permissions = static_cast<std::uint32_t>(status.permissions());
            struct stat native_status {};
            (void)::lstat(entry.path().c_str(), &native_status);
            result[relative] = {.size = entry.file_size(),
                                .mode = permissions,
                                .uid = static_cast<std::uint32_t>(native_status.st_uid),
                                .gid = static_cast<std::uint32_t>(native_status.st_gid),
                                .hash = file_fingerprint(entry.path())};
        } else if (std::filesystem::is_symlink(status)) {
            result[relative] = {.mode = static_cast<std::uint32_t>(status.permissions()),
                                .hash = fingerprint(std::filesystem::read_symlink(entry.path()).string())};
        }
    }
    return result;
}

bool write_artifacts(const Result &result) {
    std::error_code ec;
    std::filesystem::create_directories(result.session, ec);
    if (ec)
        return false;
    const auto write = [&](const std::filesystem::path &path, const std::string &text) {
        std::ofstream output(path, std::ios::binary);
        output << text;
        return output.good();
    };
    const auto metadata = std::string{"{\"schema_version\":2,\"package\":\""} +
                          json_escape(result.metadata.package.string()) + "\",\"name\":\"" +
                          json_escape(result.metadata.name) + "\",\"version\":\"" +
                          json_escape(result.metadata.version) + "\",\"architecture\":\"" +
                          json_escape(result.metadata.architecture) + "\",\"signature\":\"" +
                          json_escape(result.metadata.signature) +
                          "\",\"dependencies\":" + json_array(result.metadata.dependencies) +
                          ",\"scripts\":" + json_array(result.metadata.scripts) +
                           ",\"hooks\":" + json_array(result.metadata.hooks) +
                           ",\"files\":" + json_array(result.metadata.files) +
                           ",\"executables\":" + json_array(result.metadata.executables) +
                           ",\"executable_fingerprints\":" +
                           json_array(result.metadata.executable_fingerprints) + "}\n";
    const auto summary =
         "{\"schema_version\":2,\"ok\":" + std::string(result.ok ? "true" : "false") +
         ",\"risk_score\":" + std::to_string(result.risk_score) + ",\"verdict\":\"" +
         json_escape(result.verdict) + "\",\"coverage_confidence\":" +
         std::to_string(result.coverage_confidence) + "}\n";
    const auto filesystem = "{\"schema_version\":2,\"created\":" + json_array(result.created) +
                            ",\"modified\":" + json_array(result.modified) +
                            ",\"deleted\":" + json_array(result.deleted) +
                            ",\"mode_changed\":" + json_array(result.mode_changed) +
                            ",\"ownership_changed\":" + json_array(result.ownership_changed) +
                            ",\"hash_changed\":" + json_array(result.hash_changed) + "}\n";
    const auto processes = "{\"schema_version\":1,\"events\":" +
                           json_object_array(result.process_events) + "}\n";
    const auto network = "{\"schema_version\":1,\"events\":" +
                         json_object_array(result.network_events) + "}\n";
    const auto risk = "{\"schema_version\":2,\"score\":" + std::to_string(result.risk_score) +
                      ",\"verdict\":\"" + json_escape(result.verdict) +
                      "\",\"factors\":" + json_array(result.risk_factors) +
                      ",\"coverage\":" + json_array(result.coverage) +
                      ",\"coverage_confidence\":" + std::to_string(result.coverage_confidence) + "}\n";
    bool ok = write(result.session / "metadata.json", metadata) &&
              write(result.session / "summary.json", summary) &&
              write(result.session / "filesystem.json", filesystem) &&
              write(result.session / "processes.json", processes) &&
              write(result.session / "network.json", network) &&
              write(result.session / "risk.json", risk);
    std::ofstream events(result.session / "events.jsonl", std::ios::binary);
    for (const auto &event : result.events)
        events << event << '\n';
    return ok && events.good();
}

} // namespace

Result scan(const std::filesystem::path &package, const Options &options) {
    if (options.privileged) {
        Result result;
        result.error = "privileged package scanning is disabled: rootless mode required";
        result.risk_level = "critical";
        result.risk_action = "reject";
        return result;
    }
    Result result = inspect(package, options);
    if (!result.ok) {
        execell::risk::Engine risk;
        if (result.error.find("signature") != std::string::npos)
            risk.reject("signature", result.error);
        else if (result.error.find("architecture") != std::string::npos)
            risk.reject("architecture", result.error);
        else if (result.error.find("unsafe") != std::string::npos ||
                 result.error.find("escape") != std::string::npos)
            risk.reject("escape", result.error);
        else
            risk.reject("package_validation", result.error);
        const auto assessment = risk.assess();
        result.risk_score = assessment.score;
        result.risk_level = std::string(execell::risk::to_string(assessment.level));
        result.risk_action = std::string(execell::risk::to_string(assessment.action));
        return result;
    }
    if (options.network == "mirror" && options.mirrors.empty()) {
        result.ok = false;
        result.error = "mirror network policy requires at least one --mirror allowlist entry";
        result.risk_level = "critical";
        result.risk_action = "reject";
        return result;
    }
    for (const auto& mirror : options.mirrors) {
        if (!network::valid_mirror(mirror)) {
            result.ok = false;
            result.error = "invalid mirror allowlist entry: " + mirror;
            result.risk_level = "critical";
            result.risk_action = "reject";
            return result;
        }
    }
    std::error_code ec;
    const auto unique_directory = [](const std::filesystem::path &parent, std::string_view prefix) {
        for (unsigned int attempt = 0; attempt < 1000U; ++attempt) {
            const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            const auto candidate =
                parent / (std::string(prefix) + std::to_string(::getpid()) + "-" +
                          std::to_string(stamp) + "-" + std::to_string(attempt));
            std::error_code create_error;
            if (std::filesystem::create_directory(candidate, create_error))
                return candidate;
            if (create_error && create_error != std::errc::file_exists)
                return std::filesystem::path{};
        }
        return std::filesystem::path{};
    };
    const auto temp = std::filesystem::temp_directory_path(ec);
    const auto artifact_parent = options.session_root;
    if (std::filesystem::is_symlink(artifact_parent, ec)) {
        result.ok = false;
        result.error = "session root must not be symlink";
        return result;
    }
    if (!std::filesystem::exists(artifact_parent, ec))
        std::filesystem::create_directories(artifact_parent, ec);
    const auto artifact =
        ec ? std::filesystem::path{} : unique_directory(artifact_parent, "session-");
    result.session = artifact;
    if (ec) {
        result.ok = false;
        result.error = "rootfs creation failed: " + ec.message();
        return result;
    }
    if (artifact.empty()) {
        result.ok = false;
        result.error = "unique session directory creation failed";
        return result;
    }
    const auto root_workspace = unique_directory(temp, "execell-rootfs-");
    if (root_workspace.empty()) {
        result.ok = false;
        result.error = "rootfs workspace creation failed";
        return result;
    }
    auto rootfs_result = rootfs::Session::create(options.rootfs, root_workspace);
    if (!rootfs_result) {
        result.ok = false;
        result.error = rootfs_result.error();
        return result;
    }
    auto root_session = std::move(*rootfs_result);
    if (!root_session.isolated()) {
        result.ok = false;
        result.error = "scan rejected: Btrfs rootfs isolation unavailable";
        result.risk_level = "critical";
        result.risk_action = "reject";
        return result;
    }
    const auto &root = root_session.path();
    result.events.push_back(root_session.event());
    const auto before = snapshot(root);
    if (std::filesystem::exists(root / "usr/bin/pacman")) {
        std::filesystem::create_directories(root / "var/lib/pacman", ec);
        std::filesystem::create_directories(root / "var/cache/pacman/pkg", ec);
        const auto staged_package = root / "var/cache/pacman/pkg" / package.filename();
        std::ifstream input(package, std::ios::binary);
        const std::string package_data{std::istreambuf_iterator<char>(input), {}};
        if (!input.eof()) {
            result.error = "package staging failed";
            result.ok = false;
            return result;
        }
        if (!write_root_file(root,
                             "var/cache/pacman/pkg/" + package.filename().string(),
                             package_data, false)) {
            result.error = "package staging write failed";
            result.ok = false;
            return result;
        }
        sandbox::Config install_config;
        install_config.rootfs = root;
        install_config.read_only_root = false;
        install_config.clean_environment = true;
        install_config.user_namespace = true;
        install_config.mount_namespace = true;
        install_config.network_namespace = true;
        install_config.cpu_seconds = static_cast<std::uint64_t>(options.timeout.count());
        install_config.max_processes = 128;
        install_config.max_file_bytes = 128U * 1024U * 1024U;
        install_config.seccomp_allowlist = sandbox::default_package_syscalls();
        install_config.cgroup.path = options.cgroup_root;
        const auto installed = sandbox::run_captured(
            {"/usr/bin/pacman", "-U", "--noconfirm", "--root", "/", "--dbpath",
             "/var/lib/pacman", "/var/cache/pacman/pkg/" + package.filename().string()},
            install_config, options.timeout);
        if (installed.timed_out || installed.status != 0) {
            result.error =
                installed.timed_out ? "pacman install timed out" : "pacman install failed";
            result.ok = false;
            return result;
        }
        result.installed = true;
    } else
        result.risk_factors.push_back("rootless pacman runtime unavailable; install behavior not observed");
    const auto after = snapshot(root);
    for (const auto &[path, state] : after) {
        const auto old = before.find(path);
        if (old == before.end())
            result.created.push_back(path);
        else {
            if (old->second.size != state.size) result.modified.push_back(path);
            if (old->second.mode != state.mode) result.mode_changed.push_back(path);
            if (old->second.uid != state.uid || old->second.gid != state.gid)
                result.ownership_changed.push_back(path);
            if (old->second.hash != state.hash) result.hash_changed.push_back(path);
        }
    }
    for (const auto &[path, state] : before)
        if (!after.contains(path)) {
            (void)state;
            result.deleted.push_back(path);
        }
    const std::size_t executable_limit = std::min<std::size_t>(result.metadata.files.size(), 128U);
    const auto stage = [&](const std::string &path) {
        const auto target = root / path;
        if (std::filesystem::exists(target)) return;
        const auto content = archive_adapter::read(package, path, max_command_output);
        if (!content) return;
        std::filesystem::create_directories(target.parent_path(), ec);
        (void)write_root_file(root, path, *content, true);
    };
    for (std::size_t index = 0; index < executable_limit; ++index) {
        const std::string &path = result.metadata.files[index];
        const auto content = archive_adapter::read(package, path, max_command_output);
        if (!content)
            continue;
        const bool elf =
            content->size() >= 4U && static_cast<unsigned char>((*content)[0]) == 0x7fU &&
            (*content)[1] == 'E' && (*content)[2] == 'L' && (*content)[3] == 'F';
        if (!elf && !content->starts_with("#!"))
            continue;
        result.metadata.executables.push_back(path);
        result.metadata.executable_fingerprints.push_back(path + ":" + fingerprint(*content));
        stage(path);
    }
    for (const auto &path : result.metadata.scripts) stage(path);
    for (const auto &path : result.metadata.hooks) stage(path);
    observation::Options observation_options{.timeout = options.timeout,
                                             .global_timeout = options.timeout,
                                             .network = options.network == "mirror",
                                             .run_all = options.run_all,
                                             .max_workers = options.workers,
                                             .cgroup_root = options.cgroup_root};
    const auto observed = observation::observe(root, result.metadata.scripts,
                                               result.metadata.hooks,
                                               result.metadata.executables,
                                               observation_options);
    result.smoke_scans = observed.smoke;
    result.process_events = observed.processes;
    result.network_events = observed.network;
    result.events.insert(result.events.end(), observed.events.begin(), observed.events.end());
    result.coverage = observed.coverage;
    const auto expected_observations = result.metadata.scripts.size() +
                                       result.metadata.hooks.size() +
                                       result.metadata.executables.size();
    result.coverage_confidence = expected_observations == 0U
                                     ? 0
                                     : static_cast<int>(std::min<std::size_t>(
                                           100U, result.coverage.size() * 100U / expected_observations));
    result.risk_factors.insert(result.risk_factors.end(), observed.risk_factors.begin(),
                               observed.risk_factors.end());
    execell::risk::Engine risk;
    if (!result.installed) risk.add("rootless", 5, "package install scripts were not executed");
    if (!result.metadata.scripts.empty()) risk.add("scripts", 15, "maintainer scripts execute package-provided code");
    if (!result.metadata.hooks.empty()) risk.add("hooks", 20, "package hooks can execute during installation");
    if (!result.created.empty()) risk.add("filesystem", static_cast<int>(std::min<std::size_t>(result.created.size() * 2U, 20U)), "package changed files in isolated rootfs");
    if (!result.mode_changed.empty()) risk.add("file_modes", 15, "package changed file permissions");
    if (!result.ownership_changed.empty()) risk.add("file_ownership", 20, "package changed file ownership");
    if (!result.hash_changed.empty()) risk.add("file_hashes", 10, "package changed file contents");
    if (!result.network_events.empty() && options.network == "mirror") risk.add("network", 15, "package attempted network access under mirror policy");
    for (const auto& factor : observed.risk_factors) risk.add("observation", 10, factor);
    const auto assessment = risk.assess();
    result.risk_score = assessment.score;
    result.risk_level = std::string(execell::risk::to_string(assessment.level));
    result.risk_action = std::string(execell::risk::to_string(assessment.action));
    result.verdict = result.risk_action;
    if (assessment.action == execell::risk::Action::reject) result.ok = false;
    for (const auto& factor : assessment.factors)
        result.risk_factors.push_back(factor.name + ": " + factor.explanation);
    result.events.push_back("{\"schema_version\":1,\"type\":\"network_policy\",\"mode\":\"" + options.network + "\",\"allowlist\":" + json_array(options.mirrors) + "}");
    result.events.push_back("{\"schema_version\":1,\"type\":\"scan_complete\"}");
#ifdef EXECELL_HAVE_SQLITE
    try {
        std::error_code database_error;
        const auto parent = options.database.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent, database_error);
        if (!database_error) {
            auto database = storage::Database::open(options.database);
            storage::PackageIdentity identity{
                result.metadata.name,
                result.metadata.version,
                result.metadata.architecture,
                result.metadata.signature,
                {},
                fingerprint(json_array(result.metadata.dependencies)),
                file_fingerprint(package),
                options.rootfs.string(),
                fingerprint(json_array(result.metadata.files)),
                fingerprint(json_object_array(result.events))};
            const auto previous = database.previous_version(identity.name, identity.version);
            std::vector<storage::Event> events;
            events.reserve(result.events.size());
            for (const auto& event : result.events)
                events.push_back({"observation", "event", result.metadata.name, event, true});
            result.baseline = database.store(identity, events).baseline;
            if (previous) {
                const auto delta = database.compare(identity.name, *previous, identity.version);
                if (delta.compared && (delta.identity_changed || delta.source_changed ||
                                       delta.dependencies_changed || !delta.added_events.empty())) {
                    result.risk_factors.emplace_back("behavioral delta from version " + *previous);
                    result.risk_score = std::min(100, result.risk_score + 15);
                    result.risk_level = result.risk_score >= 50 ? "high" : "medium";
                    result.risk_action = result.risk_score >= 50 ? "reject" : "audit";
                    result.verdict = result.risk_action;
                }
            }
        } else {
            result.risk_factors.push_back("SQLite database parent creation failed");
        }
    } catch (const std::exception& error) {
        result.risk_factors.push_back(std::string{"SQLite observation storage failed: "} + error.what());
    }
#endif
    if (!write_artifacts(result))
        result.events.push_back("{\"schema_version\":1,\"type\":\"artifact_error\"}");
    return result;
}

Result fetch(const std::string &target, const Options &options) {
    Result result;
    (void)target;
    (void)options;
    result.error = "fetch unavailable: download phase requires isolated network sandbox";
    return result;
}

Result compare(const std::string& name, const std::string& from, const std::string& to,
               const Options& options) {
    Result result;
#ifdef EXECELL_HAVE_SQLITE
    try {
        std::error_code database_error;
        const auto parent = options.database.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent, database_error);
        if (database_error) {
            result.error = "SQLite database parent creation failed: " + database_error.message();
            return result;
        }
        const auto database = storage::Database::open(options.database);
        const auto delta = database.compare(name, from, to);
        result.ok = delta.compared;
        result.report_data =
            "{\"schema_version\":1,\"package\":\"" + json_escape(name) +
            "\",\"from\":\"" + json_escape(from) + "\",\"to\":\"" +
            json_escape(to) + "\",\"compared\":" + (delta.compared ? "true" : "false") +
            ",\"from_baseline\":" + (delta.from_baseline ? "true" : "false") +
            ",\"identity_changed\":" + (delta.identity_changed ? "true" : "false") +
            ",\"source_changed\":" + (delta.source_changed ? "true" : "false") +
            ",\"dependencies_changed\":" + (delta.dependencies_changed ? "true" : "false") +
            ",\"added_events\":" + json_array(delta.added_events) +
            ",\"removed_events\":" + json_array(delta.removed_events) + "}\n";
        if (!result.ok) result.error = "no observations for requested versions";
    } catch (const std::exception& error) {
        result.error = std::string{"SQLite comparison failed: "} + error.what();
    }
#else
    (void)name;
    (void)from;
    (void)to;
    (void)options;
    result.error = "SQLite baseline storage unavailable";
#endif
    return result;
}

Result report(const std::filesystem::path &session, const Options &) {
    Result result;
    result.session = session;
    std::ifstream input(session / "summary.json");
    if (!input) {
        result.error = "session report missing: " + (session / "summary.json").string();
        return result;
    }
    result.ok = true;
    result.report_data.assign(std::istreambuf_iterator<char>(input), {});
    return result;
}
Result cleanup(const Options &options) {
    Result result;
    std::error_code ec;
    if (std::filesystem::is_directory(options.session_root, ec) &&
        !std::filesystem::is_symlink(options.session_root, ec)) {
        for (const auto &entry : std::filesystem::directory_iterator(options.session_root, ec)) {
            if (ec)
                break;
            if (entry.is_directory(ec) && !entry.is_symlink(ec) &&
                entry.path().filename().string().starts_with("session-"))
                std::filesystem::remove_all(entry.path(), ec);
        }
    }
    const auto temp = std::filesystem::temp_directory_path(ec);
    if (!ec && std::filesystem::is_directory(temp, ec))
        for (const auto &entry : std::filesystem::directory_iterator(temp, ec)) {
            if (ec)
                break;
            if (entry.is_directory(ec) && !entry.is_symlink(ec) &&
                entry.path().filename().string().starts_with("execell-package-"))
                std::filesystem::remove_all(entry.path(), ec);
        }
    result.ok = !ec;
    if (ec)
        result.error = "cleanup failed: " + ec.message();
    return result;
}

void print(const Result &result, const Options &options) {
    if (!result.report_data.empty() && (options.format == "json" || options.format == "jsonl")) {
        std::cout << result.report_data;
        return;
    }
    if (options.format == "jsonl") {
        for (const auto &event : result.events) std::cout << event << '\n';
        return;
    }
    if (options.format == "json") {
        std::cout << "{\"ok\":" << (result.ok ? "true" : "false") << ",\"error\":\""
                  << json_escape(result.error) << "\",\"package\":\""
                  << json_escape(result.metadata.package.string()) << "\",\"name\":\""
                  << json_escape(result.metadata.name) << "\",\"version\":\""
                  << json_escape(result.metadata.version) << "\",\"architecture\":\""
                  << json_escape(result.metadata.architecture) << "\",\"signature\":\""
                   << json_escape(result.metadata.signature) << "\",\"risk_score\":" << result.risk_score
                   << ",\"risk_level\":\"" << json_escape(result.risk_level)
                   << "\",\"risk_action\":\"" << json_escape(result.risk_action)
                   << "\",\"verdict\":\"" << json_escape(result.verdict)
                   << "\",\"baseline\":" << (result.baseline ? "true" : "false")
                   << ",\"session\":\"" << json_escape(result.session.string())
                  << "\",\"created\":" << result.created.size()
                  << ",\"modified\":" << result.modified.size()
                  << ",\"deleted\":" << result.deleted.size() << "}\n";
        return;
    }
    if (!result.report_data.empty()) {
        std::cout << result.report_data;
        return;
    }
    std::cout << (result.ok ? "package: " + result.metadata.name + " " + result.metadata.version
                            : "package: rejected")
              << '\n';
    if (!result.error.empty())
        std::cout << "error: " << result.error << '\n';
    if (result.ok)
        std::cout << "architecture: " << result.metadata.architecture
                  << " signature: " << result.metadata.signature << "\nrisk: " << result.risk_score
                  << " verdict: " << result.verdict << "\nfiles: " << result.metadata.files.size()
                  << " executables: " << result.metadata.executables.size()
                  << "\nsession: " << result.session << '\n';
}
} // namespace execell::package
