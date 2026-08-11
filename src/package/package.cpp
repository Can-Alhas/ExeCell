#include <execell/package/package.hpp>
#include <execell/package/rootfs.hpp>
#include <execell/package/observation.hpp>
#include <execell/package/network.hpp>
#include <execell/risk/risk.hpp>

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
#include <unistd.h>

namespace execell::package {
namespace {

constexpr std::size_t max_command_output = 1U << 20U;

struct Command {
    int status{-1};
    bool timed_out{};
    std::string output;
};

Command run_command(const std::vector<std::string> &args, std::chrono::seconds limit,
                    const std::filesystem::path &directory = {}) {
    int pipefd[2];
    if (::pipe(pipefd) != 0)
        return {};
    const pid_t child = ::fork();
    if (child == -1) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return {};
    }
    if (child == 0) {
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        if (!directory.empty())
            (void)::chdir(directory.c_str());
        std::vector<char *> argv;
        argv.reserve(args.size() + 1U);
        for (const auto &arg : args)
            argv.push_back(const_cast<char *>(arg.c_str()));
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        _exit(127);
    }
    ::close(pipefd[1]);
    (void)::fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    Command result;
    const auto deadline = std::chrono::steady_clock::now() + limit;
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t count = ::read(pipefd[0], buffer.data(), buffer.size());
        if (count > 0 && result.output.size() < max_command_output) {
            const auto available = max_command_output - result.output.size();
            result.output.append(buffer.data(),
                                 std::min(available, static_cast<std::size_t>(count)));
        }
        int status{};
        const pid_t waited = ::waitpid(child, &status, WNOHANG);
        if (waited == child) {
            result.status = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            result.timed_out = true;
            (void)::kill(child, SIGKILL);
            (void)::waitpid(child, &status, 0);
            break;
        }
        struct pollfd descriptor{pipefd[0], POLLIN, 0};
        (void)::poll(&descriptor, 1, 10);
    }
    while (const ssize_t count = ::read(pipefd[0], buffer.data(), buffer.size())) {
        if (count > 0 && result.output.size() < max_command_output) {
            const auto available = max_command_output - result.output.size();
            result.output.append(buffer.data(),
                                 std::min(available, static_cast<std::size_t>(count)));
        }
    }
    ::close(pipefd[0]);
    return result;
}

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
bool exists(std::string_view program) {
    if (::access(("/usr/bin/" + std::string(program)).c_str(), X_OK) == 0 ||
        ::access(("/bin/" + std::string(program)).c_str(), X_OK) == 0)
        return true;
    const char *path = std::getenv("PATH");
    if (path == nullptr)
        return false;
    std::string paths(path);
    std::size_t begin{};
    while (begin <= paths.size()) {
        const std::size_t end = paths.find(':', begin);
        const std::string directory =
            paths.substr(begin, end == std::string::npos ? paths.size() - begin : end - begin);
        if (::access((directory + "/" + std::string(program)).c_str(), X_OK) == 0)
            return true;
        if (end == std::string::npos)
            break;
        begin = end + 1U;
    }
    return false;
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

std::optional<std::string> safe_archive_path(std::string path) {
    while (path.starts_with("./"))
        path.erase(0, 2);
    if (path.empty() || path.front() == '/' || path.find('\0') != std::string::npos)
        return std::nullopt;
    std::filesystem::path candidate(path);
    for (const auto &component : candidate) {
        if (component == ".." || component == "." || component.empty())
            return std::nullopt;
    }
    return path;
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
    if (!std::filesystem::is_regular_file(package)) {
        result.error = "package does not exist";
        return result;
    }
    if (!exists("tar")) {
        result.error = "deterministic error: tar unavailable";
        return result;
    }
    const Command info =
        run_command({"tar", "-xOf", package.string(), ".PKGINFO"}, options.timeout);
    if (info.timed_out) {
        result.error = "metadata extraction timed out";
        return result;
    }
    if (info.status != 0) {
        result.error = "corrupt archive or missing .PKGINFO";
        return result;
    }
    result.metadata.name = value(info.output, "pkgname");
    result.metadata.version = value(info.output, "pkgver");
    result.metadata.architecture = value(info.output, "arch");
    result.metadata.dependencies = values(info.output, "depend");
    if (result.metadata.architecture != "x86_64" && result.metadata.architecture != "any") {
        result.error = "unsupported architecture: " + result.metadata.architecture;
        return result;
    }
    const Command listing =
        run_command({"tar", "--null", "-tf", package.string()}, options.timeout);
    if (listing.timed_out || listing.status != 0) {
        result.error = listing.timed_out ? "archive listing timed out" : "corrupt archive";
        return result;
    }
    std::size_t begin{};
    while (begin < listing.output.size()) {
        const std::size_t end = listing.output.find('\0', begin);
        if (end == std::string::npos) {
            result.error = "archive listing is not NUL terminated";
            return result;
        }
        const auto path_result = safe_archive_path(listing.output.substr(begin, end - begin));
        if (!path_result) {
            result.error = "unsafe archive path";
            return result;
        }
        const std::string &path = *path_result;
        result.metadata.files.push_back(path);
        if (path == ".INSTALL" || path.ends_with("/.INSTALL"))
            result.metadata.scripts.push_back(path);
        if (path.ends_with(".hook") || path.find("/hooks/") != std::string::npos)
            result.metadata.hooks.push_back(path);
        begin = end + 1U;
    }
    const std::filesystem::path sig = package.string() + ".sig";
    if (!std::filesystem::exists(sig)) {
        result.error = "signature verification failed: detached signature missing";
        return result;
    }
    if (!exists("pacman-key")) {
        result.error = "signature verification unavailable: pacman-key missing";
        return result;
    }
    const Command verify =
        run_command({"pacman-key", "--verify", sig.string(), package.string()}, options.timeout);
    if (verify.timed_out || verify.status != 0) {
        result.error =
            verify.timed_out ? "signature verification timed out" : "signature verification failed";
        return result;
    }
    result.metadata.signature = "valid";
    result.ok = true;
    return result;
}

std::map<std::string, std::uintmax_t> snapshot(const std::filesystem::path &root) {
    std::map<std::string, std::uintmax_t> result;
    if (!std::filesystem::exists(root))
        return result;
    for (const auto &entry : std::filesystem::recursive_directory_iterator(
             root, std::filesystem::directory_options::skip_permission_denied))
        if (entry.is_regular_file())
            result[std::filesystem::relative(entry.path(), root).string()] = entry.file_size();
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
    const auto metadata = std::string{"{\"schema_version\":1,\"package\":\""} +
                          json_escape(result.metadata.package.string()) + "\",\"name\":\"" +
                          json_escape(result.metadata.name) + "\",\"version\":\"" +
                          json_escape(result.metadata.version) + "\",\"architecture\":\"" +
                          json_escape(result.metadata.architecture) + "\",\"signature\":\"" +
                          json_escape(result.metadata.signature) +
                          "\",\"dependencies\":" + json_array(result.metadata.dependencies) +
                          ",\"scripts\":" + json_array(result.metadata.scripts) +
                          ",\"hooks\":" + json_array(result.metadata.hooks) +
                          ",\"files\":" + json_array(result.metadata.files) +
                          ",\"executables\":" + json_array(result.metadata.executables) + "}\n";
    const auto summary =
        "{\"schema_version\":1,\"ok\":" + std::string(result.ok ? "true" : "false") +
        ",\"risk_score\":" + std::to_string(result.risk_score) + ",\"verdict\":\"" +
        json_escape(result.verdict) + "\"}\n";
    const auto filesystem = "{\"schema_version\":1,\"created\":" + json_array(result.created) +
                            ",\"modified\":" + json_array(result.modified) +
                            ",\"deleted\":" + json_array(result.deleted) + "}\n";
    const auto processes = "{\"schema_version\":1,\"events\":" +
                           json_object_array(result.process_events) + "}\n";
    const auto network = "{\"schema_version\":1,\"events\":" +
                         json_object_array(result.network_events) + "}\n";
    const auto risk = "{\"schema_version\":1,\"score\":" + std::to_string(result.risk_score) +
                      ",\"verdict\":\"" + json_escape(result.verdict) +
                      "\",\"factors\":" + json_array(result.risk_factors) + "}\n";
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
    const auto &root = root_session.path();
    result.events.push_back(root_session.event());
    if (!root_session.isolated()) {
        result.risk_factors.push_back("degraded rootfs: Btrfs unavailable; no filesystem isolation");
    }
    const auto before = snapshot(root);
    if (options.privileged && ::geteuid() == 0 &&
        std::filesystem::exists(root / "usr/bin/pacman") && exists("pacman")) {
        std::filesystem::create_directories(root / "var/lib/pacman", ec);
        std::filesystem::create_directories(root / "var/cache/pacman/pkg", ec);
        sandbox::Config install_config;
        install_config.rootfs = root;
        install_config.read_only_root = false;
        install_config.network_namespace = true;
        install_config.cpu_seconds = static_cast<std::uint64_t>(options.timeout.count());
        install_config.max_processes = 128;
        install_config.max_file_bytes = 128U * 1024U * 1024U;
        const auto installed = sandbox::run_captured(
            {"/usr/bin/pacman", "-U", "--noconfirm", "--root", "/", "--dbpath",
             "/var/lib/pacman", package.string()}, install_config, options.timeout);
        if (installed.timed_out || installed.status != 0) {
            result.error =
                installed.timed_out ? "pacman install timed out" : "pacman install failed";
            result.ok = false;
            return result;
        }
        result.installed = true;
    } else if (options.privileged)
        result.risk_factors.push_back("privileged install unavailable; root and pacman required");
    const auto after = snapshot(root);
    for (const auto &[path, size] : after) {
        const auto old = before.find(path);
        if (old == before.end())
            result.created.push_back(path);
        else if (old->second != size)
            result.modified.push_back(path);
    }
    for (const auto &[path, size] : before)
        if (!after.contains(path)) {
            (void)size;
            result.deleted.push_back(path);
        }
    const std::size_t executable_limit = std::min<std::size_t>(result.metadata.files.size(), 128U);
    const auto stage = [&](const std::string &path) {
        const auto target = root / path;
        if (std::filesystem::exists(target)) return;
        const Command content = run_command({"tar", "-xOf", package.string(), path}, options.timeout);
        if (content.status != 0 || content.timed_out) return;
        std::filesystem::create_directories(target.parent_path(), ec);
        std::ofstream output(target, std::ios::binary);
        output.write(content.output.data(), static_cast<std::streamsize>(content.output.size()));
        output.close();
        (void)::chmod(target.c_str(), 0700);
    };
    for (std::size_t index = 0; index < executable_limit; ++index) {
        const std::string &path = result.metadata.files[index];
        const Command content =
            run_command({"tar", "-xOf", package.string(), path}, options.timeout);
        if (content.status != 0 || content.timed_out)
            continue;
        const bool elf =
            content.output.size() >= 4U && static_cast<unsigned char>(content.output[0]) == 0x7fU &&
            content.output[1] == 'E' && content.output[2] == 'L' && content.output[3] == 'F';
        if (!elf && !content.output.starts_with("#!"))
            continue;
        result.metadata.executables.push_back(path);
        stage(path);
    }
    for (const auto &path : result.metadata.scripts) stage(path);
    for (const auto &path : result.metadata.hooks) stage(path);
    observation::Options observation_options{.timeout = options.timeout,
                                             .network = options.network == "mirror",
                                             .run_all = options.run_all};
    const auto observed = observation::observe(root, result.metadata.scripts,
                                               result.metadata.hooks,
                                               result.metadata.executables,
                                               observation_options);
    result.smoke_scans = observed.smoke;
    result.process_events = observed.processes;
    result.network_events = observed.network;
    result.events.insert(result.events.end(), observed.events.begin(), observed.events.end());
    result.risk_factors.insert(result.risk_factors.end(), observed.risk_factors.begin(),
                               observed.risk_factors.end());
    execell::risk::Engine risk;
    if (!result.installed) risk.add("rootless", 5, "package install scripts were not executed");
    if (!result.metadata.scripts.empty()) risk.add("scripts", 15, "maintainer scripts execute package-provided code");
    if (!result.metadata.hooks.empty()) risk.add("hooks", 20, "package hooks can execute during installation");
    if (!result.created.empty()) risk.add("filesystem", static_cast<int>(std::min<std::size_t>(result.created.size() * 2U, 20U)), "package changed files in isolated rootfs");
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
    if (!write_artifacts(result))
        result.events.push_back("{\"schema_version\":1,\"type\":\"artifact_error\"}");
    return result;
}

Result fetch(const std::string &target, const Options &options) {
    Result result;
    if (!exists("pacman")) {
        result.error = "fetch unavailable: pacman missing";
        return result;
    }
    const Command command = run_command({"pacman", "-Sw", "--noconfirm", target}, options.timeout);
    result.ok = command.status == 0 && !command.timed_out;
    result.error = command.timed_out     ? "fetch timed out"
                   : command.status == 0 ? ""
                                         : "pacman fetch failed";
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
                  << "\",\"session\":\"" << json_escape(result.session.string())
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
