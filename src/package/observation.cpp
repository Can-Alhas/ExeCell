#include <execell/package/observation.hpp>
#include <execell/sandbox/sandbox.hpp>

#include <sys/stat.h>

namespace execell::package::observation {
namespace {

std::string escape(std::string_view value) {
    std::string result;
    for (const char character : value) {
        if (character == '"' || character == '\\') result += '\\';
        if (character == '\n') { result += "\\n"; continue; }
        if (character == '\r') { result += "\\r"; continue; }
        result += character;
    }
    return result;
}

void run_one(Result& result, const std::filesystem::path& root, std::string_view path,
             bool script, const Options& options) {
    const auto relative = std::filesystem::path{path};
    if (relative.is_absolute() || relative.string().find("..") != std::string::npos) return;
    const auto host_path = root / relative;
    if (!std::filesystem::is_regular_file(host_path)) {
        result.events.push_back("{\"schema_version\":1,\"type\":\"observation_skipped\",\"path\":\"" +
                                escape(path) + "\",\"reason\":\"not staged\"}");
        return;
    }
    const std::string sandbox_path = "/" + relative.string();
    sandbox::Config config;
    // Keep host networking unreachable until mirror allowlisting is wired into namespace setup.
    config.network_namespace = true;
    config.mount_namespace = true;
    config.rootfs = root;
    config.read_only_root = false;
    config.cpu_seconds = static_cast<std::uint64_t>(options.timeout.count());
    config.max_processes = 64;
    config.max_file_bytes = 64U * 1024U * 1024U;
    const auto command = script ? std::vector<std::string>{"/bin/sh", sandbox_path, "install"}
                                : std::vector<std::string>{sandbox_path};
    const auto captured = sandbox::run_captured(command, config, options.timeout, options.output_limit);
    const std::string kind = script ? "maintainer_script" : "executable_smoke";
    result.events.push_back("{\"schema_version\":1,\"type\":\"" + kind +
                            "\",\"path\":\"" + escape(path) + "\",\"status\":" +
                            std::to_string(captured.status) + ",\"timed_out\":" +
                            (captured.timed_out ? "true" : "false") + ",\"stdout\":\"" +
                            escape(captured.stdout_data) + "\",\"stderr\":\"" +
                            escape(captured.stderr_data) + "\"}");
    result.processes.push_back("{\"path\":\"" + escape(path) + "\",\"status\":" +
                               std::to_string(captured.status) + "}");
    result.network.push_back("{\"path\":\"" + escape(path) + "\",\"isolated\":true}");
    result.smoke.push_back(std::string(path) + ":" + (captured.status == 0 ? "passed" : "failed") +
                           ":status=" + std::to_string(captured.status) +
                           (captured.timed_out ? ":timeout" : ""));
    const std::string combined = captured.stdout_data + "\n" + captured.stderr_data;
    const auto flag = [&](std::string_view text, std::string_view factor) {
        if (combined.find(text) != std::string::npos) result.risk_factors.emplace_back(factor);
    };
    flag("systemctl", "service activation attempt");
    flag("/etc/systemd", "service persistence attempt");
    flag("/etc/cron", "persistence attempt");
    flag("setuid", "privilege change attempt");
    flag("setcap", "capability change attempt");
}

} // namespace

Result observe(const std::filesystem::path& rootfs, const std::vector<std::string>& scripts,
               const std::vector<std::string>& hooks, const std::vector<std::string>& executables,
               const Options& options) {
    Result result;
    result.events.push_back(std::string{"{\"schema_version\":1,\"type\":\"observation_start\",\"network\":\""} +
                            (options.network ? "requested" : "isolated") + "\"}");
    result.events.emplace_back(
        "{\"schema_version\":1,\"type\":\"sandbox_policy\",\"no_new_privileges\":true,\"capabilities\":\"dropped\"}");
    for (const auto& path : scripts) run_one(result, rootfs, path, true, options);
    for (const auto& path : hooks) run_one(result, rootfs, path, true, options);
    if (executables.empty()) result.smoke.emplace_back("*:skipped:no executables discovered");
    for (const auto& path : executables) run_one(result, rootfs, path, false, options);
    const auto present = [&](std::string_view path) {
        return std::filesystem::exists(rootfs / std::filesystem::path{path});
    };
    if (present("etc/systemd/system") || present("etc/init.d")) {
        result.risk_factors.emplace_back("service activation or persistence path present");
        result.events.emplace_back("{\"schema_version\":1,\"type\":\"service_path\"}");
    }
    if (present("etc/cron.d") || present("etc/cron.hourly") || present("etc/cron.daily")) {
        result.risk_factors.emplace_back("scheduled persistence path present");
        result.events.emplace_back("{\"schema_version\":1,\"type\":\"persistence_path\"}");
    }
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             rootfs, std::filesystem::directory_options::skip_permission_denied)) {
        std::error_code error;
        const auto mode = entry.status(error).permissions();
        if (!error && (mode & std::filesystem::perms::set_uid) != std::filesystem::perms::none) {
            result.risk_factors.emplace_back("setuid payload present");
            result.events.emplace_back("{\"schema_version\":1,\"type\":\"privilege_change\"}");
            break;
        }
    }
    result.events.push_back("{\"schema_version\":1,\"type\":\"observation_complete\"}");
    return result;
}

} // namespace execell::package::observation
