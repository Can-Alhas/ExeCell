#include <execell/package/observation.hpp>
#include <execell/package/rootfs.hpp>
#include <execell/sandbox/sandbox.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <thread>
#include <utility>

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
        result.coverage.emplace_back(std::string(path) + ":skipped:not-staged");
        return;
    }
    static std::atomic<unsigned long long> sequence{};
    const auto workspace = std::filesystem::temp_directory_path() /
                           ("execell-observe-" + std::to_string(::getpid()) + "-" +
                            std::to_string(sequence.fetch_add(1U, std::memory_order_relaxed)));
    auto session_result = rootfs::Session::create(root, workspace);
    if (!session_result || !session_result->isolated()) {
        result.risk_factors.emplace_back("per-observation rootfs snapshot unavailable");
        result.events.push_back("{\"schema_version\":1,\"type\":\"observation_rejected\",\"reason\":\"snapshot\"}");
        result.coverage.emplace_back(std::string(path) + ":rejected:snapshot");
        return;
    }
    auto session = std::move(*session_result);
    const auto& isolated_root = session.path();
    const auto isolated_path = isolated_root / relative;
    if (!std::filesystem::is_regular_file(isolated_path)) {
        result.risk_factors.emplace_back("per-observation snapshot missing staged file");
        result.coverage.emplace_back(std::string(path) + ":rejected:missing-file");
        return;
    }
    const std::string sandbox_path = "/" + relative.string();
    sandbox::Config config;
    // Keep host networking unreachable until mirror allowlisting is wired into namespace setup.
    config.network_namespace = true;
    config.mount_namespace = true;
    config.rootfs = isolated_root;
    config.read_only_root = false;
    config.clean_environment = true;
    config.trace_events = true;
    std::filesystem::path task_cgroup;
    if (!options.cgroup_root.empty()) {
        task_cgroup = options.cgroup_root /
                      ("execell-task-" + std::to_string(::getpid()) + "-" +
                       std::to_string(sequence.load(std::memory_order_relaxed)));
        std::error_code cgroup_error;
        if (!std::filesystem::create_directory(task_cgroup, cgroup_error)) {
            result.risk_factors.emplace_back("cgroup task creation failed");
            return;
        }
        config.cgroup.path = task_cgroup;
    }
    config.cpu_seconds = static_cast<std::uint64_t>(options.timeout.count());
    config.max_processes = 64;
    config.max_file_bytes = 64U * 1024U * 1024U;
    config.seccomp_allowlist = sandbox::default_package_syscalls();
    result.events.push_back("{\"schema_version\":1,\"type\":\"attestation\",\"manifest\":" +
                            sandbox::attestation(config) + "}");
    const auto command = script ? std::vector<std::string>{"/bin/sh", sandbox_path, "install"}
                                : std::vector<std::string>{sandbox_path};
    const auto captured = sandbox::run_captured(command, config, options.timeout, options.output_limit);
    if (!task_cgroup.empty()) {
        std::error_code cgroup_error;
        std::filesystem::remove(task_cgroup, cgroup_error);
    }
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
    std::size_t trace_position{};
    while ((trace_position = captured.stderr_data.find("EXECELL_TRACE:", trace_position)) !=
           std::string::npos) {
        const auto begin = trace_position + std::string_view{"EXECELL_TRACE:"}.size();
        const auto end = captured.stderr_data.find('\n', begin);
        const auto event = captured.stderr_data.substr(
            begin, end == std::string::npos ? captured.stderr_data.size() - begin : end - begin);
        result.events.push_back(event);
        if (event.find("network_") != std::string::npos)
            result.network.push_back(event);
        if (event.find("process_") != std::string::npos)
            result.processes.push_back(event);
        trace_position = end == std::string::npos ? captured.stderr_data.size() : end + 1U;
    }
    result.smoke.push_back(std::string(path) + ":" + (captured.status == 0 ? "passed" : "failed") +
                           ":status=" + std::to_string(captured.status) +
                           (captured.timed_out ? ":timeout" : ""));
    result.coverage.emplace_back(std::string(path) + ":" +
                                 (captured.timed_out ? "timed-out" : "executed"));
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
    struct Task { std::string path; bool script{}; };
    std::vector<Task> tasks;
    tasks.reserve(scripts.size() + hooks.size() + executables.size());
    for (const auto& path : scripts) tasks.push_back({path, true});
    for (const auto& path : hooks) tasks.push_back({path, true});
    for (const auto& path : executables) tasks.push_back({path, false});
    if (tasks.empty()) result.smoke.emplace_back("*:skipped:no executables discovered");

    if (!tasks.empty()) {
        const std::size_t worker_count = std::min(
            std::max<std::size_t>(options.max_workers, 1U), tasks.size());
        std::vector<Result> partial(tasks.size());
        std::atomic<std::size_t> next{};
        const auto deadline = std::chrono::steady_clock::now() + options.global_timeout;
        std::vector<std::jthread> workers;
        workers.reserve(worker_count);
        for (std::size_t worker = 0; worker < worker_count; ++worker) {
            workers.emplace_back([&](std::stop_token stop) {
                for (;;) {
                    if (stop.stop_requested()) return;
                    const auto index = next.fetch_add(1U, std::memory_order_relaxed);
                    if (index >= tasks.size()) return;
                    const auto remaining = deadline - std::chrono::steady_clock::now();
                    if (remaining <= std::chrono::steady_clock::duration::zero()) {
                        partial[index].smoke.emplace_back(tasks[index].path + ":skipped:global-timeout");
                        partial[index].risk_factors.emplace_back("global observation budget exhausted");
                        partial[index].coverage.emplace_back(tasks[index].path + ":skipped:global-timeout");
                        return;
                    }
                    auto task_options = options;
                    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                        remaining + std::chrono::seconds{1});
                    task_options.timeout = std::min(options.timeout, seconds);
                    try {
                        run_one(partial[index], rootfs, tasks[index].path, tasks[index].script, task_options);
                    } catch (const std::exception& error) {
                        partial[index].risk_factors.emplace_back(std::string{"observation worker failed: "} + error.what());
                        partial[index].events.emplace_back("{\"schema_version\":1,\"type\":\"worker_failure\"}");
                    } catch (...) {
                        partial[index].risk_factors.emplace_back("observation worker failed: unknown error");
                        partial[index].events.emplace_back("{\"schema_version\":1,\"type\":\"worker_failure\"}");
                    }
                }
            });
        }
        workers.clear();
        for (auto& partial_result : partial) {
            result.events.insert(result.events.end(), partial_result.events.begin(), partial_result.events.end());
            result.processes.insert(result.processes.end(), partial_result.processes.begin(), partial_result.processes.end());
            result.network.insert(result.network.end(), partial_result.network.begin(), partial_result.network.end());
            result.smoke.insert(result.smoke.end(), partial_result.smoke.begin(), partial_result.smoke.end());
            result.risk_factors.insert(result.risk_factors.end(), partial_result.risk_factors.begin(), partial_result.risk_factors.end());
            result.coverage.insert(result.coverage.end(), partial_result.coverage.begin(), partial_result.coverage.end());
        }
    }
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
