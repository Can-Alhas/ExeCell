#pragma once

#include <expected>
#include <chrono>
#include <filesystem>
#include <string>
#include <cstdint>
#include <sys/types.h>
#include <vector>
#include <execell/sandbox/backend.hpp>

namespace execell::sandbox {

struct Config {
    Backend backend{Backend::namespaces};
    bool user_namespace{true};
    bool mount_namespace{true};
    bool network_namespace{false};
    bool drop_capabilities{true};
    bool no_new_privileges{true};
    bool read_only_root{true};
    bool clean_environment{};
    bool drop_to_unprivileged_user{};
    bool mount_proc{true};
    bool mount_run{true};
    bool trace_events{};
    std::uint64_t cpu_seconds{};
    std::uint64_t address_space_bytes{};
    std::uint64_t max_processes{};
    std::uint64_t max_file_bytes{};
    std::filesystem::path rootfs;
    std::filesystem::path working_directory;
    std::vector<int> seccomp_allowlist;
    struct CgroupBudget {
        std::filesystem::path path;
        std::uint64_t memory_max{};
        std::uint64_t pids_max{};
        std::uint64_t cpu_quota_us{};
        std::uint64_t cpu_period_us{100000};
    } cgroup;
};

[[nodiscard]] std::expected<void, std::string> validate(const Config& config);

[[nodiscard]] std::vector<int> default_package_syscalls();
[[nodiscard]] std::string attestation(const Config&);

[[nodiscard]] std::expected<void, std::string>
validate_cgroup(const Config::CgroupBudget&);

[[nodiscard]] bool set_parent_death_signal(pid_t expected_parent = -1) noexcept;

[[nodiscard]] int run(char* const program, char* const argv[], const Config& config);

struct Captured {
    int status{-1};
    bool timed_out{};
    bool output_limited{};
    std::string stdout_data;
    std::string stderr_data;
};

[[nodiscard]] Captured run_captured(const std::vector<std::string>& args,
                                    const Config& config,
                                    std::chrono::seconds timeout,
                                    std::size_t output_limit = 1U << 20U);

} // namespace execell::sandbox
