#pragma once

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace execell::package::build {

struct Options {
    std::filesystem::path rootfs;
    std::filesystem::path workspace{"/tmp/execell-build"};
    std::filesystem::path artifact_root{"/tmp/execell-build-artifacts"};
    std::chrono::seconds timeout{300};
    bool network{};
    std::vector<std::string> allowed_hosts;
    std::filesystem::path cgroup_root;
    std::size_t repetitions{1};
    std::size_t output_limit{1U << 20U};
};

struct Result {
    bool ok{};
    bool timed_out{};
    int status{-1};
    std::string error;
    std::vector<std::string> findings;
    std::vector<std::string> phases;
    std::vector<std::string> events;
    std::vector<std::filesystem::path> artifacts;
    bool reproducible{true};
};

[[nodiscard]] Result run(const std::filesystem::path&, const Options&);

} // namespace execell::package::build
