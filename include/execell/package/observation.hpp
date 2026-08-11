#pragma once

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace execell::package::observation {

struct Options {
    std::chrono::seconds timeout{30};
    bool network{};
    bool run_all{};
    std::size_t output_limit{1U << 20U};
};

struct Result {
    std::vector<std::string> events;
    std::vector<std::string> processes;
    std::vector<std::string> network;
    std::vector<std::string> smoke;
    std::vector<std::string> risk_factors;
};

Result observe(const std::filesystem::path& rootfs,
               const std::vector<std::string>& scripts,
               const std::vector<std::string>& hooks,
               const std::vector<std::string>& executables,
               const Options& options);

} // namespace execell::package::observation
