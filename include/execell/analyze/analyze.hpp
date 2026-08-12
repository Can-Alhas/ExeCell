#pragma once

#include <execell/policy/policy.hpp>
#include <execell/risk/risk.hpp>
#include <execell/sandbox/sandbox.hpp>
#include <execell/report/summary_reporter.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace execell::analyze {

enum class Format { terminal, json };

struct Options {
    Format format{Format::terminal};
    policy::Config policy;
    std::chrono::seconds timeout{30};
    std::size_t output_limit{1U << 20U};
    bool sandbox{};
    sandbox::Config sandbox_config{};
};

struct Result {
    int exit_status{-1};
    bool timed_out{};
    bool output_limited{};
    std::filesystem::path session;
    std::string events_json;
    std::string attestation;
    std::vector<risk::Finding> observed_findings;
    std::vector<risk::Finding> policy_findings;
    report::Summary summary;
    risk::Assessment assessment;
};

[[nodiscard]] Result run(const std::vector<std::string>& args, const Options& options);
void print(const Result& result);
[[nodiscard]] std::string json(const Result& result);

} // namespace execell::analyze
