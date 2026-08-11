#pragma once

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace execell::package {

struct Options {
    bool privileged{};
    bool run_all{};
    bool byte_diff{};
    bool confirm_privileged{};
    std::chrono::seconds timeout{30};
    std::string format{"terminal"};
    std::string network{"off"};
    std::vector<std::string> mirrors;
    std::filesystem::path rootfs;
    std::filesystem::path session_root{"/tmp/execell-package"};
};

struct Metadata {
    std::filesystem::path package;
    std::string name;
    std::string version;
    std::string architecture;
    std::vector<std::string> dependencies;
    std::vector<std::string> files;
    std::vector<std::string> scripts;
    std::vector<std::string> hooks;
    std::vector<std::string> executables;
    std::string signature;
};

struct Result {
    bool ok{};
    std::string error;
    Metadata metadata;
    std::vector<std::string> created;
    std::vector<std::string> modified;
    std::vector<std::string> deleted;
    std::vector<std::string> risk_factors;
    int risk_score{};
    std::string verdict{"reject"};
    std::string risk_level{"none"};
    std::string risk_action{"reject"};
    std::filesystem::path session;
    bool installed{};
    std::string report_data;
    std::vector<std::string> smoke_scans;
    std::vector<std::string> process_events;
    std::vector<std::string> network_events;
    std::vector<std::string> events;
};

Result scan(const std::filesystem::path&, const Options&);
Result fetch(const std::string&, const Options&);
Result report(const std::filesystem::path&, const Options&);
Result cleanup(const Options&);
void print(const Result&, const Options&);

} // namespace execell::package
