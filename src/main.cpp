#include "execell/cli/invocation.hpp"
#include "execell/analyze/analyze.hpp"
#include "execell/package/package.hpp"
#include "execell/package/build.hpp"
#include "execell/package/rootfs.hpp"
#include "execell/package/network.hpp"
#include "execell/policy/policy_reporter.hpp"
#include "execell/process/process.hpp"
#include "execell/risk/risk.hpp"
#include "execell/report/json_reporter.hpp"
#include "execell/report/summary_reporter.hpp"
#include "execell/report/terminal_reporter.hpp"
#include "execell/sandbox/sandbox.hpp"
#include "execell/trace/tracer.hpp"
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string_view>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr std::string_view version{"0.2.0"};

void print_usage(std::string_view executable) {
    std::cout
        << "ExeCell " << version << '\n'
        << "Usage:\n"
        << "  " << executable << " run <program>   [arguments...]\n"
        << "  " << executable << " trace <program> [arguments...]\n"
        << "  " << executable << " trace --format json <program> [arguments...]\n"
         << "  " << executable << " inspect <program> [arguments...]\n"
         << "  " << executable << " inspect --deny-path PATH <program> [arguments...]\n"
         << "  " << executable << " inspect --max-processes N <program> [arguments...]\n"
         << "  " << executable << " analyze [--format terminal|json] [--sandbox] [--timeout S] [--output-limit BYTES] [policy options] <program> [arguments...]\n"
        << "  " << executable
         << " sandbox [--backend namespace|vm] [--network] [--trace-events] [--cpu N] [--memory BYTES] <program> [arguments...]\n"
          << "  " << executable << " package scan|build|compare|doctor|fetch|report|cleanup [options] [path]\n"
          << "    options: --timeout 30s --workers N --rebuild N --database PATH --cgroup-root PATH --network off|mirror --mirror URL --allow-host HOST --run-all --byte-diff\n";
}

} // namespace

int main(int argc, char *argv[]) {
    const auto invocation = execell::cli::make_invocation(argc, argv);

    if (argc < 3) {
        print_usage(invocation.program);
        return EXIT_FAILURE;
    }

    const std::string_view command{argv[1]};

    if (command == "run") {
        return execell::process::run(argv[2], &argv[2]);
    }

    if (command == "trace") {
        if (argc >= 5 && std::string_view{argv[2]} == "--format" &&
            std::string_view{argv[3]} == "json") {
            execell::report::JsonReporter reporter{std::cout};
            const int result = execell::trace::run(argv[4], &argv[4], reporter);
            reporter.finish();
            return result;
        }
        return execell::trace::run(argv[2], &argv[2]);
    }

    if (command == "analyze") {
        execell::analyze::Options options;
        std::vector<std::string> target;
        int program_index = 2;
        while (program_index < argc && std::string_view{argv[program_index]}.starts_with("--")) {
            const std::string_view option{argv[program_index++]};
            if (option == "--format") {
                if (program_index >= argc) return EXIT_FAILURE;
                const std::string_view value{argv[program_index++]};
                if (value != "terminal" && value != "json") return EXIT_FAILURE;
                options.format = value == "json" ? execell::analyze::Format::json
                                                   : execell::analyze::Format::terminal;
                continue;
            }
            if (option == "--sandbox") {
                options.sandbox = true;
                continue;
            }
            if (option == "--timeout" || option == "--output-limit" ||
                option == "--deny-path" || option == "--deny-endpoint" ||
                option == "--deny-syscall" || option == "--max-processes") {
                if (program_index >= argc) return EXIT_FAILURE;
                const std::string value{argv[program_index++]};
                if (option == "--timeout" || option == "--output-limit") {
                    std::uint64_t parsed{};
                    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
                    if (error != std::errc{} || end != value.data() + value.size() || parsed == 0U) return EXIT_FAILURE;
                    if (option == "--timeout") options.timeout = std::chrono::seconds(parsed);
                    else options.output_limit = static_cast<std::size_t>(parsed);
                    continue;
                }
                if (option == "--deny-path") options.policy.denied_paths.emplace_back(value);
                else if (option == "--deny-endpoint") options.policy.denied_endpoints.push_back(value);
                else if (option == "--deny-syscall") options.policy.denied_syscalls.push_back(value);
                else {
                    std::uint64_t parsed{};
                    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
                    if (error != std::errc{} || end != value.data() + value.size()) return EXIT_FAILURE;
                    options.policy.max_processes = static_cast<std::size_t>(parsed);
                }
                continue;
            }
            std::cerr << "execell: unknown analyze option: " << option << '\n';
            return EXIT_FAILURE;
        }
        if (program_index >= argc) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        for (int index = program_index; index < argc; ++index) target.emplace_back(argv[index]);
        const auto result = execell::analyze::run(target, options);
        if (options.format == execell::analyze::Format::json) std::cout << execell::analyze::json(result) << '\n';
        else execell::analyze::print(result);
        return execell::analyze::json(result).find("\"verdict\":\"allow\"") != std::string::npos
                   ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (command == "inspect") {
        execell::report::Summary summary;
        execell::policy::Config policy_config;
        bool json_format{};
        int program_index = 2;
        while (program_index < argc &&
               (std::string_view{argv[program_index]} == "--deny-path" ||
                std::string_view{argv[program_index]} == "--deny-endpoint" ||
                std::string_view{argv[program_index]} == "--deny-syscall" ||
                std::string_view{argv[program_index]} == "--max-processes" ||
                std::string_view{argv[program_index]} == "--format")) {
            const std::string_view option{argv[program_index]};
            ++program_index;
            if (program_index >= argc) {
                std::cerr << "execell: missing path for --deny-path\n";
                return EXIT_FAILURE;
            }
            const std::string value{argv[program_index++]};
            if (option == "--format") {
                if (value != "json" && value != "terminal") {
                    std::cerr << "execell: invalid format: " << value << '\n';
                    return EXIT_FAILURE;
                }
                json_format = value == "json";
            } else if (option == "--max-processes") {
                std::uint64_t parsed{};
                const auto [end, error] =
                    std::from_chars(value.data(), value.data() + value.size(), parsed);
                if (error != std::errc{} || end != value.data() + value.size()) {
                    std::cerr << "execell: invalid process limit\n";
                    return EXIT_FAILURE;
                }
                policy_config.max_processes = static_cast<std::size_t>(parsed);
            } else if (option == "--deny-path") {
                policy_config.denied_paths.emplace_back(value);
            } else if (option == "--deny-endpoint") {
                policy_config.denied_endpoints.push_back(value);
            } else {
                policy_config.denied_syscalls.push_back(value);
            }
        }
        if (program_index >= argc) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        if (json_format) {
            execell::report::JsonReporter json{std::cout};
            execell::policy::Reporter policy{std::move(policy_config), json};
            const int result =
                execell::trace::run(argv[program_index], &argv[program_index], policy);
            json.finish();
            return result;
        }
        execell::policy::Reporter policy{std::move(policy_config), summary};
        const int result = execell::trace::run(argv[program_index], &argv[program_index], policy);
        summary.print(std::cout);
        return result;
    }

    if (command == "sandbox") {
        execell::sandbox::Config config;
        int program_index = 2;
        while (program_index < argc && std::string_view{argv[program_index]}.starts_with("--")) {
            const std::string_view option{argv[program_index++]};
            if (option == "--network") {
                config.network_namespace = true;
                continue;
            }
            if (option == "--trace-events") {
                config.trace_events = true;
                continue;
            }
            if (program_index >= argc) {
                std::cerr << "execell: missing value for " << option << '\n';
                return EXIT_FAILURE;
            }
            const std::string_view value{argv[program_index++]};
            if (option == "--backend") {
                if (value == "namespace") config.backend = execell::sandbox::Backend::namespaces;
                else if (value == "vm") config.backend = execell::sandbox::Backend::vm;
                else {
                    std::cerr << "execell: invalid sandbox backend\n";
                    return EXIT_FAILURE;
                }
                continue;
            }
            std::uint64_t parsed{};
            const auto [end, error] =
                std::from_chars(value.data(), value.data() + value.size(), parsed);
            if (error != std::errc{} || end != value.data() + value.size()) {
                std::cerr << "execell: invalid value for " << option << '\n';
                return EXIT_FAILURE;
            }
            if (option == "--cpu") {
                config.cpu_seconds = parsed;
            } else if (option == "--memory") {
                config.address_space_bytes = parsed;
            } else {
                std::cerr << "execell: unknown sandbox option: " << option << '\n';
                return EXIT_FAILURE;
            }
        }
        if (program_index >= argc) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        return execell::sandbox::run(argv[program_index], &argv[program_index], config);
    }

    if (command == "package") {
        if (argc < 3) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        execell::package::Options options;
        const std::string_view action{argv[2]};
        int argument = 3;
        while (argument < argc && std::string_view{argv[argument]}.starts_with("--")) {
            const std::string_view option{argv[argument++]};
            if (option == "--privileged") {
                std::cerr << "execell: privileged package scanning is disabled; rootless only\n";
                return EXIT_FAILURE;
            }
            if (option == "--yes") {
                std::cerr << "execell: --yes is only valid with disabled privileged scanning\n";
                return EXIT_FAILURE;
            }
            if (option == "--run-all") {
                options.run_all = true;
                continue;
            }
            if (option == "--byte-diff") {
                options.byte_diff = true;
                continue;
            }
            if (argument >= argc) {
                std::cerr << "execell: missing value for " << option << '\n';
                return EXIT_FAILURE;
            }
            const std::string value{argv[argument++]};
            if (option == "--format") {
                if (value != "terminal" && value != "json" && value != "jsonl") {
                    std::cerr << "execell: invalid package format\n";
                    return EXIT_FAILURE;
                }
                options.format = value;
            } else if (option == "--network") {
                if (value != "off" && value != "mirror") {
                    std::cerr << "execell: invalid package network policy\n";
                    return EXIT_FAILURE;
                }
                options.network = value;
            } else if (option == "--mirror") {
                if (!execell::package::network::valid_mirror(value)) {
                    std::cerr << "execell: invalid mirror URL\n";
                    return EXIT_FAILURE;
                }
                options.mirrors.push_back(value);
            } else if (option == "--allow-host") {
                if (value.empty() || value.find('/') != std::string::npos ||
                    value.find('\0') != std::string::npos) {
                    std::cerr << "execell: invalid allowed host\n";
                    return EXIT_FAILURE;
                }
                options.allowed_hosts.push_back(value);
            } else if (option == "--rootfs")
                options.rootfs = value;
            else if (option == "--timeout") {
                std::string seconds = value;
                if (!seconds.empty() && seconds.back() == 's')
                    seconds.pop_back();
                std::uint64_t parsed{};
                const auto [end, error] =
                    std::from_chars(seconds.data(), seconds.data() + seconds.size(), parsed);
                if (error != std::errc{} || end != seconds.data() + seconds.size() ||
                    parsed == 0U) {
                    std::cerr << "execell: invalid package timeout\n";
                    return EXIT_FAILURE;
                }
                options.timeout = std::chrono::seconds(parsed);
            } else if (option == "--workers") {
                std::uint64_t parsed{};
                const auto [end, error] =
                    std::from_chars(value.data(), value.data() + value.size(), parsed);
                if (error != std::errc{} || end != value.data() + value.size() || parsed == 0U ||
                    parsed > 128U) {
                    std::cerr << "execell: invalid package worker count\n";
                    return EXIT_FAILURE;
                }
                options.workers = static_cast<std::size_t>(parsed);
            } else if (option == "--database") {
                options.database = value;
            } else if (option == "--cgroup-root") {
                options.cgroup_root = value;
            } else if (option == "--rebuild") {
                std::uint64_t repetitions{};
                const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), repetitions);
                if (error != std::errc{} || end != value.data() + value.size() || repetitions < 1U || repetitions > 3U) {
                    std::cerr << "execell: invalid rebuild count\n";
                    return EXIT_FAILURE;
                }
                options.build_repetitions = static_cast<std::size_t>(repetitions);
            } else {
                std::cerr << "execell: unknown package option: " << option << '\n';
                return EXIT_FAILURE;
            }
        }
        if (options.network == "mirror" && options.mirrors.empty()) {
            std::cerr << "execell: --network mirror requires --mirror URL\n";
            return EXIT_FAILURE;
        }
        if (options.network == "off" && !options.mirrors.empty()) {
            std::cerr << "execell: --mirror requires --network mirror\n";
            return EXIT_FAILURE;
        }
        execell::package::Result result;
        if (action == "doctor") {
            const auto capabilities = execell::package::rootfs::detect(options.rootfs.empty()
                                                                             ? std::filesystem::path{"/"}
                                                                            : options.rootfs);
            const auto has = [](const char* path) { return ::access(path, X_OK) == 0; };
            if (options.format == "json") {
                std::cout << "{\"schema_version\":1,\"btrfs\":"
                          << (capabilities.btrfs ? "true" : "false")
                          << ",\"rootless\":" << (capabilities.rootless ? "true" : "false")
                          << ",\"mount_namespace\":"
                          << (capabilities.mount_namespace ? "true" : "false")
                          << ",\"user_namespace\":"
                          << (capabilities.user_namespace ? "true" : "false")
                          << ",\"pacman\":" << (has("/usr/bin/pacman") ? "true" : "false")
                          << ",\"makepkg\":" << (has("/usr/bin/makepkg") ? "true" : "false")
                          << ",\"gpgv\":" << (has("/usr/bin/gpgv") ? "true" : "false")
                          << "}\n";
            } else {
                std::cout << "btrfs: " << (capabilities.btrfs ? "yes" : "no") << '\n'
                          << "rootless: " << (capabilities.rootless ? "yes" : "no") << '\n'
                          << "mount namespace: " << (capabilities.mount_namespace ? "yes" : "no") << '\n'
                          << "user namespace: " << (capabilities.user_namespace ? "yes" : "no") << '\n'
                          << "pacman: " << (has("/usr/bin/pacman") ? "yes" : "no") << '\n'
                          << "makepkg: " << (has("/usr/bin/makepkg") ? "yes" : "no") << '\n'
                          << "gpgv: " << (has("/usr/bin/gpgv") ? "yes" : "no") << '\n';
            }
            return (capabilities.btrfs && capabilities.rootless && capabilities.mount_namespace)
                       ? EXIT_SUCCESS
                       : EXIT_FAILURE;
        }
        if (action == "scan" && argument < argc)
            result = execell::package::scan(argv[argument], options);
        else if (action == "compare" && argument + 2 < argc) {
            result = execell::package::compare(argv[argument], argv[argument + 1],
                                               argv[argument + 2], options);
            execell::package::print(result, options);
            return result.ok ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else if (action == "build" && argument < argc) {
            execell::package::build::Options build_options{
                .rootfs = options.rootfs,
                .workspace = options.session_root / "build-workspace",
                .artifact_root = options.session_root / "build-artifacts",
                .timeout = options.timeout,
                .network = options.network == "mirror",
                .allowed_hosts = options.allowed_hosts,
                .cgroup_root = options.cgroup_root,
                .repetitions = options.build_repetitions};
            const auto built = execell::package::build::run(argv[argument], build_options);
            std::cout << (built.ok ? "build: ok" : "build: rejected") << '\n';
            if (!built.error.empty()) std::cout << "error: " << built.error << '\n';
            for (const auto& finding : built.findings) std::cout << "finding: " << finding << '\n';
            if (!built.ok) return EXIT_FAILURE;
            bool packages_ok = true;
            for (const auto& artifact : built.artifacts) {
                const auto scanned = execell::package::scan(artifact, options);
                std::cout << "artifact: " << artifact << " verdict=" << scanned.verdict << '\n';
                packages_ok = packages_ok && scanned.ok;
            }
            return packages_ok ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else if (action == "fetch" && argument < argc)
            result = execell::package::fetch(argv[argument], options);
        else if (action == "report" && argument < argc)
            result = execell::package::report(argv[argument], options);
        else if (action == "cleanup")
            result = execell::package::cleanup(options);
        else {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        execell::package::print(result, options);
        return result.ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    std::cerr << "execell: unknown command: " << command << '\n';

    print_usage(argv[0]);
    return EXIT_FAILURE;
}
