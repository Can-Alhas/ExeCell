#include "execell/cli/invocation.hpp"
#include "execell/package/package.hpp"
#include "execell/package/network.hpp"
#include "execell/policy/policy_reporter.hpp"
#include "execell/process/process.hpp"
#include "execell/report/json_reporter.hpp"
#include "execell/report/summary_reporter.hpp"
#include "execell/sandbox/sandbox.hpp"
#include "execell/trace/tracer.hpp"
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string_view>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr std::string_view version{"0.1.0"};

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
        << "  " << executable
        << " sandbox [--network] [--cpu N] [--memory BYTES] <program> [arguments...]\n"
        << "  " << executable << " package scan|fetch|report|cleanup [options] [path]\n"
         << "    options: --privileged --yes --timeout 30s --network off|mirror --mirror URL --run-all --byte-diff\n";
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
            if (program_index >= argc) {
                std::cerr << "execell: missing value for " << option << '\n';
                return EXIT_FAILURE;
            }
            const std::string_view value{argv[program_index++]};
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
                options.privileged = true;
                continue;
            }
            if (option == "--yes") {
                options.confirm_privileged = true;
                continue;
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
        if (options.privileged && !options.confirm_privileged) {
            if (!::isatty(STDIN_FILENO)) {
                std::cerr << "execell: --privileged requires --yes in noninteractive mode\n";
                return EXIT_FAILURE;
            }
            std::cerr << "warning: privileged package execution can modify system state. Continue? [y/N] ";
            std::string answer;
            if (!std::getline(std::cin, answer) || (answer != "y" && answer != "Y")) return EXIT_FAILURE;
        }
        execell::package::Result result;
        if (action == "scan" && argument < argc)
            result = execell::package::scan(argv[argument], options);
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
