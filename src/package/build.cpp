#include <execell/package/build.hpp>

#include <execell/package/aur.hpp>
#include <execell/package/rootfs.hpp>
#include <execell/sandbox/sandbox.hpp>

#include <fstream>
#include <array>
#include <map>
#include <string_view>

namespace execell::package::build {
namespace {

std::string json_escape(std::string value) {
    std::string result;
    for (const char character : value) {
        if (character == '"' || character == '\\') result.push_back('\\');
        result.push_back(character);
    }
    return result;
}

std::string host_from_source(std::string_view source) {
    const auto scheme = source.find("://");
    if (scheme == std::string_view::npos) return {};
    auto host = source.substr(scheme + 3U);
    const auto end = host.find_first_of("/:");
    return std::string(host.substr(0, end));
}

bool allowed(std::string_view host, const std::vector<std::string>& allowlist) {
    for (const auto& entry : allowlist)
        if (host == entry) return true;
    return false;
}

std::string file_fingerprint(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::uint64_t hash = 1469598103934665603ULL;
    std::array<char, 8192> buffer{};
    while (input.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || input.gcount() > 0) {
        for (std::streamsize index = 0; index < input.gcount(); ++index) {
            hash ^= static_cast<unsigned char>(buffer[static_cast<std::size_t>(index)]);
            hash *= 1099511628211ULL;
        }
    }
    return std::to_string(hash);
}

} // namespace

Result run(const std::filesystem::path& pkgbuild, const Options& options) {
    Result result;
    const auto manifest = aur::parse(pkgbuild);
    if (!manifest) {
        result.error = manifest.error();
        return result;
    }
    result.findings = manifest->findings;
    result.phases = manifest->phases;
    for (const auto& source : manifest->sources) {
        const auto host = host_from_source(source.value);
        if (!host.empty() && options.network && !allowed(host, options.allowed_hosts)) {
            result.error = "source host is not allowlisted: " + host;
            result.findings.emplace_back("network source rejected by allowlist: " + host);
            return result;
        }
    }
    std::error_code error;
    std::filesystem::create_directories(options.workspace, error);
    if (error) {
        result.error = "build workspace creation failed: " + error.message();
        return result;
    }
    auto session_result = rootfs::Session::create(options.rootfs, options.workspace);
    if (!session_result) {
        result.error = session_result.error();
        return result;
    }
    auto session = std::move(*session_result);
    if (!session.isolated()) {
        result.error = "build rejected: Btrfs rootfs isolation unavailable";
        return result;
    }
    const auto build_root = session.path() / "build";
    std::filesystem::create_directories(build_root, error);
    if (error) {
        result.error = "build directory creation failed: " + error.message();
        return result;
    }
    std::ifstream input(pkgbuild, std::ios::binary);
    std::ofstream staged(build_root / "PKGBUILD", std::ios::binary | std::ios::trunc);
    staged << input.rdbuf();
    if (!input || !staged) {
        result.error = "PKGBUILD staging failed";
        return result;
    }

    sandbox::Config config;
    config.rootfs = session.path();
    config.working_directory = "/build";
    config.mount_namespace = true;
    config.user_namespace = true;
    config.network_namespace = true;
    config.read_only_root = false;
    config.clean_environment = true;
    config.drop_to_unprivileged_user = true;
    config.cpu_seconds = static_cast<std::uint64_t>(options.timeout.count());
    config.address_space_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    config.max_processes = 256;
    config.max_file_bytes = 512ULL * 1024ULL * 1024ULL;
    config.seccomp_allowlist = sandbox::default_package_syscalls();
    config.cgroup.path = options.cgroup_root;
    result.events.emplace_back("source_download_start");
    result.events.emplace_back(options.network ? "network_requested_isolated" : "network_disabled");
    for (const auto& source : manifest->sources) {
        result.events.push_back("{\"type\":\"source\",\"url\":\"" +
                                json_escape(source.value) + "\",\"sha256\":\"" +
                                json_escape(source.hash) + "\",\"host\":\"" +
                                json_escape(host_from_source(source.value)) + "\"}");
    }
    const auto source_phase = sandbox::run_captured(
        {"/usr/bin/makepkg", "--noconfirm", "--nodeps", "--nobuild"}, config,
        options.timeout, options.output_limit);
    result.status = source_phase.status;
    result.timed_out = source_phase.timed_out;
    result.events.emplace_back(source_phase.timed_out ? "source_download_timeout" : "source_download_complete");
    if (source_phase.timed_out) {
        result.error = "AUR source phase timed out";
        return result;
    }
    if (source_phase.status != 0) {
        result.error = "AUR source phase failed";
        return result;
    }
    result.events.emplace_back("build_start");
    const auto build_phase = sandbox::run_captured(
        {"/usr/bin/makepkg", "--noconfirm", "--nodeps", "--noextract", "--noprepare"}, config,
        options.timeout, options.output_limit);
    result.status = build_phase.status;
    result.timed_out = build_phase.timed_out;
    result.events.emplace_back(build_phase.timed_out ? "build_timeout" : "build_complete");
    if (build_phase.timed_out) {
        result.error = "AUR build timed out";
        return result;
    }
    if (build_phase.status != 0) {
        result.error = "makepkg build phase failed";
        return result;
    }
    std::filesystem::create_directories(options.artifact_root, error);
    if (error) {
        result.error = "artifact directory creation failed: " + error.message();
        return result;
    }
    std::map<std::string, std::string> first_hashes;
    for (const auto& entry : std::filesystem::directory_iterator(build_root, error)) {
        if (error) break;
        if (entry.is_regular_file(error) && entry.path().filename().string().find(".pkg.tar.") != std::string::npos) {
            first_hashes[entry.path().filename().string()] = file_fingerprint(entry.path());
            const auto destination = options.artifact_root / entry.path().filename();
            std::filesystem::copy_file(entry.path(), destination,
                                       std::filesystem::copy_options::overwrite_existing, error);
            if (!error) result.artifacts.push_back(destination);
        }
    }
    for (std::size_t repetition = 1; repetition < options.repetitions; ++repetition) {
        const auto rebuild = sandbox::run_captured(
            {"/usr/bin/makepkg", "--noconfirm", "--nodeps", "--noextract", "--noprepare"},
            config, options.timeout, options.output_limit);
        if (rebuild.timed_out || rebuild.status != 0) {
            result.reproducible = false;
            result.findings.emplace_back("repeat build failed");
            break;
        }
        for (const auto& [name, original] : first_hashes) {
            const auto current = file_fingerprint(build_root / name);
            if (current != original) {
                result.reproducible = false;
                result.findings.emplace_back("non-deterministic artifact: " + name);
            }
        }
    }
    if (!result.reproducible) result.events.emplace_back("reproducibility_mismatch");
    result.ok = !result.artifacts.empty() && result.reproducible;
    if (result.artifacts.empty()) result.error = "makepkg produced no package artifact";
    else if (!result.reproducible) result.error = "reproducibility mismatch";
    return result;
}

} // namespace execell::package::build
