#include <execell/package/aur.hpp>

#include <fstream>
#include <array>
#include <regex>
#include <sstream>
#include <string_view>
#include <utility>

namespace execell::package::aur {
namespace {

std::string assignment(std::string_view text, std::string_view key) {
    const std::string prefix = std::string(key) + "=";
    std::size_t position{};
    while (position < text.size()) {
        const auto end = text.find('\n', position);
        auto line = text.substr(position, end == std::string_view::npos ? text.size() - position : end - position);
        while (line.starts_with(" ") || line.starts_with("\t")) line.remove_prefix(1);
        if (line.starts_with(prefix)) {
            line.remove_prefix(prefix.size());
            while (line.starts_with(" ") || line.starts_with("\t")) line.remove_prefix(1);
            if (line.size() >= 2U && ((line.front() == '\'' && line.back() == '\'') ||
                                      (line.front() == '"' && line.back() == '"')))
                line = line.substr(1, line.size() - 2U);
            return std::string(line);
        }
        if (end == std::string_view::npos) break;
        position = end + 1U;
    }
    return {};
}

std::vector<std::string> words(std::string value) {
    for (char& character : value)
        if (character == '(' || character == ')' || character == '"' || character == '\'') character = ' ';
    std::istringstream input(value);
    std::vector<std::string> result;
    for (std::string word; input >> word;) result.push_back(std::move(word));
    return result;
}

} // namespace

std::expected<Manifest, std::string> parse(const std::filesystem::path& path,
                                            std::size_t max_bytes) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error))
        return std::unexpected{"PKGBUILD is not a regular file"};
    if (std::filesystem::file_size(path, error) > max_bytes)
        return std::unexpected{"PKGBUILD exceeds size limit"};
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::unexpected{"PKGBUILD open failed"};
    const std::string text{std::istreambuf_iterator<char>(input), {}};
    if (text.find('\0') != std::string::npos)
        return std::unexpected{"PKGBUILD contains NUL byte"};

    Manifest result;
    result.name = assignment(text, "pkgname");
    result.version = assignment(text, "pkgver");
    result.release = assignment(text, "pkgrel");
    result.architectures = words(assignment(text, "arch"));
    const auto source_words = words(assignment(text, "source"));
    const auto hash_words = words(assignment(text, "sha256sums"));
    for (std::size_t index = 0; index < source_words.size(); ++index)
        result.sources.push_back({source_words[index],
                                  index < hash_words.size() ? hash_words[index] : std::string{}});

    static constexpr std::array<std::string_view, 5> phase_names{
        "prepare", "build", "check", "package", "pkgver"};
    for (const auto phase : phase_names)
        if (text.find(std::string(phase) + "()") != std::string::npos)
            result.phases.emplace_back(phase);

    static constexpr std::array<std::string_view, 10> suspicious{
        "eval", "curl | sh", "wget | sh", "systemctl", "sudo", "setcap",
        "chmod +s", "mount ", "insmod", "modprobe"};
    for (const auto pattern : suspicious)
        if (text.find(pattern) != std::string::npos)
            result.findings.emplace_back("PKGBUILD contains suspicious construct: " + std::string(pattern));
    if (result.name.empty() || result.version.empty())
        return std::unexpected{"PKGBUILD missing pkgname or pkgver"};
    if (result.architectures.empty()) result.findings.emplace_back("architecture declaration missing");
    return result;
}

} // namespace execell::package::aur
