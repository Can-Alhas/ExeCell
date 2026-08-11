#include <execell/package/network.hpp>

#include <cctype>

namespace execell::package::network {
namespace {
std::string extract_host(std::string_view value) {
    const std::size_t scheme = value.find("://");
    if (scheme == std::string_view::npos || scheme == 0U) return {};
    const std::size_t begin = scheme + 3U;
    const std::size_t end = value.find_first_of("/:?#", begin);
    const std::string_view name = value.substr(begin, end == std::string_view::npos
                                                         ? value.size() - begin : end - begin);
    if (name.empty() || name.find('@') != std::string_view::npos) return {};
    for (const char raw_character : name) {
        const auto character = static_cast<unsigned char>(raw_character);
        if (!(std::isalnum(character) != 0 || character == '.' || character == '-')) return {};
    }
    return std::string(name);
}
}

std::string host(std::string_view endpoint) { return extract_host(endpoint); }

bool valid_mirror(std::string_view mirror) noexcept {
    const std::size_t scheme = mirror.find("://");
    if (scheme != 4U && scheme != 5U) return false;
    if (mirror.substr(0, scheme) != "http" && mirror.substr(0, scheme) != "https") return false;
    return !extract_host(mirror).empty();
}

bool allowed(std::string_view endpoint, const std::vector<std::string>& mirrors) noexcept {
    const std::string endpoint_host = extract_host(endpoint);
    if (endpoint_host.empty()) return false;
    for (const auto& mirror : mirrors)
        if (extract_host(mirror) == endpoint_host) return true;
    return false;
}

} // namespace execell::package::network
