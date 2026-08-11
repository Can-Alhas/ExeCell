#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace execell::package::archive_adapter {

enum class Kind { regular, symlink, hardlink };

struct Entry {
    std::string path;
    Kind kind{Kind::regular};
    std::string link_target;
    std::uint64_t size{};
    std::uint32_t mode{};
};

struct Limits {
    std::uint64_t max_archive_bytes{1ULL << 32U};
    std::uint64_t max_unpacked_bytes{1ULL << 30U};
    std::size_t max_entries{100000U};
    std::size_t max_path_bytes{4096U};
};

[[nodiscard]] std::expected<std::vector<Entry>, std::string>
list(const std::filesystem::path&, const Limits& = {});

[[nodiscard]] std::expected<std::string, std::string>
read(const std::filesystem::path&, const std::string&, std::size_t max_bytes,
     const Limits& = {});

[[nodiscard]] std::expected<std::string, std::string>
validate_path(std::string_view, std::size_t max_bytes = 4096U);

[[nodiscard]] std::expected<std::string, std::string>
validate_link_target(std::string_view, std::size_t max_bytes = 4096U);

} // namespace execell::package::archive_adapter
