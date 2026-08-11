#pragma once

#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace execell::package::aur {

struct Source {
    std::string value;
    std::string hash;
};

struct Manifest {
    std::string name;
    std::string version;
    std::string release;
    std::vector<std::string> architectures;
    std::vector<Source> sources;
    std::vector<std::string> phases;
    std::vector<std::string> findings;
};

[[nodiscard]] std::expected<Manifest, std::string>
parse(const std::filesystem::path&, std::size_t max_bytes = 1U << 20U);

} // namespace execell::package::aur
