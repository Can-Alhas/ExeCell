#pragma once

#include <execell/event/event.hpp>

#include <filesystem>
#include <string>
#include <vector>
#include <string_view>
#include <cstddef>

namespace execell::policy {

enum class Decision { allow, deny };

struct Violation {
    std::string rule;
    std::string resource;
};

struct Config {
    std::vector<std::filesystem::path> denied_paths;
    std::vector<std::string> denied_endpoints;
    std::vector<std::string> denied_syscalls;
    std::size_t max_processes{};
};

class Engine {
public:
    explicit Engine(Config config = {});

    [[nodiscard]] Decision evaluate(const event::Event& event);
    [[nodiscard]] const std::vector<Violation>& violations() const noexcept;
    [[nodiscard]] std::size_t process_count() const noexcept;

private:
    Config config_;
    std::vector<Violation> violations_;
    std::size_t process_count_{};
};

} // namespace execell::policy
