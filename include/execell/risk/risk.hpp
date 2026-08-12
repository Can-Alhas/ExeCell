#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <sys/types.h>

namespace execell::risk {

enum class Level { none, low, medium, high, critical };
enum class Action { allow, audit, reject };

struct Factor {
    std::string name;
    int weight{};
    std::string explanation;
};

struct Finding {
    std::string id;
    std::string resource;
    pid_t pid{};
    std::uint64_t sequence{};
    std::string explanation;
    int weight{};
};

struct Assessment {
    int score{};
    Level level{Level::none};
    Action action{Action::allow};
    std::vector<Factor> factors;
    std::vector<Finding> findings;
};

class Engine {
public:
    void add(std::string_view name, int weight, std::string_view explanation);
    void reject(std::string_view name, std::string_view explanation);
    [[nodiscard]] Assessment assess() const;

private:
    std::vector<Factor> factors_;
    bool direct_reject_{};
};

[[nodiscard]] std::string_view to_string(Level) noexcept;
[[nodiscard]] std::string_view to_string(Action) noexcept;

} // namespace execell::risk
