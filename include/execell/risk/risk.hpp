#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace execell::risk {

enum class Level { none, low, medium, high, critical };
enum class Action { allow, audit, reject };

struct Factor {
    std::string name;
    int weight{};
    std::string explanation;
};

struct Assessment {
    int score{};
    Level level{Level::none};
    Action action{Action::allow};
    std::vector<Factor> factors;
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
