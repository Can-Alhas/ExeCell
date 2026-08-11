#include <execell/risk/risk.hpp>

#include <algorithm>

namespace execell::risk {

void Engine::add(std::string_view name, int weight, std::string_view explanation) {
    factors_.push_back({std::string(name), std::max(0, weight), std::string(explanation)});
}

void Engine::reject(std::string_view name, std::string_view explanation) {
    factors_.push_back({std::string(name), 0, std::string(explanation)});
    direct_reject_ = true;
}

Assessment Engine::assess() const {
    Assessment result;
    result.factors = factors_;
    for (const auto& factor : factors_) result.score += factor.weight;
    result.score = std::min(result.score, 100);
    if (direct_reject_) {
        result.level = Level::critical;
        result.action = Action::reject;
    } else if (result.score >= 75) {
        result.level = Level::critical;
        result.action = Action::reject;
    } else if (result.score >= 50) {
        result.level = Level::high;
        result.action = Action::reject;
    } else if (result.score >= 25) {
        result.level = Level::medium;
        result.action = Action::audit;
    } else if (result.score != 0) {
        result.level = Level::low;
        result.action = Action::allow;
    }
    return result;
}

std::string_view to_string(Level level) noexcept {
    switch (level) {
    case Level::none: return "none";
    case Level::low: return "low";
    case Level::medium: return "medium";
    case Level::high: return "high";
    case Level::critical: return "critical";
    }
    return "critical";
}

std::string_view to_string(Action action) noexcept {
    switch (action) {
    case Action::allow: return "allow";
    case Action::audit: return "audit";
    case Action::reject: return "reject";
    }
    return "reject";
}

} // namespace execell::risk
