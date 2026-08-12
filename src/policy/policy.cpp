#include <execell/policy/policy.hpp>

#include <type_traits>
#include <utility>

namespace execell::policy {

Engine::Engine(Config config)
    : config_{std::move(config)}
{
}

Decision Engine::evaluate(const event::Event& event)
{
    std::string resource;
    std::string syscall;
    bool process_spawn{};
    std::visit([&resource](const auto& value) {
        if constexpr (requires { value.path; }) {
            resource = value.path;
        } else if constexpr (requires { value.endpoint; }) {
            resource = value.endpoint;
        }
    }, event);

    std::visit([&](const auto& value) {
        using T = std::remove_cvref_t<decltype(value)>;
        if constexpr (std::is_same_v<T, event::SyscallFailed>) {
            syscall = value.syscall;
        } else if constexpr (std::is_same_v<T, event::ProcessSpawned>) {
            process_spawn = true;
            ++process_count_;
        }
    }, event);

    for (const auto& denied : config_.denied_paths) {
        if (resource.starts_with(denied.string())) {
            violations_.push_back({"denied-path", resource,
                                    std::visit([](const auto& value) { return value.context; }, event)});
            return Decision::deny;
        }
    }
    for (const auto& denied : config_.denied_endpoints) {
        if (!resource.empty() && resource.starts_with(denied)) {
            violations_.push_back({"denied-endpoint", resource,
                                    std::visit([](const auto& value) { return value.context; }, event)});
            return Decision::deny;
        }
    }
    for (const auto& denied : config_.denied_syscalls) {
        if (syscall == denied) {
            violations_.push_back({"denied-syscall", syscall,
                                    std::visit([](const auto& value) { return value.context; }, event)});
            return Decision::deny;
        }
    }
    if (process_spawn && config_.max_processes != 0 &&
        process_count_ > config_.max_processes) {
        violations_.push_back({"process-limit", "process",
                                std::visit([](const auto& value) { return value.context; }, event)});
        return Decision::deny;
    }
    return Decision::allow;
}

std::size_t Engine::process_count() const noexcept
{
    return process_count_;
}

const std::vector<Violation>& Engine::violations() const noexcept
{
    return violations_;
}

} // namespace execell::policy
