#pragma once

#include <execell/policy/policy.hpp>
#include <execell/report/reporter.hpp>

#include <utility>

namespace execell::policy {

class Reporter final : public execell::report::Reporter {
public:
    Reporter(Config config, execell::report::Reporter& downstream)
        : engine_{std::move(config)}, downstream_{downstream} {}

    void report(const event::Event& event) override;
    [[nodiscard]] bool stop_requested() const noexcept override { return denied_; }
    [[nodiscard]] bool denied() const noexcept { return denied_; }
    [[nodiscard]] const Engine& engine() const noexcept { return engine_; }

private:
    Engine engine_;
    execell::report::Reporter& downstream_;
    bool denied_{};
};

} // namespace execell::policy
