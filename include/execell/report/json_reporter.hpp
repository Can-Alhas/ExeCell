#pragma once

#include <execell/report/reporter.hpp>

#include <ostream>

namespace execell::report {

class JsonReporter final : public Reporter {
public:
    explicit JsonReporter(std::ostream& output) noexcept : output_{output} {}
    ~JsonReporter() override { finish(); }
    void report(const event::Event& event) override;
    void finish();

private:
    std::ostream& output_;
    bool first_{true};
    bool finished_{};
};

} // namespace execell::report
