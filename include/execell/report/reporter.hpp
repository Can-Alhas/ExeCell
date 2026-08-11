#pragma once

#include <execell/event/event.hpp>

namespace execell::report {

class Reporter {
public:
    virtual ~Reporter() = default;
    virtual void report(const event::Event& event) = 0;
    [[nodiscard]] virtual bool stop_requested() const noexcept { return false; }
};

} // namespace execell::report
