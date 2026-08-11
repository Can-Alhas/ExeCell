#pragma once

#include <execell/report/reporter.hpp>

#include <cstddef>
#include <iosfwd>

namespace execell::report {

struct Summary final : Reporter {
    std::size_t files_opened{};
    std::size_t files_read{};
    std::size_t files_written{};
    std::size_t processes_spawned{};
    std::size_t network_attempts{};
    std::size_t failures{};

    void report(const event::Event& event) override;
    void print(std::ostream& output) const;
};

} // namespace execell::report
