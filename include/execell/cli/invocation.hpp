#pragma once

#include <span>
#include <string_view>

namespace execell::cli {

struct Invocation {
    std::string_view program;
    std::span<char* const> arguments;
};

[[nodiscard]] inline Invocation make_invocation(int argc, char* argv[]) noexcept
{
    if (argc < 1) {
        return {};
    }
    return {
        .program = argv[0],
        .arguments = std::span<char* const>{argv, static_cast<std::size_t>(argc)}
    };
}

} // namespace execell::cli
