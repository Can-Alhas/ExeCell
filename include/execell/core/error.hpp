#pragma once

#include <cerrno>
#include <string>
#include <system_error>
#include <utility>

namespace execell {

struct Error {
    std::string operation;
    std::error_code code;

    [[nodiscard]] std::string message() const
    {
        return operation + ": " + code.message();
    }

    [[nodiscard]] static Error from_errno(std::string operation)
    {
        return {std::move(operation), {errno, std::generic_category()}};
    }
};

} // namespace execell
