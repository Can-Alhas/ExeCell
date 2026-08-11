#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace execell::package::network {

[[nodiscard]] bool valid_mirror(std::string_view mirror) noexcept;
[[nodiscard]] bool allowed(std::string_view endpoint,
                           const std::vector<std::string>& mirrors) noexcept;
[[nodiscard]] std::string host(std::string_view endpoint);

} // namespace execell::package::network
