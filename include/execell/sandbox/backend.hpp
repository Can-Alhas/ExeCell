#pragma once

#include <expected>
#include <string>

namespace execell::sandbox {

enum class Backend { namespaces, vm };

struct BackendCapabilities {
    bool namespaces{};
    bool firecracker{};
    bool qemu{};
};

[[nodiscard]] BackendCapabilities detect_backends();
[[nodiscard]] std::expected<void, std::string> validate_backend(Backend);

} // namespace execell::sandbox
