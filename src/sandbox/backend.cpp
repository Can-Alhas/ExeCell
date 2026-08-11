#include <execell/sandbox/backend.hpp>

#include <cstdlib>
#include <unistd.h>

namespace execell::sandbox {
namespace {

bool executable(const char* name) {
    const char* path = std::getenv("PATH");
    if (path == nullptr) return false;
    std::string paths(path);
    std::size_t begin{};
    while (begin <= paths.size()) {
        const auto end = paths.find(':', begin);
        const auto directory = paths.substr(begin, end == std::string::npos
                                                    ? paths.size() - begin
                                                    : end - begin);
        if (::access((directory + "/" + name).c_str(), X_OK) == 0) return true;
        if (end == std::string::npos) break;
        begin = end + 1U;
    }
    return false;
}

} // namespace

BackendCapabilities detect_backends() {
    return {.namespaces = true,
            .firecracker = executable("firecracker"),
            .qemu = executable("qemu-system-x86_64")};
}

std::expected<void, std::string> validate_backend(Backend backend) {
    if (backend == Backend::namespaces) return {};
    const auto capabilities = detect_backends();
    if (!capabilities.firecracker && !capabilities.qemu)
        return std::unexpected{"VM backend unavailable: Firecracker or QEMU required"};
    return std::unexpected{"VM backend detected but implementation unavailable"};
}

} // namespace execell::sandbox
