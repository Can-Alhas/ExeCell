#include <execell/package/rootfs.hpp>

#include <cstdlib>
#include <filesystem>

int main() {
    const char* value = std::getenv("EXECELL_ARCH_ROOTFS");
    if (value == nullptr || *value == '\0') return 77;
    const std::filesystem::path root{value};
    const auto capabilities = execell::package::rootfs::detect(root);
    if (!capabilities.btrfs || !capabilities.rootless || !capabilities.mount_namespace)
        return 1;
    if (!std::filesystem::exists(root / "usr/bin/pacman") ||
        !std::filesystem::exists(root / "usr/bin/makepkg"))
        return 1;
    return 0;
}
