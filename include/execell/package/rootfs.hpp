#pragma once

#include <expected>
#include <filesystem>
#include <string>
#include <sys/types.h>

namespace execell::package::rootfs {

enum class Mode { btrfs, degraded };

struct Capabilities {
    bool btrfs{};
    bool rootless{};
    bool rootful{};
    bool user_namespace{};
    bool mount_namespace{};
};

[[nodiscard]] Capabilities detect(const std::filesystem::path &path = "/tmp");

class Session {
  public:
    Session() = default;
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;
    Session(Session &&other) noexcept;
    Session &operator=(Session &&other) noexcept;
    ~Session();

    [[nodiscard]] static std::expected<Session, std::string>
    create(const std::filesystem::path &source, const std::filesystem::path &workspace);
    [[nodiscard]] const std::filesystem::path &path() const noexcept { return writable_; }
    [[nodiscard]] const std::filesystem::path &source_snapshot() const noexcept { return source_; }
    [[nodiscard]] Mode mode() const noexcept { return mode_; }
    [[nodiscard]] bool isolated() const noexcept { return mode_ == Mode::btrfs; }
    [[nodiscard]] std::string event() const;
    void release() noexcept;

  private:
    std::filesystem::path source_;
    std::filesystem::path writable_;
    std::filesystem::path workspace_;
    std::filesystem::path base_;
    pid_t guardian_{-1};
    Mode mode_{Mode::degraded};
};

} // namespace execell::package::rootfs
