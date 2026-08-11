#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace execell::package::storage {

inline constexpr int schema_version = 1;

struct PackageIdentity {
    std::string name;
    std::string version;
    std::string architecture;
    std::string signature;
    std::string source_revision;
    std::string dependency_fingerprint;
    std::string package_hash;
    std::string build_options;
    std::string static_fingerprint;
    std::string dynamic_fingerprint;
};

struct Event {
    std::string category;
    std::string action;
    std::string subject;
    std::string detail;
    bool dynamic{};
};

struct Observation {
    std::int64_t id{};
    bool baseline{};
};

struct VersionDelta {
    bool compared{};
    bool from_baseline{};
    bool identity_changed{};
    bool source_changed{};
    bool dependencies_changed{};
    std::vector<std::string> added_events;
    std::vector<std::string> removed_events;
};

class Database {
public:
    static Database open(const std::filesystem::path &path);

    Database(Database &&) noexcept;
    Database &operator=(Database &&) noexcept;
    Database(const Database &) = delete;
    Database &operator=(const Database &) = delete;
    ~Database();

    [[nodiscard]] int version() const noexcept;
    Observation store(const PackageIdentity &, const std::vector<Event> &);
    VersionDelta compare(const std::string &package_name,
                         const std::string &from_version,
                         const std::string &to_version) const;
    [[nodiscard]] std::optional<std::string>
    previous_version(const std::string &package_name, const std::string &current_version) const;

private:
    explicit Database(void *handle);
    void *handle_{};
};

} // namespace execell::package::storage
