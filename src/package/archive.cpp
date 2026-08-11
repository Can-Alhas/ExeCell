#include <execell/package/archive.hpp>

#include <archive.h>
#include <archive_entry.h>

#include <cerrno>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>

namespace execell::package::archive_adapter {
namespace {

struct Reader {
    struct archive* value{};
    explicit Reader(struct archive* input) : value(input) {}
    ~Reader() { if (value != nullptr) archive_read_free(value); }
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;
    Reader(Reader&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Reader& operator=(Reader&& other) noexcept {
        if (this != &other) {
            if (value != nullptr) archive_read_free(value);
            value = std::exchange(other.value, nullptr);
        }
        return *this;
    }
};

std::expected<Reader, std::string> open(const std::filesystem::path& path,
                                        const Limits& limits) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error) return std::unexpected{"archive stat failed: " + error.message()};
    if (size > limits.max_archive_bytes)
        return std::unexpected{"archive exceeds compressed-size limit"};

    Reader reader{archive_read_new()};
    if (reader.value == nullptr) return std::unexpected{"archive reader allocation failed"};
    if (archive_read_support_filter_all(reader.value) != ARCHIVE_OK ||
        archive_read_support_format_all(reader.value) != ARCHIVE_OK)
        return std::unexpected{"archive format setup failed"};
    if (archive_read_open_filename(reader.value, path.c_str(), 64 * 1024) != ARCHIVE_OK)
        return std::unexpected{"archive open failed: " + std::string(archive_error_string(reader.value))};
    return reader;
}

std::expected<std::string, std::string> safe_path(const char* raw, std::size_t limit) {
    if (raw == nullptr) return std::unexpected{"archive entry has no path"};
    std::string path(raw);
    while (path.starts_with("./")) path.erase(0, 2);
    if (path.empty() || path.size() > limit || path.front() == '/' || path.find('\0') != std::string::npos)
        return std::unexpected{"unsafe archive path"};
    std::size_t begin{};
    while (begin <= path.size()) {
        const auto end = path.find('/', begin);
        const auto component = path.substr(begin, end == std::string::npos ? path.size() - begin : end - begin);
        if (component.empty() || component == "." || component == "..")
            return std::unexpected{"unsafe archive path"};
        if (end == std::string::npos) break;
        begin = end + 1U;
    }
    return path;
}

std::expected<std::string, std::string> safe_link(const char* raw, std::size_t limit) {
    if (raw == nullptr) return std::unexpected{"archive link has no target"};
    std::string target(raw);
    if (target.empty() || target.size() > limit || target.front() == '/' || target.find('\0') != std::string::npos)
        return std::unexpected{"unsafe archive link"};
    std::size_t begin{};
    while (begin <= target.size()) {
        const auto end = target.find('/', begin);
        const auto component = target.substr(begin, end == std::string::npos ? target.size() - begin : end - begin);
        if (component == "..") return std::unexpected{"unsafe archive link"};
        if (end == std::string::npos) break;
        begin = end + 1U;
    }
    return target;
}

std::expected<Entry, std::string> entry_of(struct archive_entry* raw, const Limits& limits) {
    auto path = safe_path(archive_entry_pathname(raw), limits.max_path_bytes);
    if (!path) return std::unexpected{path.error()};
    Entry entry{.path = *path,
                .kind = Kind::regular,
                .link_target = {},
                .size = archive_entry_size_is_set(raw) && archive_entry_size(raw) >= 0
                            ? static_cast<std::uint64_t>(archive_entry_size(raw))
                            : 0U,
                .mode = static_cast<std::uint32_t>(archive_entry_mode(raw))};
    const auto type = archive_entry_filetype(raw);
    if (type == AE_IFLNK) {
        entry.kind = Kind::symlink;
        auto link = safe_link(archive_entry_symlink(raw), limits.max_path_bytes);
        if (!link) return std::unexpected{link.error()};
        entry.link_target = *link;
    } else if (archive_entry_hardlink(raw) != nullptr) {
        entry.kind = Kind::hardlink;
        auto link = safe_link(archive_entry_hardlink(raw), limits.max_path_bytes);
        if (!link) return std::unexpected{link.error()};
        entry.link_target = *link;
    } else if (type == AE_IFREG) {
        entry.kind = Kind::regular;
    } else if (type == AE_IFDIR) {
        entry.size = 0;
    } else {
        return std::unexpected{"unsupported archive entry type"};
    }
    if ((entry.mode & 06000U) != 0U)
        return std::unexpected{"setuid or setgid archive entry rejected"};
    return entry;
}

bool discard_entry(struct archive* reader, std::uint64_t& total,
                   std::uint64_t limit) {
    std::array<char, 65536> buffer{};
    for (;;) {
        const auto count = archive_read_data(reader, buffer.data(), buffer.size());
        if (count == 0) return true;
        if (count < 0) return false;
        const auto bytes = static_cast<std::uint64_t>(count);
        if (bytes > limit - std::min(total, limit)) return false;
        total += bytes;
    }
}

} // namespace

std::expected<std::vector<Entry>, std::string> list(const std::filesystem::path& path,
                                                    const Limits& limits) {
    auto reader = open(path, limits);
    if (!reader) return std::unexpected{reader.error()};
    std::vector<Entry> result;
    std::uint64_t unpacked{};
    archive_entry* raw{};
    while (archive_read_next_header(reader->value, &raw) == ARCHIVE_OK) {
        if (result.size() >= limits.max_entries)
            return std::unexpected{"archive entry-count limit exceeded"};
        auto entry = entry_of(raw, limits);
        if (!entry) return std::unexpected{entry.error()};
        if (entry->size > limits.max_unpacked_bytes - std::min(unpacked, limits.max_unpacked_bytes))
            return std::unexpected{"archive unpacked-size limit exceeded"};
        unpacked += entry->size;
        result.push_back(*entry);
        if (!discard_entry(reader->value, unpacked, limits.max_unpacked_bytes))
            return std::unexpected{"archive unpacked-size limit exceeded"};
    }
    if (archive_errno(reader->value) != 0)
        return std::unexpected{"archive iteration failed: " + std::string(archive_error_string(reader->value))};
    return result;
}

std::expected<std::string, std::string> read(const std::filesystem::path& path,
                                             const std::string& wanted,
                                             std::size_t max_bytes,
                                             const Limits& limits) {
    auto safe = safe_path(wanted.c_str(), limits.max_path_bytes);
    if (!safe) return std::unexpected{safe.error()};
    auto reader = open(path, limits);
    if (!reader) return std::unexpected{reader.error()};
    archive_entry* raw{};
    while (archive_read_next_header(reader->value, &raw) == ARCHIVE_OK) {
        auto entry = entry_of(raw, limits);
        if (!entry) return std::unexpected{entry.error()};
        if (entry->path != *safe) {
            std::uint64_t discarded{};
            if (!discard_entry(reader->value, discarded, limits.max_unpacked_bytes))
                return std::unexpected{"archive entry read failed"};
            continue;
        }
        if (entry->kind != Kind::regular || entry->size > max_bytes)
            return std::unexpected{"archive entry is not bounded regular data"};
        std::string result;
        result.resize(static_cast<std::size_t>(entry->size));
        std::size_t offset{};
        while (offset < result.size()) {
            const auto count = archive_read_data(reader->value, result.data() + offset,
                                                 result.size() - offset);
            if (count <= 0) return std::unexpected{"archive entry read failed"};
            offset += static_cast<std::size_t>(count);
        }
        return result;
    }
    return std::unexpected{"archive entry not found: " + *safe};
}

std::expected<std::string, std::string> validate_path(std::string_view value,
                                                      std::size_t max_bytes) {
    const std::string copy(value);
    return safe_path(copy.c_str(), max_bytes);
}

std::expected<std::string, std::string> validate_link_target(std::string_view value,
                                                             std::size_t max_bytes) {
    const std::string copy(value);
    return safe_link(copy.c_str(), max_bytes);
}

} // namespace execell::package::archive_adapter
