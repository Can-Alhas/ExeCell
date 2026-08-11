#include <execell/package/storage.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <set>
#include <string_view>
#include <utility>

namespace execell::package::storage {
namespace {

sqlite3 *db(void *handle) { return static_cast<sqlite3 *>(handle); }

void check(int result, sqlite3 *database, std::string_view operation) {
    if (result != SQLITE_OK)
        throw std::runtime_error(std::string(operation) + ": " + sqlite3_errmsg(database));
}

void exec(sqlite3 *database, const char *sql) { check(sqlite3_exec(database, sql, nullptr, nullptr, nullptr), database, "sqlite"); }

class Statement {
public:
    Statement(sqlite3 *database, const char *sql) : database_(database) {
        check(sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr), database, "prepare");
    }
    ~Statement() { sqlite3_finalize(statement_); }
    Statement(const Statement &) = delete;
    Statement &operator=(const Statement &) = delete;

    void text(int index, const std::string &value) { check(sqlite3_bind_text(statement_, index, value.c_str(), -1, SQLITE_TRANSIENT), database_, "bind text"); }
    void integer(int index, std::int64_t value) { check(sqlite3_bind_int64(statement_, index, value), database_, "bind integer"); }
    bool next() { const int result = sqlite3_step(statement_); if (result == SQLITE_ROW) return true; if (result == SQLITE_DONE) return false; check(result, database_, "step"); return false; }
    void reset() { check(sqlite3_reset(statement_), database_, "reset"); check(sqlite3_clear_bindings(statement_), database_, "clear bindings"); }
    std::string text(int index) const { const auto *value = sqlite3_column_text(statement_, index); return value == nullptr ? std::string{} : reinterpret_cast<const char *>(value); }
    std::int64_t integer(int index) const { return sqlite3_column_int64(statement_, index); }

private:
    sqlite3 *database_{};
    sqlite3_stmt *statement_{};
};

void migrate(sqlite3 *database) {
    exec(database, "PRAGMA foreign_keys = ON;");
    exec(database, "BEGIN IMMEDIATE;");
    try {
        exec(database, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);");
        Statement current(database, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;");
        const int version = current.next() ? static_cast<int>(current.integer(0)) : 0;
        if (version > schema_version)
            throw std::runtime_error("database schema is newer than this build");
        if (version < 1) {
            exec(database, "CREATE TABLE observations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL, architecture TEXT NOT NULL, signature TEXT NOT NULL, source_revision TEXT NOT NULL, dependency_fingerprint TEXT NOT NULL, package_hash TEXT NOT NULL, build_options TEXT NOT NULL, static_fingerprint TEXT NOT NULL, dynamic_fingerprint TEXT NOT NULL, baseline INTEGER NOT NULL DEFAULT 0, observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);");
            exec(database, "CREATE TABLE events (id INTEGER PRIMARY KEY, observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE, category TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL, detail TEXT NOT NULL, dynamic INTEGER NOT NULL);");
            exec(database, "CREATE INDEX events_observation_idx ON events(observation_id);");
            exec(database, "INSERT INTO schema_migrations(version) VALUES (1);");
        }
        exec(database, "COMMIT;");
    } catch (...) {
        (void)sqlite3_exec(database, "ROLLBACK;", nullptr, nullptr, nullptr);
        throw;
    }
}

void bind_identity(Statement &statement, const PackageIdentity &identity) {
    statement.text(1, identity.name); statement.text(2, identity.version); statement.text(3, identity.architecture);
    statement.text(4, identity.signature); statement.text(5, identity.source_revision); statement.text(6, identity.dependency_fingerprint);
    statement.text(7, identity.package_hash); statement.text(8, identity.build_options); statement.text(9, identity.static_fingerprint);
    statement.text(10, identity.dynamic_fingerprint);
}

} // namespace

Database Database::open(const std::filesystem::path &path) {
    sqlite3 *database = nullptr;
    const auto filename = path.string();
    const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    const int result = sqlite3_open_v2(filename.c_str(), &database, flags, nullptr);
    if (result != SQLITE_OK) {
        const std::string message = database == nullptr ? "sqlite open failed" : sqlite3_errmsg(database);
        if (database != nullptr)
            sqlite3_close(database);
        throw std::runtime_error("open database: " + message);
    }
    try { migrate(database); } catch (...) { sqlite3_close(database); throw; }
    return Database(database);
}

Database::Database(void *handle) : handle_(handle) {}
Database::Database(Database &&other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
Database &Database::operator=(Database &&other) noexcept { if (this != &other) { if (handle_ != nullptr) sqlite3_close(db(handle_)); handle_ = std::exchange(other.handle_, nullptr); } return *this; }
Database::~Database() { if (handle_ != nullptr) sqlite3_close(db(handle_)); }

int Database::version() const noexcept { return schema_version; }

Observation Database::store(const PackageIdentity &identity, const std::vector<Event> &events) {
    auto *database = db(handle_);
    exec(database, "BEGIN IMMEDIATE;");
    try {
        Statement insert(database, "INSERT INTO observations(name,version,architecture,signature,source_revision,dependency_fingerprint,package_hash,build_options,static_fingerprint,dynamic_fingerprint,baseline) VALUES (?,?,?,?,?,?,?,?,?,?,NOT EXISTS (SELECT 1 FROM observations WHERE name=?));");
        bind_identity(insert, identity); insert.text(11, identity.name); if (insert.next()) {}
        const auto id = sqlite3_last_insert_rowid(database);
        Statement event_insert(database, "INSERT INTO events(observation_id,category,action,subject,detail,dynamic) VALUES (?,?,?,?,?,?);");
        for (const auto &event : events) {
            event_insert.integer(1, id); event_insert.text(2, event.category); event_insert.text(3, event.action); event_insert.text(4, event.subject); event_insert.text(5, event.detail); event_insert.integer(6, event.dynamic ? 1 : 0);
            if (event_insert.next()) {}
            event_insert.reset();
        }
        exec(database, "COMMIT;");
        Statement baseline(database, "SELECT baseline FROM observations WHERE id=?;"); baseline.integer(1, id);
        return {id, baseline.next() && baseline.integer(0) != 0};
    } catch (...) { (void)sqlite3_exec(database, "ROLLBACK;", nullptr, nullptr, nullptr); throw; }
}

VersionDelta Database::compare(const std::string &name, const std::string &from, const std::string &to) const {
    auto *database = db(handle_); VersionDelta result;
    Statement query(database, "SELECT id, version, architecture, signature, source_revision, dependency_fingerprint, package_hash, build_options, static_fingerprint, dynamic_fingerprint, baseline FROM observations WHERE name=? AND version IN (?,?) ORDER BY id;");
    query.text(1, name); query.text(2, from); query.text(3, to);
    std::int64_t from_id{}; std::int64_t to_id{}; std::string from_arch; std::string to_arch; std::string from_sig; std::string to_sig; std::string from_source; std::string to_source; std::string from_deps; std::string to_deps; std::string from_hash; std::string to_hash; std::string from_options; std::string to_options; std::string from_static; std::string to_static; std::string from_dynamic; std::string to_dynamic; bool baseline{};
    while (query.next()) { const bool is_from = query.text(1) == from; auto &id = is_from ? from_id : to_id; id = query.integer(0); auto &arch = is_from ? from_arch : to_arch; arch = query.text(2); auto &sig = is_from ? from_sig : to_sig; sig = query.text(3); auto &source = is_from ? from_source : to_source; source = query.text(4); auto &deps = is_from ? from_deps : to_deps; deps = query.text(5); auto &hash = is_from ? from_hash : to_hash; hash = query.text(6); auto &options = is_from ? from_options : to_options; options = query.text(7); auto &static_fingerprint = is_from ? from_static : to_static; static_fingerprint = query.text(8); auto &dynamic_fingerprint = is_from ? from_dynamic : to_dynamic; dynamic_fingerprint = query.text(9); if (is_from) baseline = query.integer(10) != 0; }
    if (from_id == 0 || to_id == 0)
        return result;
    result.compared = true;
    result.from_baseline = baseline;
    result.identity_changed = from_arch != to_arch || from_sig != to_sig || from_hash != to_hash || from_options != to_options || from_static != to_static || from_dynamic != to_dynamic;
    result.source_changed = from_source != to_source;
    result.dependencies_changed = from_deps != to_deps;
    std::set<std::string> old_events; std::set<std::string> new_events; for (const auto &pair : {std::pair{from_id, &old_events}, std::pair{to_id, &new_events}}) { Statement events(database, "SELECT category || char(31) || action || char(31) || subject || char(31) || detail || char(31) || dynamic FROM events WHERE observation_id=?;"); events.integer(1, pair.first); while (events.next()) pair.second->insert(events.text(0)); }
    std::set_difference(new_events.begin(), new_events.end(), old_events.begin(), old_events.end(), std::back_inserter(result.added_events)); std::set_difference(old_events.begin(), old_events.end(), new_events.begin(), new_events.end(), std::back_inserter(result.removed_events)); return result;
}

std::optional<std::string> Database::previous_version(const std::string &name,
                                                       const std::string &current) const {
    Statement query(db(handle_),
                    "SELECT version FROM observations WHERE name=? AND version<>? "
                    "ORDER BY id DESC LIMIT 1;");
    query.text(1, name);
    query.text(2, current);
    if (!query.next()) return std::nullopt;
    return query.text(0);
}

} // namespace execell::package::storage
