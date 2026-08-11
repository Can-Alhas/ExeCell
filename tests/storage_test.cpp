#include <execell/package/storage.hpp>

#include <cassert>
#include <filesystem>
#include <string>
#include <unistd.h>

int main() {
    const auto path = std::filesystem::temp_directory_path() /
                      ("execell-storage-test-" + std::to_string(::getpid()) + ".db");
    std::filesystem::remove(path);
    {
        auto database = execell::package::storage::Database::open(path);
        assert(database.version() == execell::package::storage::schema_version);

        execell::package::storage::PackageIdentity first{
            "fixture", "1", "x86_64", "signed", "commit-a", "deps-a",
            "hash-a", "-O2", "static-a", "dynamic-a"};
        const auto baseline = database.store(first, {{"filesystem", "create", "/etc/fixture", "mode=755", false}});
        (void)baseline;
        assert(baseline.baseline);
        assert(baseline.id > 0);

        auto second = first;
        second.version = "2";
        second.source_revision = "commit-b";
        second.dependency_fingerprint = "deps-b";
        second.package_hash = "hash-b";
        const auto observation = database.store(second, {{"filesystem", "create", "/etc/fixture", "mode=755", false},
                                                         {"network", "connect", "example.test:443", "success", true}});
        (void)observation;
        assert(!observation.baseline);

        const auto delta = database.compare("fixture", "1", "2");
        assert(delta.compared);
        assert(delta.from_baseline);
        assert(delta.source_changed);
        assert(delta.dependencies_changed);
        assert(delta.identity_changed);
        assert(delta.added_events.size() == 1);
        assert(delta.removed_events.empty());
    }
    std::filesystem::remove(path);
}
