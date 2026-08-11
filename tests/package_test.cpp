#include <execell/package/package.hpp>
#include <execell/package/rootfs.hpp>

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

int main() {
    const auto capabilities = execell::package::rootfs::detect();
    assert(capabilities.mount_namespace);
    (void)capabilities;
    const auto suffix = std::to_string(::getpid());
    const auto rootfs_fixture = std::filesystem::temp_directory_path() / ("execell-rootfs-test-" + suffix);
    std::filesystem::remove_all(rootfs_fixture);
    std::filesystem::create_directories(rootfs_fixture / "source");
    std::ofstream(rootfs_fixture / "source" / "sentinel") << "safe";
    {
        auto session = execell::package::rootfs::Session::create(
            rootfs_fixture / "source", rootfs_fixture / "workspace");
        assert(session);
        assert(!session->path().empty());
        assert(session->event().find("rootfs_") != std::string::npos);
        assert(std::filesystem::exists(session->path()));
        assert(std::filesystem::exists(session->path() / "sentinel") || !session->isolated());
        const auto path = session->path();
        session->release();
        assert(!std::filesystem::exists(path));
    }
    std::filesystem::remove_all(rootfs_fixture);

    execell::package::Options options;
    const auto invalid = execell::package::scan("not-a-package", options);
    assert(!invalid.ok);
    assert(invalid.error.find(".pkg.tar") != std::string::npos);
    const auto fixture = std::filesystem::temp_directory_path() / ("execell-package-test-" + suffix);
    std::filesystem::remove_all(fixture);
    std::filesystem::create_directories(fixture);
    const auto tar = fixture / "tar";
    const auto key = fixture / "pacman-key";
    {
        std::ofstream script(tar);
        script << "#!/bin/sh\n"
                  "case \"$*\" in\n"
                  "  *\\.PKGINFO*) printf 'pkgname = fixture\\npkgver = 1\\narch = x86_64\\n';;\n"
                  "  *--null*) printf 'usr/bin/tool\\000';;\n"
                  "  *) printf '#!/bin/sh\\nexit 0\\n';;\n"
                  "esac\n";
    }
    {
        std::ofstream script(key);
        script << "#!/bin/sh\nexit 0\n";
    }
    (void)::chmod(tar.c_str(), 0700);
    (void)::chmod(key.c_str(), 0700);
    const char* old_path = std::getenv("PATH");
    const std::string path = fixture.string() + ":" + (old_path == nullptr ? "" : old_path);
    (void)::setenv("PATH", path.c_str(), 1);
    const auto archive = fixture / "fixture.pkg.tar.zst";
    std::ofstream(archive) << "not an archive";
    std::ofstream(archive.string() + ".sig") << "signature";
    options.session_root = fixture / "sessions";
    const auto scanned = execell::package::scan(archive, options);
    assert(scanned.ok);
    assert(scanned.session != std::filesystem::path{});
    for (const char* name : {"metadata.json", "summary.json", "events.jsonl", "filesystem.json", "processes.json", "network.json", "risk.json"}) {
        assert(std::filesystem::exists(scanned.session / name));
        (void)name;
    }
    const auto second = execell::package::scan(archive, options);
    assert(second.ok);
    assert(scanned.session != second.session);
    {
        std::ofstream script(tar);
        script << "#!/bin/sh\n"
                  "case \"$*\" in\n"
                  "  *\\.PKGINFO*) printf 'pkgname = fixture\\npkgver = 1\\narch = x86_64\\n';;\n"
                  "  *--null*) printf '../escape\\000';;\n"
                  "esac\n";
    }
    (void)::chmod(tar.c_str(), 0700);
    const auto rejected = execell::package::scan(archive, options);
    assert(!rejected.ok);
    assert(rejected.error.find("unsafe archive path") != std::string::npos);
    if (old_path == nullptr) (void)::unsetenv("PATH"); else (void)::setenv("PATH", old_path, 1);
    std::filesystem::remove_all(fixture);
    const auto cleaned = execell::package::cleanup(options);
    assert(cleaned.ok);
}
