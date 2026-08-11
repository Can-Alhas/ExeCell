#include <execell/package/archive.hpp>

#include <archive.h>
#include <archive_entry.h>

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <unistd.h>

namespace {
void add_file(archive* output, const char* path, const char* data) {
    archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, path);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_entry_set_size(entry, static_cast<la_int64_t>(std::string(data).size()));
    if (archive_write_header(output, entry) != ARCHIVE_OK ||
        archive_write_data(output, data, std::string(data).size()) < 0)
        std::abort();
    archive_entry_free(entry);
}

void add_setuid_file(archive* output) {
    archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, "usr/bin/setuid-fixture");
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 04755);
    archive_entry_set_size(entry, 3);
    if (archive_write_header(output, entry) != ARCHIVE_OK ||
        archive_write_data(output, "bad", 3) < 0)
        std::abort();
    archive_entry_free(entry);
}
}

int main() {
    const auto path = std::filesystem::temp_directory_path() /
                      ("execell-archive-test-" + std::to_string(::getpid()) + ".pkg.tar");
    archive* output = archive_write_new();
    if (output == nullptr || archive_write_set_format_pax_restricted(output) != ARCHIVE_OK ||
        archive_write_open_filename(output, path.c_str()) != ARCHIVE_OK)
        return 1;
    add_file(output, ".PKGINFO", "pkgname = fixture\npkgver = 1\narch = x86_64\n");
    add_file(output, "usr/bin/tool", "#!/bin/sh\nexit 0\n");
    if (archive_write_close(output) != ARCHIVE_OK) return 1;
    archive_write_free(output);

    const auto entries = execell::package::archive_adapter::list(path);
    if (!entries || entries->size() != 2U) return 1;
    const auto info = execell::package::archive_adapter::read(path, ".PKGINFO", 1024U);
    if (!info || info->find("pkgname = fixture") == std::string::npos) return 1;
    std::filesystem::remove(path);

    const auto unsafe_path = std::filesystem::temp_directory_path() /
                             ("execell-archive-unsafe-" + std::to_string(::getpid()) + ".pkg.tar");
    output = archive_write_new();
    if (output == nullptr || archive_write_set_format_pax_restricted(output) != ARCHIVE_OK ||
        archive_write_open_filename(output, unsafe_path.c_str()) != ARCHIVE_OK)
        return 1;
    add_file(output, "../escape", "bad");
    if (archive_write_close(output) != ARCHIVE_OK) return 1;
    archive_write_free(output);
    if (execell::package::archive_adapter::list(unsafe_path)) return 1;
    std::filesystem::remove(unsafe_path);

    const auto mode_path = std::filesystem::temp_directory_path() /
                           ("execell-archive-mode-" + std::to_string(::getpid()) + ".pkg.tar");
    output = archive_write_new();
    if (output == nullptr || archive_write_set_format_pax_restricted(output) != ARCHIVE_OK ||
        archive_write_open_filename(output, mode_path.c_str()) != ARCHIVE_OK)
        return 1;
    add_setuid_file(output);
    if (archive_write_close(output) != ARCHIVE_OK) return 1;
    archive_write_free(output);
    if (execell::package::archive_adapter::list(mode_path)) return 1;
    std::filesystem::remove(mode_path);
}
