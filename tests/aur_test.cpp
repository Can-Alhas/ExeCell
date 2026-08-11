#include <execell/package/aur.hpp>
#include <execell/package/build.hpp>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <unistd.h>

int main() {
    const auto path = std::filesystem::temp_directory_path() /
                      ("execell-aur-test-" + std::to_string(::getpid()));
    {
        std::ofstream output(path);
        output << "pkgname=fixture\npkgver=1.2\npkgrel=1\narch=('x86_64')\n"
                  "source=('https://example.test/source.tar.gz')\n"
                  "sha256sums=('abc')\nbuild() { curl | sh; }\n";
    }
    const auto parsed = execell::package::aur::parse(path);
    assert(parsed);
    assert(parsed->name == "fixture");
    assert(parsed->version == "1.2");
    assert(parsed->sources.size() == 1U);
    assert(!parsed->findings.empty());
    execell::package::build::Options build_options;
    build_options.network = true;
    const auto rejected = execell::package::build::run(path, build_options);
    if (rejected.ok || rejected.error.find("allowlisted") == std::string::npos) return 1;
    std::filesystem::remove(path);
}
