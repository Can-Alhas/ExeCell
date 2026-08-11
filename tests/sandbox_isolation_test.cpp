#include <execell/sandbox/sandbox.hpp>

#include <cassert>
#include <filesystem>

int main()
{
    constexpr char path[] = "/tmp/execell-host-must-not-exist";
    std::filesystem::remove(path);
    char program[] = "/bin/sh";
    char command[] = "touch /tmp/execell-host-must-not-exist";
    char* args[] = {program, const_cast<char*>("-c"), command, nullptr};
    assert(execell::sandbox::run(program, args, {}) == 0);
    assert(!std::filesystem::exists(path));
}
