#include <execell/sandbox/sandbox.hpp>

#include <cassert>

int main()
{
    char program[] = "/bin/sh";
    char command[] = "while :; do :; done";
    char* args[] = {program, const_cast<char*>("-c"), command, nullptr};
    execell::sandbox::Config config{.cpu_seconds = 1};
    assert(execell::sandbox::run(program, args, config) != 0);
}
