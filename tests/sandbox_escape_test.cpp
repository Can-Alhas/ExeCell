#include <execell/sandbox/sandbox.hpp>

#include <cassert>
#include <string_view>

int main(int argc, char* argv[])
{
    assert(argc == 2);
    char program[] = "/bin/sh";
    char* args[] = {
        program,
        const_cast<char*>("-c"),
        argv[1],
        nullptr
    };
    assert(execell::sandbox::run(program, args, {}) != 0);
}
