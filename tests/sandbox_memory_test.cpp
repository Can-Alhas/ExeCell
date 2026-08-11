#include <execell/sandbox/sandbox.hpp>

#include <cassert>

int main(int argc, char* argv[])
{
    assert(argc == 2);
    char* args[] = {argv[1], nullptr};
    execell::sandbox::Config config{.address_space_bytes = 16U * 1024U * 1024U};
    assert(execell::sandbox::run(argv[1], args, config) != 0);
}
