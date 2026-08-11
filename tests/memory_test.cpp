#include <execell/trace/memory.hpp>

#include <cassert>
#include <unistd.h>

int main()
{
    const auto invalid = execell::trace::read_process_memory_string(
        ::getpid(),
        1UL);
    assert(invalid.status == execell::trace::MemoryReadStatus::invalid_address);
    assert(invalid.value.empty());
}
