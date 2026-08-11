#include <execell/trace/fd_table.hpp>

#include <cassert>

int main()
{
    execell::trace::FdTable table;
    table.track(execell::FileDescriptor{2}, "/tmp/typed");
    assert(table.contains(execell::FileDescriptor{2}));
    table.close(execell::FileDescriptor{2});
    table.track(3, "/tmp/input");
    assert(table.contains(3));
    assert(table.lookup(3)->get() == "/tmp/input");

    table.duplicate(3, 7);
    assert(table.lookup(7)->get() == "/tmp/input");

    table.track(7, "/tmp/output");
    table.duplicate(3, 7);
    assert(table.lookup(7)->get() == "/tmp/input");

    table.close(3);
    assert(!table.contains(3));
    table.duplicate(3, 7);
    assert(!table.contains(7));

    table.track(execell::FileDescriptor{4}, "/tmp/a");
    table.track(execell::FileDescriptor{8}, "/tmp/b");
    table.close_range(4, 8);
    assert(!table.contains(4));
    assert(!table.contains(8));
}
