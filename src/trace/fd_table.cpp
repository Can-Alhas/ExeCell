#include <execell/trace/fd_table.hpp>

#include <optional>
#include <string_view>
#include <utility>

namespace execell::trace {

void FdTable::track(int fd, std::string path) {

    entries_.insert_or_assign(fd, std::move(path));
}

void FdTable::track(FileDescriptor fd, std::string path)
{
    track(fd.value, std::move(path));
}

void FdTable::duplicate(int source_fd, int target_fd) {
    const auto path = lookup(source_fd);
    if (!path) {
        close(target_fd);
        return;
    }

    track(target_fd, path->get());
}

void FdTable::duplicate(FileDescriptor source_fd, FileDescriptor target_fd)
{
    duplicate(source_fd.value, target_fd.value);
}


std::optional<FdTable::PathReference>
FdTable::lookup(int fd) const noexcept {

        const auto it = entries_.find(fd);
        
        if (it == entries_.end())
            return std::nullopt;
        
        
        return std::cref(it->second);
    }

    bool FdTable::contains(int fd) const noexcept {
        return entries_.contains(fd);
    }

    bool FdTable::contains(FileDescriptor fd) const noexcept
    {
        return contains(fd.value);
    }
 
    void FdTable::close(int fd) noexcept {
        entries_.erase(fd);
    }

    void FdTable::close(FileDescriptor fd) noexcept
    {
        close(fd.value);
    }

    void FdTable::close_range(unsigned first, unsigned last) noexcept
    {
        for (auto it = entries_.begin(); it != entries_.end();) {
            const auto fd = static_cast<unsigned>(it->first);
            if (fd >= first && fd <= last) {
                it = entries_.erase(it);
            } else {
                ++it;
            }
        }
    }


   
} // namespace execell::trace
