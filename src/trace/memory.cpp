#include <execell/trace/memory.hpp>

#include <cerrno>

#include <sys/ptrace.h>

namespace execell::trace {

MemoryRead read_process_memory_string(pid_t pid, unsigned long address)
{
    constexpr std::size_t word_size = sizeof(long);
    constexpr std::size_t max_string_size = 4096;

    MemoryRead result;
    result.value.reserve(128);

    while (result.value.size() < max_string_size) {
        errno = 0;
        const long data = ::ptrace(
            PTRACE_PEEKDATA,
            pid,
            address + result.value.size(),
            nullptr);
        if (data == -1 && errno != 0) {
            result.status = MemoryReadStatus::invalid_address;
            result.bytes = result.value.size();
            return result;
        }

        const auto* bytes = reinterpret_cast<const char*>(&data);
        for (std::size_t index = 0; index < word_size; ++index) {
            if (bytes[index] == '\0') {
                result.bytes = result.value.size();
                return result;
            }
            result.value.push_back(bytes[index]);
            if (result.value.size() >= max_string_size) {
                result.status = MemoryReadStatus::truncated;
                result.bytes = result.value.size();
                return result;
            }
        }
    }

    result.status = MemoryReadStatus::truncated;
    result.bytes = result.value.size();
    return result;
}

std::string read_process_string_value(pid_t pid, unsigned long address)
{
    return read_process_memory_string(pid, address).value;
}

} // namespace execell::trace
