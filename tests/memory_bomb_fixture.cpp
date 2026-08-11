#include <cstdlib>
#include <cstring>

int main()
{
    constexpr std::size_t size = 64U * 1024U * 1024U;
    void* memory = std::malloc(size);
    if (memory == nullptr) {
        return 1;
    }
    std::memset(memory, 0xA5, size);
    std::free(memory);
    return 0;
}
