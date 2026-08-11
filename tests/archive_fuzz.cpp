#include <execell/package/archive.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view input{reinterpret_cast<const char*>(data), size};
    (void)execell::package::archive_adapter::validate_path(input);
    (void)execell::package::archive_adapter::validate_link_target(input);
    return 0;
}
