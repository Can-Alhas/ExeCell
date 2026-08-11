#include <unistd.h>

int main()
{
    ::execl("/bin/true", "true", static_cast<char*>(nullptr));
    return 127;
}
