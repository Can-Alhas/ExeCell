#include <cstdio>

int main()
{
    for (int index = 0; index < 10000; ++index) std::fputs("output-limit-fixture\n", stdout);
    return 0;
}
