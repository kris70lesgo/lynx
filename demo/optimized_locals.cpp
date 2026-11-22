#include <stddef.h>
#include <string.h>

// Keep this function out of line so MSVC emits a distinct PDB procedure.
__declspec(noinline)
int copy_prefix(char *destination, const char *source, size_t capacity)
{
    size_t cchDest = strlen(source);
    if (capacity == 0)
        return -1;
    if (cchDest >= capacity)
        cchDest = capacity - 1;

    memcpy(destination, source, cchDest);
    destination[cchDest] = '\0';
    return static_cast<int>(cchDest);
}

int main()
{
    char destination[16] = {};
    return copy_prefix(destination, "lynx-demo", sizeof(destination));
}
