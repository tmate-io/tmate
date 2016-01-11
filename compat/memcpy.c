// http://stackoverflow.com/questions/8823267/linking-against-older-symbol-version-in-a-so-file

#include <string.h>

/* some systems do not have newest memcpy@@GLIBC_2.14 - stay with old good one */
asm (".symver memcpy, memcpy@GLIBC_2.2.5");

void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}
