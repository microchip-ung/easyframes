#include "ef.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0)
        dup2(devnull, 1);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s;
    buf_t *b;
    int bytes;

    /* parse_bytes expects a null-terminated string */
    if (size < 1 || size > 256)
        return 0;

    s = (char *)malloc(size + 1);
    if (!s)
        return 0;

    memcpy(s, data, size);
    s[size] = '\0';

    /* Try several output sizes, exercises different code paths */
    for (bytes = 1; bytes <= 16; bytes <<= 1) {
        b = parse_bytes(s, bytes);
        if (b)
            bfree(b);
    }

    free(s);
    return 0;
}
