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

/*
 * Split fuzz input on null bytes to build an argv array, then feed it
 * to argc_frame.  This exercises all header and field parsers.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const char *argv[64];
    int argc = 0;
    char *buf;
    frame_t *f;

    if (size < 1 || size > 4096)
        return 0;

    /* Work on a mutable copy, ensure it's null-terminated */
    buf = (char *)malloc(size + 1);
    if (!buf)
        return 0;

    memcpy(buf, data, size);
    buf[size] = '\0';

    /* Split on null bytes into argv */
    argv[argc++] = buf;
    for (size_t i = 0; i < size && argc < 63; i++) {
        if (buf[i] == '\0') {
            argv[argc++] = buf + i + 1;
        }
    }

    f = frame_alloc();
    if (f) {
        argc_frame(argc, argv, f);
        frame_free(f);
    }

    free(buf);
    return 0;
}
