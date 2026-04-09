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
 * Property-based fuzz test: a frame must always match its own receive
 * filter.  Given a fuzz-generated argv (frame spec), we:
 *
 *   1. Parse it into a frame via argc_frame()
 *   2. Serialize to bytes via frame_to_buf()
 *   3. Build the mask via frame_mask_to_buf() (if the frame has ign fields)
 *   4. Assert bequal_mask(buf, buf, mask, padding_len) == 1
 *
 * If this invariant is violated, the fuzzer reports it as a crash,
 * meaning either serialization or matching has a bug.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const char *argv[64];
    int argc = 0;
    char *input;
    frame_t *f;
    buf_t *buf, *mask;
    int res, matched;

    if (size < 1 || size > 4096)
        return 0;

    /* Work on a mutable, null-terminated copy */
    input = (char *)malloc(size + 1);
    if (!input)
        return 0;

    memcpy(input, data, size);
    input[size] = '\0';

    /* Split on null bytes into argv */
    argv[argc++] = input;
    for (size_t i = 0; i < size && argc < 63; i++) {
        if (input[i] == '\0') {
            argv[argc++] = input + i + 1;
        }
    }

    /* Parse the frame spec */
    f = frame_alloc();
    if (!f) {
        free(input);
        return 0;
    }

    res = argc_frame(argc, argv, f);
    if (res <= 0) {
        frame_free(f);
        free(input);
        return 0;
    }

    /* Serialize frame to bytes, returns NULL on invalid combinations */
    buf = frame_to_buf(f);
    if (!buf) {
        frame_free(f);
        free(input);
        return 0;
    }

    /* Build mask (NULL if no ign fields, bequal_mask handles that) */
    mask = f->has_mask ? frame_mask_to_buf(f) : NULL;

    /*
     * For padded frames, construct a synthetic RX frame: the serialized
     * frame data plus padding_len zero bytes appended.  This simulates
     * what a real receiver would see, the expected frame with extra
     * trailing bytes from the wire.
     */
    if (f->padding_len < 0) {
        /*
         * Negative padding (e.g. integer overflow from "padding 0xdeadbeef").
         * bequal_mask correctly rejects this, not a bug, skip.
         */
        if (mask) bfree(mask);
        bfree(buf);
        frame_free(f);
        free(input);
        return 0;
    }

    if (f->padding_len > 0) {
        /*
         * Construct a synthetic RX frame: the serialized frame data plus
         * padding_len zero bytes.  This simulates what a real receiver
         * would see, the expected frame with extra trailing bytes.
         */
        buf_t *rx = balloc(buf->size + f->padding_len);
        if (!rx) {
            if (mask) bfree(mask);
            bfree(buf);
            frame_free(f);
            free(input);
            return 0;
        }
        memcpy(rx->data, buf->data, buf->size);
        memset(rx->data + buf->size, 0, f->padding_len);
        matched = bequal_mask(rx, buf, mask, f->padding_len);
        bfree(rx);
    } else {
        matched = bequal_mask(buf, buf, mask, 0);
    }

    if (!matched) {
        /* Invariant violated, abort so the fuzzer captures this input */
        abort();
    }

    if (mask)
        bfree(mask);
    bfree(buf);
    frame_free(f);
    free(input);
    return 0;
}
