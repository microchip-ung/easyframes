#include "ef.h"

static int padding_parser(frame_t *f, hdr_t *hdr, int argc, const char *argv[]) {
    uint32_t len = 0;


    if (argc <= 0)
        return -1;

    if (parse_uint32(argv[0], &len) != 0) {
        return -1;
    }

    f->padding_len = len;

    return 1;
}

static hdr_t HDR_PADDING = {
    .name = "padding",
    .help = "Ignore padding",
    .parser = padding_parser,
};

void padding_init() {
    hdr_tmpls[HDR_TMPL_PADDING] = &HDR_PADDING;
}

void padding_uninit() {
    hdr_tmpls[HDR_TMPL_PADDING] = 0;
}

