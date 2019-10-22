#include "ef.h"

static int payload_parser(frame_t *frame, hdr_t *hdr, int offset,
                          int argc, const char *argv[]) {
    int res;
    buf_t *b = 0;

    res = parse_var_bytes(&b, argc, argv);
    if (res <= 0) {
        bfree(b);
        return res;
    }

    hdr->size = b->size;
    hdr->fields[0].bit_width = b->size * 8;
    hdr->fields[0].val = b;

    return res;
}

static field_t PAYLOAD_FIELDS[] = {
    { .name = "hex",
      .help = "Variable length data",
      .bit_width = 0 },
};

static hdr_t HDR_PAYLOAD = {
    .name = "data",
    .help = "Generic payload data",
    .fields = PAYLOAD_FIELDS,
    .fields_size = sizeof(PAYLOAD_FIELDS) / sizeof(PAYLOAD_FIELDS[0]),
    .parser = payload_parser,
};

void payload_init() {
    def_offset(&HDR_PAYLOAD);

    hdr_tmpls[HDR_TMPL_PAYLOAD] = &HDR_PAYLOAD;
}

void payload_uninit() {
    uninit_frame_data(&HDR_PAYLOAD);
    hdr_tmpls[HDR_TMPL_PAYLOAD] = 0;
}

