#include "ef.h"

field_t PAYLOAD_FIELDS[] = {
    { .name = "hex",
      .help = "64 bit data",
      .bit_width = 64 },
};

hdr_t HDR_PAYLOAD = {
    .name = "payload",
    .help = "Generic payload data",
    .fields = PAYLOAD_FIELDS,
    .fields_size = sizeof(PAYLOAD_FIELDS) / sizeof(PAYLOAD_FIELDS[0]),
};

void payload_init() {
    def_offset(&HDR_PAYLOAD);

    hdr_tmpls[HDR_TMPL_PAYLOAD] = &HDR_PAYLOAD;
}

void payload_uninit() {
    uninit_frame_data(&HDR_PAYLOAD);
    hdr_tmpls[HDR_TMPL_PAYLOAD] = 0;
}
