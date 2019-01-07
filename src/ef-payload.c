#include "ef.h"

field_t PAYLOAD_FIELDS[] = {
    { .name = "hex", .bit_width = 64 },
};

hdr_t HDR_PAYLOAD = {
    .name = "payload",
    .fields = PAYLOAD_FIELDS,
    .fields_size = sizeof(PAYLOAD_FIELDS) / sizeof(PAYLOAD_FIELDS[0]),
};

void payload_init() __attribute__ ((constructor));
void payload_uninit() __attribute__ ((destructor));

void payload_init() {
    def_offset(&HDR_PAYLOAD);
}

void payload_uninit() {
    uninit_frame_data(&HDR_PAYLOAD);
}
