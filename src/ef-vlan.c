#include "ef.h"

static int vlan_fill_defaults(struct frame *f, int stack_idx) {
    return ether_type_fill_defaults(f, stack_idx);
}

field_t STAG_FIELDS[] = {
    { .name = "pcp",  .bit_width =   3 },
    { .name = "dei",  .bit_width =   1 },
    { .name = "vid",  .bit_width =  12 },
    { .name = "et",   .bit_width =  16 },
};

hdr_t HDR_STAG = {
    .name = "stag",
    .type = 0x88A8,
    .fields = STAG_FIELDS,
    .fields_size = sizeof(STAG_FIELDS) / sizeof(STAG_FIELDS[0]),
    .frame_fill_defaults = vlan_fill_defaults,
};

field_t CTAG_FIELDS[] = {
    { .name = "pcp",  .bit_width =   3 },
    { .name = "dei",  .bit_width =   1 },
    { .name = "vid",  .bit_width =  12 },
    { .name = "et",   .bit_width =  16 },
};

hdr_t HDR_CTAG = {
    .name = "ctag",
    .type = 0x8100,
    .fields = CTAG_FIELDS,
    .fields_size = sizeof(CTAG_FIELDS) / sizeof(CTAG_FIELDS[0]),
    .frame_fill_defaults = vlan_fill_defaults,
};

void vlan_init() __attribute__ ((constructor));
void vlan_uninit() __attribute__ ((destructor));

void vlan_init() {
    def_offset(&HDR_STAG);
    def_offset(&HDR_CTAG);
}

void vlan_uninit() {
    uninit_frame_data(&HDR_STAG);
    uninit_frame_data(&HDR_CTAG);
}
