#include "ef.h"

static int vlan_fill_defaults(struct frame *f, int stack_idx) {
    return ether_type_fill_defaults(f, stack_idx);
}

field_t STAG_FIELDS[] = {
    { .name = "pcp",
      .help = "Priority Code Point",
      .bit_width =   3 },
    { .name = "dei",
      .help = "Drop Elegible Indicator",
      .bit_width =   1 },
    { .name = "vid",
      .help = "VLAN Identifier",
      .bit_width =  12 },
    { .name = "et",
      .help = "Tag Protocol Identifier",
      .bit_width =  16 },
};

hdr_t HDR_STAG = {
    .name = "stag",
    .help = "Service VLAN Tag",
    .type = 0x88A8,
    .fields = STAG_FIELDS,
    .fields_size = sizeof(STAG_FIELDS) / sizeof(STAG_FIELDS[0]),
    .frame_fill_defaults = vlan_fill_defaults,
    .parser = hdr_parse_fields,
};

field_t CTAG_FIELDS[] = {
    { .name = "pcp",
      .help = "Priority Code Point",
      .bit_width =   3 },
    { .name = "dei",
      .help = "Drop Elegible Indicator",
      .bit_width =   1 },
    { .name = "vid",
      .help = "VLAN Identifier",
      .bit_width =  12 },
    { .name = "et",
      .help = "Tag Protocol Identifier",
      .bit_width =  16 },
};

hdr_t HDR_CTAG = {
    .name = "ctag",
    .help = "Customer VLAN Tag",
    .type = 0x8100,
    .fields = CTAG_FIELDS,
    .fields_size = sizeof(CTAG_FIELDS) / sizeof(CTAG_FIELDS[0]),
    .frame_fill_defaults = vlan_fill_defaults,
    .parser = hdr_parse_fields,
};

void vlan_init() {
    def_offset(&HDR_STAG);
    def_offset(&HDR_CTAG);

    hdr_tmpls[HDR_TMPL_STAG] = &HDR_STAG;
    hdr_tmpls[HDR_TMPL_CTAG] = &HDR_CTAG;
}

void vlan_uninit() {
    uninit_frame_data(&HDR_STAG);
    uninit_frame_data(&HDR_CTAG);

    hdr_tmpls[HDR_TMPL_STAG] = 0;
    hdr_tmpls[HDR_TMPL_CTAG] = 0;
}
