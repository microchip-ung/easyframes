#include "ef.h"

static int vlan_fill_defaults(struct frame *f, int stack_idx) {
    return ether_type_fill_defaults(f, stack_idx);
}

static field_t STAG_FIELDS[] = {
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

static hdr_t HDR_STAG = {
    .name = "stag",
    .help = "Service VLAN Tag",
    .type = 0x88A8,
    .fields = STAG_FIELDS,
    .fields_size = sizeof(STAG_FIELDS) / sizeof(STAG_FIELDS[0]),
    .frame_fill_defaults = vlan_fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t CTAG_FIELDS[] = {
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

static hdr_t HDR_CTAG = {
    .name = "ctag",
    .help = "Customer VLAN Tag",
    .type = 0x8100,
    .fields = CTAG_FIELDS,
    .fields_size = sizeof(CTAG_FIELDS) / sizeof(CTAG_FIELDS[0]),
    .frame_fill_defaults = vlan_fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t RTAG_FIELDS[] = {
    { .name = "recv",
      .help = "Reserved",
      .bit_width =  16 },
    { .name = "seqn",
      .help = "Sequence Number",
      .bit_width =  16 },
    { .name = "et",
      .help = "EtherType",
      .bit_width =  16 },
};

static hdr_t HDR_RTAG = {
    .name = "rtag",
    .help = "Redundancy Tag",
    .type = 0xF1C1,
    .fields = RTAG_FIELDS,
    .fields_size = sizeof(RTAG_FIELDS) / sizeof(RTAG_FIELDS[0]),
    .frame_fill_defaults = vlan_fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t PRP_RCT_FIELDS[] = {
    { .name = "seqn",
      .help = "Sequence Number",
      .bit_width = 16 },
    { .name = "lanid",
      .help = "LAN ID",
      .bit_width =  4 },
    { .name = "size",
      .help = "LSDU size",
      .bit_width = 12 },
    { .name = "suffix",
      .help = "PRP suffix",
      .bit_width = 16 },
};

static hdr_t HDR_PRP_RCT = {
    .name = "prp",
    .help = "PRP Redundancy Check Trailer",
    .type = 0,
    .fields = PRP_RCT_FIELDS,
    .fields_size = sizeof(PRP_RCT_FIELDS) / sizeof(PRP_RCT_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t HSR_TAG_FIELDS[] = {
    { .name = "pathid",
      .help = "Path ID",
      .bit_width =  4 },
    { .name = "size",
      .help = "LSDU size",
      .bit_width = 12 },
    { .name = "seqn",
      .help = "Sequence Number",
      .bit_width = 16 },
    { .name = "et",
      .help = "EtherType",
      .bit_width = 16 },
};

static hdr_t HDR_HSR_TAG = {
    .name = "htag",
    .help = "HSR Tag",
    .type = 0x892f,
    .fields = HSR_TAG_FIELDS,
    .fields_size = sizeof(HSR_TAG_FIELDS) / sizeof(HSR_TAG_FIELDS[0]),
    .frame_fill_defaults = vlan_fill_defaults,
    .parser = hdr_parse_fields,
};

void vlan_init() {
    def_offset(&HDR_STAG);
    def_offset(&HDR_CTAG);
    def_offset(&HDR_RTAG);
    def_offset(&HDR_PRP_RCT);
    def_offset(&HDR_HSR_TAG);
    def_val(&HDR_PRP_RCT, "suffix", "0x88fb");

    hdr_tmpls[HDR_TMPL_STAG] = &HDR_STAG;
    hdr_tmpls[HDR_TMPL_CTAG] = &HDR_CTAG;
    hdr_tmpls[HDR_TMPL_RTAG] = &HDR_RTAG;
    hdr_tmpls[HDR_TMPL_PRP_RCT] = &HDR_PRP_RCT;
    hdr_tmpls[HDR_TMPL_HSR_TAG] = &HDR_HSR_TAG;
}

void vlan_uninit() {
    uninit_frame_data(&HDR_STAG);
    uninit_frame_data(&HDR_CTAG);
    uninit_frame_data(&HDR_RTAG);
    uninit_frame_data(&HDR_PRP_RCT);
    uninit_frame_data(&HDR_HSR_TAG);

    hdr_tmpls[HDR_TMPL_STAG] = 0;
    hdr_tmpls[HDR_TMPL_CTAG] = 0;
    hdr_tmpls[HDR_TMPL_RTAG] = 0;
    hdr_tmpls[HDR_TMPL_PRP_RCT] = 0;
    hdr_tmpls[HDR_TMPL_HSR_TAG] = 0;
}
