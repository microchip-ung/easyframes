#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ef.h"

static int ccm_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t CCM_FIELDS[] = {
    { .name = "mel",
      .help = "",
      .bit_width =   3 },
    { .name = "version",
      .help = "",
      .bit_width =   5 },
    { .name = "opcode",
      .help = "",
      .bit_width =  8 },
    { .name = "rdi",
      .help = "",
      .bit_width =  1 },
    { .name = "reserved",
      .help = "",
      .bit_width =  4 },
    { .name = "period",
      .help = "",
      .bit_width =  3 },
    { .name = "tlv_off",
      .help = "",
      .bit_width =  8 },
    { .name = "seq_num",
      .help = "",
      .bit_width =  32 },
    { .name = "mep_id",
      .help = "",
      .bit_width =  16 },
    { .name = "meg_id",
      .help = "",
      .parser = parse_field_hex,
      .bit_width =  (48*8) },
    { .name = "txfcf",
      .help = "",
      .bit_width =  32 },
    { .name = "rxfcb",
      .help = "",
      .bit_width =  32 },
    { .name = "txfcb",
      .help = "",
      .bit_width =  32 },
    { .name = "reserved",
      .help = "",
      .bit_width =  32 },
    { .name = "end_tlv",
      .help = "",
      .bit_width =  8 },
    { .name = "tlv_length",
      .help = "",
      .bit_width =  16 },
    { .name = "tlv_value",
      .help = "",
      .bit_width =  8 },
};

static hdr_t HDR_CCM = {
    .name = "oam-ccm",
    .help = "OAM-CCM frame",
    .type = 0x8902,
    .fields = CCM_FIELDS,
    .fields_size = sizeof(CCM_FIELDS) / sizeof(CCM_FIELDS[0]),
    .frame_fill_defaults = ccm_fill_defaults,
    .parser = hdr_parse_fields,
};

static int laps_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t LAPS_FIELDS[] = {
    { .name = "mel",
      .help = "",
      .bit_width =   3 },
    { .name = "version",
      .help = "",
      .bit_width =   5 },
    { .name = "opcode",
      .help = "",
      .bit_width =  8 },
    { .name = "flags",
      .help = "",
      .bit_width =  8 },
    { .name = "tlv_off",
      .help = "",
      .bit_width =  8 },
    { .name = "req_sta",
      .help = "",
      .bit_width =  4 },
    { .name = "prot_type",
      .help = "",
      .bit_width =  4 },
    { .name = "request_sig",
      .help = "",
      .bit_width =  8 },
    { .name = "bridge_sig",
      .help = "",
      .bit_width =  8 },
    { .name = "t",
      .help = "",
      .bit_width =  1 },
    { .name = "reserved",
      .help = "",
      .bit_width =  7 },
    { .name = "padding",
      .help = "",
      .bit_width =  50*8 },
};

static hdr_t HDR_LAPS = {
    .name = "oam-laps",
    .help = "OAM-LAPS frame",
    .type = 0x8902,
    .fields = LAPS_FIELDS,
    .fields_size = sizeof(LAPS_FIELDS) / sizeof(LAPS_FIELDS[0]),
    .frame_fill_defaults = laps_fill_defaults,
    .parser = hdr_parse_fields,
};

static int lb_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t LB_FIELDS[] = {
    { .name = "mel",
      .help = "",
      .bit_width =   3 },
    { .name = "version",
      .help = "",
      .bit_width =   5 },
    { .name = "opcode",
      .help = "",
      .bit_width =  8 },
    { .name = "flags",
      .help = "",
      .bit_width =  8 },
    { .name = "tlv_off",
      .help = "",
      .bit_width =  8 },
    { .name = "trans_id",
      .help = "",
      .bit_width =  32 },
    { .name = "type",
      .help = "",
      .bit_width =  8 },
    { .name = "tlv_length",
      .help = "",
      .bit_width =  16 },
    { .name = "pattern_type",
      .help = "",
      .bit_width =  8 },
    { .name = "pattern",
      .help = "",
      .bit_width =  7*8 },
    { .name = "crc32",
      .help = "",
      .bit_width =  32 },
    { .name = "padding",
      .help = "",
      .bit_width =  50*8 },
};

static hdr_t HDR_LB = {
    .name = "oam-lb",
    .help = "OAM-LB frame",
    .type = 0x8902,
    .fields = LB_FIELDS,
    .fields_size = sizeof(LB_FIELDS) / sizeof(LB_FIELDS[0]),
    .frame_fill_defaults = lb_fill_defaults,
    .parser = hdr_parse_fields,
};

static int lt_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t LT_FIELDS[] = {
    { .name = "mel",
      .help = "",
      .bit_width =   3 },
    { .name = "version",
      .help = "",
      .bit_width =   5 },
    { .name = "opcode",
      .help = "",
      .bit_width =  8 },
    { .name = "flags",
      .help = "",
      .bit_width =  8 },
    { .name = "tlv_off",
      .help = "",
      .bit_width =  8 },
    { .name = "trans_id",
      .help = "",
      .bit_width =  32 },
    { .name = "padding",
      .help = "",
      .bit_width =  60*8 },
};

static hdr_t HDR_LT = {
    .name = "oam-lt",
    .help = "OAM-LT frame",
    .type = 0x8902,
    .fields = LT_FIELDS,
    .fields_size = sizeof(LT_FIELDS) / sizeof(LT_FIELDS[0]),
    .frame_fill_defaults = lt_fill_defaults,
    .parser = hdr_parse_fields,
};

static int raps_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t RAPS_FIELDS[] = {
    { .name = "mel",
      .help = "",
      .bit_width =   3 },
    { .name = "version",
      .help = "",
      .bit_width =   5 },
    { .name = "opcode",
      .help = "",
      .bit_width =  8 },
    { .name = "flags",
      .help = "",
      .bit_width =  8 },
    { .name = "tlv_off",
      .help = "",
      .bit_width =  8 },
    { .name = "req_sta",
      .help = "",
      .bit_width =  4 },
    { .name = "sub_code",
      .help = "",
      .bit_width =  4 },
    { .name = "status",
      .help = "",
      .bit_width =  8 },
    { .name = "node_id",
      .help = "",
      .bit_width =  6*8 },
    { .name = "reserved",
      .help = "",
      .bit_width =  24*8 },
    { .name = "padding",
      .help = "",
      .bit_width =  30*8 },
};

static hdr_t HDR_RAPS = {
    .name = "oam-raps",
    .help = "OAM-RAPS frame",
    .type = 0x8902,
    .fields = RAPS_FIELDS,
    .fields_size = sizeof(RAPS_FIELDS) / sizeof(RAPS_FIELDS[0]),
    .frame_fill_defaults = raps_fill_defaults,
    .parser = hdr_parse_fields,
};

void oam_init() {
    def_offset(&HDR_CCM);
    def_val(&HDR_CCM, "version", "0");
    def_val(&HDR_CCM, "opcode", "1");
    def_val(&HDR_CCM, "tlv_off", "70");
    def_val(&HDR_CCM, "rdi", "0");
    def_val(&HDR_CCM, "reserved", "0");
    def_val(&HDR_CCM, "seq_num", "0");

    def_offset(&HDR_LAPS);
    def_val(&HDR_LAPS, "version", "0");
    def_val(&HDR_LAPS, "opcode", "39");
    def_val(&HDR_LAPS, "tlv_off", "4");

    def_offset(&HDR_LB);
    def_val(&HDR_LB, "version", "0");
    def_val(&HDR_LB, "tlv_off", "4");
    def_val(&HDR_LB, "type", "0");
    def_val(&HDR_LB, "tlv_length", "0");

    def_offset(&HDR_LT);
    def_val(&HDR_LT, "version", "0");

    def_offset(&HDR_RAPS);
    def_val(&HDR_RAPS, "version", "1");
    def_val(&HDR_RAPS, "opcode", "40");
    def_val(&HDR_RAPS, "tlv_off", "32");

    hdr_tmpls[HDR_TMPL_OAM_CCM] =  &HDR_CCM;
    hdr_tmpls[HDR_TMPL_OAM_LAPS] = &HDR_LAPS;
    hdr_tmpls[HDR_TMPL_OAM_LB] = &HDR_LB;
    hdr_tmpls[HDR_TMPL_OAM_LT] = &HDR_LT;
    hdr_tmpls[HDR_TMPL_OAM_RAPS] = &HDR_RAPS;
}

void oam_uninit() {
    uninit_frame_data(&HDR_CCM);
    uninit_frame_data(&HDR_LAPS);

    hdr_tmpls[HDR_TMPL_OAM_CCM] = 0;
    hdr_tmpls[HDR_TMPL_OAM_LAPS] = 0;
    hdr_tmpls[HDR_TMPL_OAM_LB] = 0;
    hdr_tmpls[HDR_TMPL_OAM_LT] = 0;
}
