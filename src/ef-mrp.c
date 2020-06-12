#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ef.h"

static int mrp_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t MRP_TST_FIELDS[] = {
    { .name = "version",
      .help = "",
      .bit_width =   16 },
    { .name = "t_type",     // MRP_Type TLV
      .help = "",
      .bit_width =  8 },
    { .name = "t_length",
      .help = "",
      .bit_width =  8 },
    { .name = "t_prio",
      .help = "",
      .bit_width =  16 },
    { .name = "t_sa",
      .help = "",
      .bit_width =  48 },
    { .name = "t_role",
      .help = "",
      .bit_width =  16 },
    { .name = "t_state",
      .help = "",
      .bit_width =  16 },
    { .name = "t_trans",
      .help = "",
      .bit_width =  16 },
    { .name = "t_ts",
      .help = "",
      .bit_width =  32 },
    { .name = "c_type",     // MRP_Common TLV
      .help = "",
      .bit_width =  8 },
    { .name = "c_length",
      .help = "",
      .bit_width =  8 },
    { .name = "c_seq_num",
      .help = "",
      .bit_width =  16 },
    { .name = "c_domain",
      .help = "",
      .bit_width =  128 },
    { .name = "e_type",     // MRP_End TLV
      .help = "",
      .bit_width =  8 },
    { .name = "e_length",
      .help = "",
      .bit_width =  8 },
};

static hdr_t HDR_MRP_TST = {
    .name = "mrp_tst",
    .help = "MRP TST frame",
    .type = 0x88E3,
    .fields = MRP_TST_FIELDS,
    .fields_size = sizeof(MRP_TST_FIELDS) / sizeof(MRP_TST_FIELDS[0]),
    .frame_fill_defaults = mrp_fill_defaults,
    .parser = hdr_parse_fields,
};

void mrp_init() {
    def_offset(&HDR_MRP_TST);
    def_val(&HDR_MRP_TST, "version", "1");
    def_val(&HDR_MRP_TST, "t_type", "2");
    def_val(&HDR_MRP_TST, "t_length", "21");
    def_val(&HDR_MRP_TST, "c_type", "1");
    def_val(&HDR_MRP_TST, "c_length", "18");
    def_val(&HDR_MRP_TST, "e_type", "0");
    def_val(&HDR_MRP_TST, "e_length", "0");

    hdr_tmpls[HDR_TMPL_MRP_TST] =  &HDR_MRP_TST;
}

void mrp_uninit() {
    uninit_frame_data(&HDR_MRP_TST);

    hdr_tmpls[HDR_TMPL_MRP_TST] = 0;
}
