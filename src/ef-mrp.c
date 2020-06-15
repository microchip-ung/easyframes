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
    { .name = "padding",
      .help = "",
      .bit_width =  20*8 },
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

static field_t MRP_PROP_NACK_FIELDS[] = {
    { .name = "version",
      .help = "",
      .bit_width =   16 },
    { .name = "t_type",         // MRP_Type TLV
      .help = "",
      .bit_width =  8 },
    { .name = "t_length",
      .help = "",
      .bit_width =  8 },
    { .name = "t_qui",
      .help = "",
      .bit_width =  24 },
    { .name = "t_sub1_type",    //MRP_SubOption1
      .help = "",
      .bit_width =  8 },
    { .name = "t_sub1_man",
      .help = "",
      .bit_width =  16 },
    { .name = "t_s_type",       // MRP_SubType TLV
      .help = "",
      .bit_width =  8 },
    { .name = "t_s_length",
      .help = "",
      .bit_width =  8 },
    { .name = "t_s_prio",
      .help = "",
      .bit_width =  16 },
    { .name = "t_s_sa",
      .help = "",
      .bit_width =  48 },
    { .name = "t_s_oprio",
      .help = "",
      .bit_width =  16 },
    { .name = "t_s_osa",
      .help = "",
      .bit_width =  48 },
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
    { .name = "padding",
      .help = "",
      .bit_width =  40*8 },
};

static hdr_t HDR_MRP_PROP = {
    .name = "mrp_prop",
    .help = "MRP Propagate frame",
    .type = 0x88E3,
    .fields = MRP_PROP_NACK_FIELDS,
    .fields_size = sizeof(MRP_PROP_NACK_FIELDS) / sizeof(MRP_PROP_NACK_FIELDS[0]),
    .frame_fill_defaults = mrp_fill_defaults,
    .parser = hdr_parse_fields,
};

static hdr_t HDR_MRP_NACK = {
    .name = "mrp_nack",
    .help = "MRP MgrNAck frame",
    .type = 0x88E3,
    .fields = MRP_PROP_NACK_FIELDS,
    .fields_size = sizeof(MRP_PROP_NACK_FIELDS) / sizeof(MRP_PROP_NACK_FIELDS[0]),
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

    def_offset(&HDR_MRP_PROP);
    def_val(&HDR_MRP_PROP, "version", "1");
    def_val(&HDR_MRP_PROP, "t_type", "127");
    def_val(&HDR_MRP_PROP, "t_length", "24");
    def_val(&HDR_MRP_PROP, "t_s_type", "2");
    def_val(&HDR_MRP_PROP, "t_s_length", "16");
    def_val(&HDR_MRP_PROP, "c_type", "1");
    def_val(&HDR_MRP_PROP, "c_length", "18");
    def_val(&HDR_MRP_PROP, "e_type", "0");
    def_val(&HDR_MRP_PROP, "e_length", "0");

    def_offset(&HDR_MRP_NACK);
    def_val(&HDR_MRP_NACK, "version", "1");
    def_val(&HDR_MRP_NACK, "t_type", "127");
    def_val(&HDR_MRP_NACK, "t_length", "24");
    def_val(&HDR_MRP_NACK, "t_s_type", "1");
    def_val(&HDR_MRP_NACK, "t_s_length", "16");
    def_val(&HDR_MRP_NACK, "c_type", "1");
    def_val(&HDR_MRP_NACK, "c_length", "18");
    def_val(&HDR_MRP_NACK, "e_type", "0");
    def_val(&HDR_MRP_NACK, "e_length", "0");

    hdr_tmpls[HDR_TMPL_MRP_TST] =  &HDR_MRP_TST;
    hdr_tmpls[HDR_TMPL_MRP_PROP] =  &HDR_MRP_PROP;
    hdr_tmpls[HDR_TMPL_MRP_NACK] =  &HDR_MRP_NACK;
}

void mrp_uninit() {
    uninit_frame_data(&HDR_MRP_TST);

    hdr_tmpls[HDR_TMPL_MRP_TST] = 0;
}
