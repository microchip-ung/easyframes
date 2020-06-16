#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ef.h"

static int tst_fill_defaults(struct frame *f, int stack_idx) {
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
    { .name = "padding",    // Padding
      .help = "",
      .bit_width =  20*8 },
};

static hdr_t HDR_MRP_TST = {
    .name = "mrp_tst",
    .help = "MRP Test frame",
    .type = 0x88E3,
    .fields = MRP_TST_FIELDS,
    .fields_size = sizeof(MRP_TST_FIELDS) / sizeof(MRP_TST_FIELDS[0]),
    .frame_fill_defaults = tst_fill_defaults,
    .parser = hdr_parse_fields,
};

static int topo_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t MRP_TOPO_FIELDS[] = {
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
    { .name = "t_interval",
      .help = "",
      .bit_width =  16 },
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
    { .name = "padding",    // Padding
      .help = "",
      .bit_width =  30*8 },
};

static hdr_t HDR_MRP_TOPO = {
    .name = "mrp_topo",
    .help = "MRP Topology Change frame",
    .type = 0x88E3,
    .fields = MRP_TOPO_FIELDS,
    .fields_size = sizeof(MRP_TOPO_FIELDS) / sizeof(MRP_TOPO_FIELDS[0]),
    .frame_fill_defaults = topo_fill_defaults,
    .parser = hdr_parse_fields,
};

static int lnk_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t MRP_LNK_FIELDS[] = {
    { .name = "version",
      .help = "",
      .bit_width =   16 },
    { .name = "t_type",     // MRP_Type TLV
      .help = "",
      .bit_width =  8 },
    { .name = "t_length",
      .help = "",
      .bit_width =  8 },
    { .name = "t_sa",
      .help = "",
      .bit_width =  48 },
    { .name = "t_role",
      .help = "",
      .bit_width =  16 },
    { .name = "t_interval",
      .help = "",
      .bit_width =  16 },
    { .name = "t_blocked",
      .help = "",
      .bit_width =  16 },
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
    { .name = "padding",    // Padding
      .help = "",
      .bit_width =  30*8 },
};

static hdr_t HDR_MRP_LNK = {
    .name = "mrp_lnk",
    .help = "MRP Link Change frame",
    .type = 0x88E3,
    .fields = MRP_LNK_FIELDS,
    .fields_size = sizeof(MRP_LNK_FIELDS) / sizeof(MRP_LNK_FIELDS[0]),
    .frame_fill_defaults = lnk_fill_defaults,
    .parser = hdr_parse_fields,
};

static int prop_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

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
    { .name = "padding",    // Padding
      .help = "",
      .bit_width =  40*8 },
};

static hdr_t HDR_MRP_PROP_NACK = {
    .name = "mrp_prop_nack",
    .help = "MRP Propagate/MgrNAck frame",
    .type = 0x88E3,
    .fields = MRP_PROP_NACK_FIELDS,
    .fields_size = sizeof(MRP_PROP_NACK_FIELDS) / sizeof(MRP_PROP_NACK_FIELDS[0]),
    .frame_fill_defaults = prop_fill_defaults,
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

    def_offset(&HDR_MRP_TOPO);
    def_val(&HDR_MRP_TOPO, "version", "1");
    def_val(&HDR_MRP_TOPO, "t_type", "3");
    def_val(&HDR_MRP_TOPO, "t_length", "12");
    def_val(&HDR_MRP_TOPO, "c_type", "1");
    def_val(&HDR_MRP_TOPO, "c_length", "18");
    def_val(&HDR_MRP_TOPO, "e_type", "0");
    def_val(&HDR_MRP_TOPO, "e_length", "0");

    def_offset(&HDR_MRP_LNK);
    def_val(&HDR_MRP_LNK, "version", "1");
    def_val(&HDR_MRP_LNK, "t_type", "4");       // Default value is 4 (LinkDown) - Must be 5 to be LinkUp
    def_val(&HDR_MRP_LNK, "t_length", "12");
    def_val(&HDR_MRP_LNK, "c_type", "1");
    def_val(&HDR_MRP_LNK, "c_length", "18");
    def_val(&HDR_MRP_LNK, "e_type", "0");
    def_val(&HDR_MRP_LNK, "e_length", "0");

    def_offset(&HDR_MRP_PROP_NACK);
    def_val(&HDR_MRP_PROP_NACK, "version", "1");
    def_val(&HDR_MRP_PROP_NACK, "t_type", "127");
    def_val(&HDR_MRP_PROP_NACK, "t_length", "24");
    def_val(&HDR_MRP_PROP_NACK, "t_s_type", "2");    // Default value is 2 (PROP) - Must be 1 to be NACK
    def_val(&HDR_MRP_PROP_NACK, "t_s_length", "16");
    def_val(&HDR_MRP_PROP_NACK, "c_type", "1");
    def_val(&HDR_MRP_PROP_NACK, "c_length", "18");
    def_val(&HDR_MRP_PROP_NACK, "e_type", "0");
    def_val(&HDR_MRP_PROP_NACK, "e_length", "0");

    hdr_tmpls[HDR_TMPL_MRP_TST] =        &HDR_MRP_TST;
    hdr_tmpls[HDR_TMPL_MRP_TOPO] =       &HDR_MRP_TOPO;
    hdr_tmpls[HDR_TMPL_MRP_LNK] =        &HDR_MRP_LNK;
    hdr_tmpls[HDR_TMPL_MRP_PROP_NACK] =  &HDR_MRP_PROP_NACK;
}

void mrp_uninit() {
    uninit_frame_data(&HDR_MRP_TST);
    uninit_frame_data(&HDR_MRP_TOPO);
    uninit_frame_data(&HDR_MRP_LNK);
    uninit_frame_data(&HDR_MRP_PROP_NACK);

    hdr_tmpls[HDR_TMPL_MRP_TST] = 0;
    hdr_tmpls[HDR_TMPL_MRP_TOPO] = 0;
    hdr_tmpls[HDR_TMPL_MRP_LNK] = 0;
    hdr_tmpls[HDR_TMPL_MRP_PROP_NACK] = 0;
}
