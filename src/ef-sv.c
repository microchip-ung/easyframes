#include <arpa/inet.h> /* For htonl() */
#include <stdio.h>
#include "ef.h"

// This file provides handles to create PRP and HSR Supervision frames.
// PRP and HSR and the accompanying supervision frames are defined in the
// IEC 62439-3 standard.

static int sv_fill_defaults(struct frame *f, int stack_idx) {
    int        found = 0;
    size_t     i;
    hdr_t      *h = f->stack[stack_idx];
    field_t    *fld;
    const char *tlv2_fields[]  = {"tlv2_type", "tlv2_len", "tlv2_mac"};

    // If none of the tlv2_fields are present, we adjust the size to 8 bytes
    // less.
    for (i = 0; i < sizeof(tlv2_fields) / sizeof(tlv2_fields[0]); i++) {
        fld = find_field(h, tlv2_fields[i]);
        if (fld->val) {
            found = 1;
            break;
        }
    }

    if (!found) {
        h->size -= 8; // Bytes

        // Also adjust the bit-widths to 0
        for (i = 0; i < sizeof(tlv2_fields) / sizeof(tlv2_fields[0]); i++) {
            fld = find_field(h, tlv2_fields[i]);
            fld->bit_width = 0;
        }
    }

    return 0;
}

static field_t SV_FIELDS[] = {
    { .name = "path",
      .help = "SupPath (0)",
      .bit_width = 4},
    { .name = "ver",
      .help = "SupVersion (1)",
      .bit_width = 12},
    { .name = "seqn",
      .help = "Sequence Number",
      .bit_width = 16},
    { .name = "tlv1_type",
      .help = "TLV1.Type (20 = PRP-DD, 21 = PRP-DA, 23 = HSR)",
      .bit_width = 8},
    { .name = "tlv1_len",
      .help = "TLV1.Length (6)",
      .bit_width = 8},
    { .name = "tlv1_mac",
      .help = "TLV1.MacAddress (MAC of DANP/DANH)",
      .bit_width = 48},
    { .name = "tlv2_type",
      .help = "TLV2.Type (30). Don't specify if not a RedBox SV frame",
      .bit_width = 8},
    { .name = "tlv2_len",
      .help = "TLV2.Length (6)",
      .bit_width = 8},
    { .name = "tlv2_mac",
      .help = "TLV2.RedBoxMacAddress",
      .bit_width = 48},
    { .name = "tlv0_type",
      .help = "TLV0.Type (0)",
      .bit_width = 8},
    { .name = "tlv0_len",
      .help = "TLV0.Length (0)",
      .bit_width = 8},
};

static hdr_t HDR_SV = {
    .name = "sv",
    .help = "PRP & HSR Supervision Frames",
    .type = 0x88fb,
    .fields = SV_FIELDS,
    .fields_size = sizeof(SV_FIELDS) / sizeof(SV_FIELDS[0]),
    .frame_fill_defaults = sv_fill_defaults,
    .parser = hdr_parse_fields,
};

void sv_init() {
    def_offset(&HDR_SV);
    def_val(&HDR_SV, "ver",       "1");
    def_val(&HDR_SV, "tlv1_type", "20");
    def_val(&HDR_SV, "tlv1_len",  "6");
    def_val(&HDR_SV, "tlv2_len",  "6");
    def_val(&HDR_SV, "tlv2_type", "30");

    hdr_tmpls[HDR_TMPL_SV] = &HDR_SV;
}

void sv_uninit() {
    uninit_frame_data(&HDR_SV);
    hdr_tmpls[HDR_TMPL_SV] = 0;
}

