#include <stdio.h>
#include "ef.h"

static int igmp_fill_defaults(struct frame *f, int stack_idx) {
    int i, igmp_len = 0, found = 0;
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
    field_t *chksum = find_field(h, "chksum"), *fld;
    const char *v3_fields[] = {"resv", "s", "qrv", "qqic", "ns"};

    // If none of the fields "resv", "s", qrv" "qqic", or "ns" are present,
    // we adjust the size to 4 bytes less. Otherwise the receiver will always
    // interpret this as an IGMPv3 query.
    for (i = 0; i < sizeof(v3_fields) / sizeof(v3_fields[0]); i++) {
        fld = find_field(h, v3_fields[i]);
        if (fld->val || fld->def) {
            found = 1;
            break;
        }
    }

    if (!found) {
        h->size -= 4;
    }

    for (i = stack_idx; i < f->stack_size; ++i) {
        igmp_len += f->stack[i]->size;
    }

    if (!chksum->val) {
        buf_t *b;
        int offset = 0, sum;

        // Serialize the header (making checksum calculation easier)
        b = balloc(igmp_len);
        for (i = stack_idx; i < f->stack_size; ++i) {
            hdr_copy_to_buf(f->stack[i], offset, b);
            offset += f->stack[i]->size;
        }

        // Write the checksum to the header
        sum = inet_chksum(0, (uint16_t *)b->data, b->size);
        snprintf(buf, 16, "%d", sum);
        buf[15] = 0;
        chksum->val = parse_bytes(buf, 2);

        bfree(b);
    }
    return 0;
}

static field_t IGMP_FIELDS[] = {
    { .name = "type",
      .help = "IGMP type",
      .bit_width =   8 },
    { .name = "code",
      .help = "Max Resp Code",
      .bit_width =   8 },
    { .name = "chksum",
      .help = "Checksum",
      .bit_width =  16 },
    { .name = "ga",
      .help = "Group Address",
      .bit_width =  32 },
    { .name = "resv",
      .help = "Reserved (IGMPv3)",
      .bit_width =   4 },
    { .name = "s",
      .help = "Suppress Router-Side Processing (IGMPv3)",
      .bit_width =   1 },
    { .name = "qrv",
      .help = "Querier's Robustness Variable (IGMPv3)",
      .bit_width =   3 },
    { .name = "qqic",
      .help = "Querier's Query Interval Code (IGMPv3)",
      .bit_width =   8 },
    { .name = "ns",
      .help = "Number of Sources (IGMPv3)",
      .bit_width =   16 },
};

static hdr_t HDR_IGMP = {
    .name = "igmp",
    .help = "Internet Group Management Protocol",
    .type = 2,
    .fields = IGMP_FIELDS,
    .fields_size = sizeof(IGMP_FIELDS) / sizeof(IGMP_FIELDS[0]),
    .frame_fill_defaults = igmp_fill_defaults,
    .parser = hdr_parse_fields,
};

void igmp_init() {
    def_offset(&HDR_IGMP);
    hdr_tmpls[HDR_TMPL_IGMP] = &HDR_IGMP;
}

void igmp_uninit() {
    uninit_frame_data(&HDR_IGMP);
    hdr_tmpls[HDR_TMPL_IGMP] = 0;
}
