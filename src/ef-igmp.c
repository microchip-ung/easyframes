#include <stdio.h>
#include "ef.h"

static int igmp_fill_defaults(struct frame *f, int stack_idx) {
    int        i, found = 0, offset = 0, sum = 0, igmp_len = 0;
    char       buf[16];
    hdr_t      *h = f->stack[stack_idx];
    field_t    *chksum = find_field(h, "chksum"), *fld;
    buf_t      *b;
    const char *v3_query_fields[]  = {"qresv", "s", "qrv", "qqic", "ns"};
    const char *v3_report_fields[] = {"rresv", "ng"};

    // If none of the fields "qresv", "s", qrv" "qqic", or "ns" are present,
    // we adjust the size to 4 bytes less. Otherwise the receiver will always
    // interpret this as an IGMPv3 query.
    for (i = 0; i < sizeof(v3_query_fields) / sizeof(v3_query_fields[0]); i++) {
        fld = find_field(h, v3_query_fields[i]);
        if (fld->val || fld->def) {
            found = 1;
            break;
        }
    }

    if (!found) {
        h->size -= 4;

        // Also adjust the bit-widths to 0 in order to support IGMPv3 reports.
        for (i = 0; i < sizeof(v3_query_fields) / sizeof(v3_query_fields[0]); i++) {
            fld = find_field(h, v3_query_fields[i]);
            fld->bit_width = 0;
        }

        // po("Adjusted IGMPv3 query fields' bit-widths to 0\n");
    }

    // If none of the fields "rresv" or "ng" are present, we adjust the size to
    // 4 bytes less. Otherwise the receiver will interpret this as an IGMPv3
    // report.
    found = 0;
    for (i = 0; i < sizeof(v3_report_fields) / sizeof(v3_report_fields[0]); i++) {
        fld = find_field(h, v3_report_fields[i]);
        if (fld->val || fld->def) {
            found = 1;
            break;
        }
    }

    if (!found) {
        h->size -= 4;

        // Also adjust the bit-widths to 0 in order to support IGMPv3 Queries.
        for (i = 0; i < sizeof(v3_report_fields) / sizeof(v3_report_fields[0]); i++) {
            fld = find_field(h, v3_report_fields[i]);
            fld->bit_width = 0;
        }

        // po("Adjusted IGMPv3 report fields' bit-widths to 0\n");
    } else {
        // At least one of the IGMPv3 report fields are present, so remove the
        // Group Address, which is then only used in queries.
        h->size -= 4;
        fld = find_field(h, "ga");
        fld->bit_width = 0;

        // And move the "rresv" and "ng" bit-offsets to where they belong
        fld = find_field(h, "rresv");
        fld->bit_offset = 32;
        fld = find_field(h, "ng");
        fld->bit_offset = 48;

        // po("Adjusted IGMPv1/IGMPv2 \"ga\" field's bit-width to 0, because it's not used in IGMPv3 reports\n");
    }

    if (chksum->val) {
        // Value set by user. Don't overwrite.
        return 0;
    }

    for (i = stack_idx; i < f->stack_size; ++i) {
        igmp_len += f->stack[i]->size;
    }

    // Serialize the header (making checksum calculation easier)
    b = balloc(igmp_len);
    for (i = stack_idx; i < f->stack_size; ++i) {
        hdr_copy_to_buf(f->stack[i], offset, b);
        offset += f->stack[i]->size;
    }

    // Compute the checksum
    sum = inet_chksum(0, (uint16_t *)b->data, b->size);

    // And write it to the checksum field.
    snprintf(buf, 16, "0x%x", sum);
    buf[15] = 0;
    chksum->val = parse_bytes(buf, 2);
    bfree(b);

    return 0;
}

// To issue an IGMPv1 query, leave "max_resp" at 0 and don't use any of the
// fields "qresv", "s", "qrv", "qqic" or "ns".
// To issue an IGMPv2 query, set "max_resp" to a non-zero value and don't use
// any of the fields "qresv", "s", "qrv", "qqic" or "ns".
// To issue an IGMPv3 query, use any of the fields "qresv", "s", "qrv", "qqic",
// or "ns" and add sources with the "data hex ..." command.
// To issue an IGMPv1 or IGMPv2 report, leave "rresv" and "ng" untouched.
// To issue an IGMPv3 report, use either of the fields "rresv" or "ng" followed
// by one or more igmpv3_group records.
static field_t IGMP_FIELDS[] = {
    { .name = "type",
      .help = "IGMP type",
      .bit_width = 8},
    { .name = "max_resp",
      .help = "Max Resp Time (IGMPv2) or Max Resp Code (IGMPv3), Queries only)",
      .bit_width = 8},
    { .name = "chksum",
      .help = "Checksum",
      .bit_width = 16},
    { .name = "ga",
      .help = "Group Address (not to be used in IGMPv3 reports)",
      .bit_width = 32},
    { .name = "qresv",
      .help = "Reserved (IGMPv3, Query, only)",
      .bit_width = 4},
    { .name = "s",
      .help = "Suppress Router-Side Processing (IGMPv3, Query, only)",
      .bit_width = 1},
    { .name = "qrv",
      .help = "Querier's Robustness Variable (IGMPv3, Query, only)",
      .bit_width = 3},
    { .name = "qqic",
      .help = "Querier's Query Interval Code (IGMPv3, Query, only)",
      .bit_width = 8},
    { .name = "ns",
      .help = "Number of Sources (IGMPv3, Query, only)",
      .bit_width = 16},
    { .name = "rresv",
      .help = "Reserved (IGMPv3, Report, only)",
      .bit_width = 16},
    { .name = "ng",
      .help = "Number of Group Records (IGMPv3, Report, only)",
      .bit_width = 16},
};

// When using groups, sources (and possibly auxiliary data) are added with the
// "data hex ...." command
static field_t IGMPV3_GROUP_FIELDS[] = {
    { .name = "rec_type",
      .help = "IGMPv3 group record type",
      .bit_width = 8},
    { .name = "auxlen",
      .help = "IGMPv3 group auxLen",
      .bit_width = 8},
    { .name = "ns",
      .help = "IGMPv3 Number of Sources in group",
      .bit_width = 16},
    { .name = "ga",
      .help = "IGMPv2 Group Address",
      .bit_width = 32},
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

static hdr_t HDR_IGMPV3_GROUP = {
    .name = "igmpv3_group",
    .help = "Internet Group Management Protocol - groups used in IGMPv3 Membership Report Messages",
    .fields = IGMPV3_GROUP_FIELDS,
    .fields_size = sizeof(IGMPV3_GROUP_FIELDS) / sizeof(IGMPV3_GROUP_FIELDS[0]),
    .parser = hdr_parse_fields,
};

void igmp_init() {
    def_offset(&HDR_IGMP);
    def_offset(&HDR_IGMPV3_GROUP);

    hdr_tmpls[HDR_TMPL_IGMP]         = &HDR_IGMP;
    hdr_tmpls[HDR_TMPL_IGMPV3_GROUP] = &HDR_IGMPV3_GROUP;
}

void igmp_uninit() {
    uninit_frame_data(&HDR_IGMP);
    uninit_frame_data(&HDR_IGMPV3_GROUP);

    hdr_tmpls[HDR_TMPL_IGMP]         = 0;
    hdr_tmpls[HDR_TMPL_IGMPV3_GROUP] = 0;
}

