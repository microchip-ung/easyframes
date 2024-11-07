#include <arpa/inet.h> /* For htonl() */
#include <stdio.h>
#include "ef.h"

static int mld_fill_defaults(struct frame *f, int stack_idx) {
    int        i, found = 0, offset = 0, sum, mld_len;
    size_t     i2;
    char       buf[16];
    hdr_t      *h = f->stack[stack_idx], *ip_hdr = f->stack[0];
    field_t    *chksum = find_field(h, "chksum"), *fld, *sip = NULL, *dip = NULL;
    uint8_t   *ptr;
    buf_t      *b;
    const char *v2_query_fields[]  = {"qresv", "s", "qrv", "qqic", "ns"};
    const char *v2_report_fields[] = {"rresv", "ng"};

    struct {
        uint8_t     sip[16];
        uint8_t     dip[16];
        uint32_t    len;
        uint8_t     zeros[3];
        uint8_t     next_hdr;
    } __attribute__((packed)) pseudo_hdr;

    // If none of the fields "qresv", "s", qrv" "qqic", or "ns" are present,
    // we adjust the size to 4 bytes less. Otherwise the receiver will always
    // interpret this as an MLDv2 query.
    for (i2 = 0; i2 < sizeof(v2_query_fields) / sizeof(v2_query_fields[0]); i2++) {
        fld = find_field(h, v2_query_fields[i2]);
        if (fld->val || fld->def) {
            found = 1;
            break;
        }
    }

    if (!found) {
        h->size -= 4;

        // Also adjust the bit-widths to 0 in order to support MLDv2 reports.
        for (i2 = 0; i2 < sizeof(v2_query_fields) / sizeof(v2_query_fields[0]); i2++) {
            fld = find_field(h, v2_query_fields[i2]);
            fld->bit_width = 0;
        }

        // po("Adjusted MLDv2 query fields' bit-widths to 0\n");
    }

    // If none of the fields "rresv" or "ng" are present, we adjust the size to
    // 4 bytes less. Otherwise the receiver will interpret this as an MLDv2
    // report.
    found = 0;
    for (i2 = 0; i2 < sizeof(v2_report_fields) / sizeof(v2_report_fields[0]); i2++) {
        fld = find_field(h, v2_report_fields[i2]);
        if (fld->val || fld->def) {
            found = 1;
            break;
        }
    }

    if (!found) {
        h->size -= 4;

        // Also adjust the bit-widths to 0 in order to support IGMPv3 Queries.
        for (i2 = 0; i2 < sizeof(v2_report_fields) / sizeof(v2_report_fields[0]); i2++) {
            fld = find_field(h, v2_report_fields[i2]);
            fld->bit_width = 0;
        }

        // po("Adjusted MLDv2 report fields' bit-widths to 0\n");
    } else {
        // At least one of the MLDv2 report fields are present, so remove the
        // Group Address, Maximum Response Code, and Reserved, which are only
        // used in queries.
        h->size -= 20;
        fld = find_field(h, "ga");
        fld->bit_width = 0;
        fld = find_field(h, "max_resp");
        fld->bit_width = 0;
        fld = find_field(h, "rsv");
        fld->bit_width = 0;

        // And move the "rresv" and "ng" bit-offsets to where they belong
        fld = find_field(h, "rresv");
        fld->bit_offset = 32;
        fld = find_field(h, "ng");
        fld->bit_offset = 48;

        // po("Adjusted MLDv1 \"ga\" field's bit-width to 0, because it's not used in MLDv2 reports\n");
    }

    if (chksum->val) {
        // Value set by user. Don't overwrite.
        return 0;
    }

    memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));

    // Look for an IPv6 header.
    found = 0;
    for (i = 0; i < stack_idx; i++) {
        ip_hdr = f->stack[i];

        if (ip_hdr && strcmp(ip_hdr->name, "ipv6") == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        po("Error: MLD fields must be preceded by an IPv6 header (sip = %p, dip = %p)\n", sip, dip);
        exit(-1);
    }

    sip = find_field(ip_hdr, "sip");
    if (!sip) {
        po("Internal error: \"sip\" field not found in IPv6 header\n");
        exit(-1);
    }

    dip = find_field(ip_hdr, "dip");
    if (!dip) {
        po("Internal error: \"dip\" field not found in IPv6 header\n");
        exit(-1);
    }

    if (!sip->val || !sip->val->data || sip->val->size != 16) {
        po("Error: IPv6 header's SIP is not set or its size is not 16 bytes\n");
        exit(-1);
    }

    if (!dip->val || !dip->val->data || dip->val->size != 16) {
        po("Error: IPv6 header's DIP is not set or its size is not 16 bytes\n");
        exit(-1);
    }

    memcpy(pseudo_hdr.sip, sip->val->data, sizeof(pseudo_hdr.sip));
    memcpy(pseudo_hdr.dip, dip->val->data, sizeof(pseudo_hdr.dip));

    mld_len = 0;
    for (i = stack_idx; i < f->stack_size; ++i) {
        mld_len += f->stack[i]->size;
    }

    pseudo_hdr.len = htonl(mld_len);

    // We anticipate the IPv6 header's next header to be 58 for ICMP, which is
    // what MLD is using.
    pseudo_hdr.next_hdr = 58;

    // First compute the checksum of the pseudo header by simply summing up all
    // 16-bit values without folding. Notice that we expect the pseudo header to
    // be an even number of bytes.
    sum = 0;
    
    ptr = (uint8_t *)&pseudo_hdr;
    for (i2 = 0; i2 < sizeof(pseudo_hdr); i2 += 2) {
        //make sure each value is read in big endian
        uint16_t value = (((uint16_t)(ptr[0])) << 8) |
                          (uint16_t)(ptr[1]);
        sum += value;
        ptr+=2;
    }

    // Then serialize the MLD message
    b = balloc(mld_len);
    for (i = stack_idx; i < f->stack_size; ++i) {
        hdr_copy_to_buf(f->stack[i], offset, b);
        offset += f->stack[i]->size;
    }

    // Finally provide the so-far-reached sum to inet_chksum(), which computes
    // the final checksum of the MLD message.
    sum = inet_chksum(sum, (uint16_t *)b->data, b->size);

    // And write it to the checksum field.
    snprintf(buf, 16, "0x%x", sum);
    buf[15] = 0;
    chksum->val = parse_bytes(buf, 2);
    bfree(b);

    return 0;
}

// To issue an MLDv1 query, don't use any of the fields "qresv", "s", "qrv",
// "qqic" or "ns".
// To issue an MLDv2 query, use any of the fields "qresv", "s", "qrv", "qqic", or
// "ns" and add possible sources with the "data hex ..." command.
// To issue an MLDv2 report, leave "rresv" and "ng" untouched.
// To issue an MLDv3 report, use either of the fields "rresv" or "ng" followed
// by one or more mldv2_group records.
static field_t MLD_FIELDS[] = {
    { .name = "type",
      .help = "MLD type",
      .bit_width = 8},
    { .name = "code",
      .help = "Code - initialized to zero by the sender, ignored by receivers",
      .bit_width = 8},
    { .name = "chksum",
      .help = "Checksum",
      .bit_width = 16},
    { .name = "max_resp",
      .help = "Maximum Response Delay (MLDv1) or Maximum Response Code (MLDv2), Query, only",
      .bit_width = 16},
    { .name = "rsv",
      .help = "Reserved",
      .bit_width = 16},
    { .name = "ga",
      .help = "Group Address (not to be used in MLDv2 reports)",
      .bit_width = 128},
    { .name = "qresv",
      .help = "Reserved (MLDv2, Query, only)",
      .bit_width = 4},
    { .name = "s",
      .help = "Suppress Router-Side Processing (MLDv2, Query, only)",
      .bit_width = 1},
    { .name = "qrv",
      .help = "Querier's Robustness Variable (MLDv2, Query, only)",
      .bit_width = 3},
    { .name = "qqic",
      .help = "Querier's Query Interval Code (MLDv2, Query, only)",
      .bit_width = 8},
    { .name = "ns",
      .help = "Number of Sources (MLDv2, Query, only)",
      .bit_width = 16},
    { .name = "rresv",
      .help = "Reserved (MLDv3, Report, only)",
      .bit_width = 16},
    { .name = "ng",
      .help = "Number of Group Records (MLDv2, Report, only)",
      .bit_width = 16},
};

// When using groups, sources (and possibly auxiliary data) are added with the
// "data hex ...." command
static field_t MLDV2_GROUP_FIELDS[] = {
    { .name = "rec_type",
      .help = "MLDv2 group record type",
      .bit_width = 8},
    { .name = "auxlen",
      .help = "MLDv2 group auxLen",
      .bit_width = 8},
    { .name = "ns",
      .help = "MLDv2 Number of Sources in group",
      .bit_width = 16},
    { .name = "ga",
      .help = "MLDv2 Group Address",
      .bit_width = 128},
};

static hdr_t HDR_MLD = {
    .name = "mld",
    .help = "Multicast Listener Discovery Protocol",
    .type = 0, // Hop-by-Hop
    .fields = MLD_FIELDS,
    .fields_size = sizeof(MLD_FIELDS) / sizeof(MLD_FIELDS[0]),
    .frame_fill_defaults = mld_fill_defaults,
    .parser = hdr_parse_fields,
};

static hdr_t HDR_MLDV2_GROUP = {
    .name = "mldv2_group",
    .help = "Multicast Listener Discovery - groups used in MLDv2 Membership Report Messages",
    .type = 2,
    .fields = MLDV2_GROUP_FIELDS,
    .fields_size = sizeof(MLDV2_GROUP_FIELDS) / sizeof(MLDV2_GROUP_FIELDS[0]),
    .parser = hdr_parse_fields,
};

void mld_init() {
    def_offset(&HDR_MLD);
    def_offset(&HDR_MLDV2_GROUP);

    hdr_tmpls[HDR_TMPL_MLD]         = &HDR_MLD;
    hdr_tmpls[HDR_TMPL_MLDV2_GROUP] = &HDR_MLDV2_GROUP;
}

void mld_uninit() {
    uninit_frame_data(&HDR_MLD);
    uninit_frame_data(&HDR_MLDV2_GROUP);
    hdr_tmpls[HDR_TMPL_MLD]         = 0;
    hdr_tmpls[HDR_TMPL_MLDV2_GROUP] = 0;
}

