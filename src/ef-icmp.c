#include <stdio.h>
#include "ef.h"

// Borrow IPv6 pseudo header from ef-udp.c
// It is already initialized in ef-udp.c
extern hdr_t HDR_IPV6_PSEUDO;

static int icmp_fill_defaults(struct frame *f, int stack_idx) {
    int i, icmp_len = 0;
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
    field_t *chksum = find_field(h, "chksum");

    for (i = stack_idx; i < f->stack_size; ++i) {
        icmp_len += f->stack[i]->size;
    }

    if (!chksum->val) {
        hdr_t *pseudo_hdr = NULL;
        int pseudo_hdr_size = 0;
        buf_t *b;
        int offset, sum;

        if (stack_idx >= 1) {
            hdr_t *ll = f->stack[stack_idx - 1];

            if (strcmp(ll->name, "ipv6") == 0) {
                pseudo_hdr = hdr_clone(&HDR_IPV6_PSEUDO);
                pseudo_hdr_size = pseudo_hdr->size;

                // Clone selected parts of ip header into pseudo header
                find_field(pseudo_hdr, "sip")->val = bclone(find_field(ll, "sip")->val);
                find_field(pseudo_hdr, "dip")->val = bclone(find_field(ll, "dip")->val);

                // Set proto to ICMPv6 in pseudo header and update our own type
                find_field(pseudo_hdr, "proto")->val = parse_bytes("58", 1);
                h->type = 58;

                // Set len in pseudo header
                snprintf(buf, 16, "%d", icmp_len);
                buf[15] = 0;
                find_field(pseudo_hdr, "len")->val = parse_bytes(buf, 4);
            }
        }

        // Serialize the header (making checksum calculation easier)
        b = balloc(icmp_len + pseudo_hdr_size);
        if (pseudo_hdr)
            hdr_copy_to_buf(pseudo_hdr, 0, b);
        offset = pseudo_hdr_size;
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
        if (pseudo_hdr)
            hdr_free(pseudo_hdr);
    }
    return 0;
}

static field_t ICMP_FIELDS[] = {
    { .name = "type",
      .help = "ICMP type",
      .bit_width =   8 },
    { .name = "code",
      .help = "ICMP subtype",
      .bit_width =   8 },
    { .name = "chksum",
      .help = "Checksum",
      .bit_width =  16 },
    { .name = "hd",
      .help = "Four-byte Header Data. Contents vary based on the ICMP type and code",
      .bit_width =  32 },
};

static hdr_t HDR_ICMP = {
    .name = "icmp",
    .help = "Internet Control Message Protocol for both IPv4 and IPv6",
    .type = 1, // For IPv4. Changed to 58 if IPv6 is detected
    .fields = ICMP_FIELDS,
    .fields_size = sizeof(ICMP_FIELDS) / sizeof(ICMP_FIELDS[0]),
    .frame_fill_defaults = icmp_fill_defaults,
    .parser = hdr_parse_fields,
};

void icmp_init() {
    def_offset(&HDR_ICMP);
    hdr_tmpls[HDR_TMPL_ICMP] = &HDR_ICMP;
}

void icmp_uninit() {
    uninit_frame_data(&HDR_ICMP);
    hdr_tmpls[HDR_TMPL_ICMP] = 0;
}
