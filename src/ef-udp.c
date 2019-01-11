#include <stdio.h>
#include "ef.h"

field_t UDP_IPv4_CHKSUM_FIELDS[] = {
    { .name = "sip",     .bit_width =  32 },
    { .name = "dip",     .bit_width =  32 },
    { .name = "zero",    .bit_width =   8 },
    { .name = "proto",   .bit_width =   8 },
    { .name = "udp_len", .bit_width =  16 },
};

hdr_t HDR_UDP_IPV4_CHKSUM = {
    .name = "udp_ip_chksum",
    .fields = UDP_IPv4_CHKSUM_FIELDS,
    .fields_size = sizeof(UDP_IPv4_CHKSUM_FIELDS) /
            sizeof(UDP_IPv4_CHKSUM_FIELDS[0]),
};

int udp_fill_defaults(struct frame *f, int stack_idx) {
    int i, udp_len = 0, offset, sum;
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
    hdr_t *ll;
    field_t *chksum = find_field(h, "chksum");
    field_t *len = find_field(h, "len");

    for (i = stack_idx; i < f->stack_size; ++i) {
        udp_len += f->stack[i]->size;
    }

    if (!len->val) {
        snprintf(buf, 16, "%d", udp_len);
        buf[15] = 0;
        len->val = parse_bytes(buf, 2);
    }

    if (!chksum->val && stack_idx >= 1) {
        ll = f->stack[stack_idx - 1];

        // TODO, ipv6
        if (strcmp(ll->name, "ipv4") == 0) {
            field_t *ll_field;

            // Alloc and fill the UDP checksum pseudo header.
            hdr_t *ipv4_chksum_hdr = hdr_clone(&HDR_UDP_IPV4_CHKSUM);

            ll_field = find_field(ll, "sip");
            find_field(ipv4_chksum_hdr, "sip")->val = bclone(ll_field->val);

            ll_field = find_field(ll, "dip");
            find_field(ipv4_chksum_hdr, "dip")->val = bclone(ll_field->val);

            find_field(ipv4_chksum_hdr, "proto")->val = parse_bytes("17", 1);

            snprintf(buf, 16, "%d", udp_len);
            buf[15] = 0;
            find_field(ipv4_chksum_hdr, "udp_len")->val = parse_bytes(buf, 2);

            // 12 is the size of the ip-header-for-udp-calc
            buf_t *b = balloc(udp_len + 12);

            // Serialize the header (making checksum calculation easier)
            hdr_copy_to_buf(ipv4_chksum_hdr, 0, b);
            offset = ipv4_chksum_hdr->size;
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
            hdr_free(ipv4_chksum_hdr);
        }
    }

    return 0;
}

field_t UDP_FIELDS[] = {
    { .name = "sport",
      .help = "Source Port Number, e.g. 22 for SSH",
      .bit_width =  16 },
    { .name = "dport",
      .help = "Destination Port Number, e.g. 22 for SSH",
      .bit_width =  16 },
    { .name = "len",
      .help = "Length of UDP header and data",
      .bit_width =  16 },
    { .name = "chksum",
      .help = "Checksum",
      .bit_width =  16 },
};

hdr_t HDR_UDP = {
    .name = "udp",
    .help = "User Datagram Protocol",
    .type = 17,
    .fields = UDP_FIELDS,
    .fields_size = sizeof(UDP_FIELDS) / sizeof(UDP_FIELDS[0]),
    .frame_fill_defaults = udp_fill_defaults,
    .parser = hdr_parse_fields,
};

void udp_init() {
    def_offset(&HDR_UDP);
    def_offset(&HDR_UDP_IPV4_CHKSUM);

    hdr_tmpls[HDR_TMPL_UDP] = &HDR_UDP;
}

void udp_uninit() {
    uninit_frame_data(&HDR_UDP);
    uninit_frame_data(&HDR_UDP_IPV4_CHKSUM);

    hdr_tmpls[HDR_TMPL_UDP] = 0;
}
