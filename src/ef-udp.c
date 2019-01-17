#include <stdio.h>
#include "ef.h"

static field_t IPv4_PSEUDO_FIELDS[] = {
    { .name = "sip",     .bit_width =  32 },
    { .name = "dip",     .bit_width =  32 },
    { .name = "zero",    .bit_width =   8 },
    { .name = "proto",   .bit_width =   8 },
    { .name = "len",     .bit_width =  16 },
};

static hdr_t HDR_IPV4_PSEUDO = {
    .name = "ipv4-pseudo",
    .fields = IPv4_PSEUDO_FIELDS,
    .fields_size = sizeof(IPv4_PSEUDO_FIELDS) /
            sizeof(IPv4_PSEUDO_FIELDS[0]),
};

static field_t IPv6_PSEUDO_FIELDS[] = {
    { .name = "sip",     .bit_width = 128 },
    { .name = "dip",     .bit_width = 128 },
    { .name = "len",     .bit_width =  32 },
    { .name = "zero",    .bit_width =  24 },
    { .name = "proto",   .bit_width =   8 },
};

hdr_t HDR_IPV6_PSEUDO = {
    .name = "ipv6-pseudo",
    .fields = IPv6_PSEUDO_FIELDS,
    .fields_size = sizeof(IPv6_PSEUDO_FIELDS) /
            sizeof(IPv6_PSEUDO_FIELDS[0]),
};

static int udp_fill_defaults(struct frame *f, int stack_idx) {
    int i, udp_len = 0;
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
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
        hdr_t *ll = f->stack[stack_idx - 1];
        hdr_t *pseudo_hdr;
        field_t *pseudo_len;
        buf_t *b;
        int offset, sum;

        if (strcmp(ll->name, "ipv4") == 0) {
            pseudo_hdr = hdr_clone(&HDR_IPV4_PSEUDO);
        } else if (strcmp(ll->name, "ipv6") == 0) {
            pseudo_hdr = hdr_clone(&HDR_IPV6_PSEUDO);
        } else {
            return 0;
        }

        // Clone selected parts of ip header into pseudo header
        find_field(pseudo_hdr, "sip")->val = bclone(find_field(ll, "sip")->val);
        find_field(pseudo_hdr, "dip")->val = bclone(find_field(ll, "dip")->val);

        // Set proto to UDP in pseudo header
        find_field(pseudo_hdr, "proto")->val = parse_bytes("17", 1);

        // Set len in pseudo header. Size of len is different in ipv4 and 6
        snprintf(buf, 16, "%d", udp_len);
        buf[15] = 0;
        pseudo_len = find_field(pseudo_hdr, "len");
        pseudo_len->val = parse_bytes(buf, pseudo_len->bit_width / 8);

        // Serialize the header (making checksum calculation easier)
        b = balloc(udp_len + pseudo_hdr->size);
        hdr_copy_to_buf(pseudo_hdr, 0, b);
        offset = pseudo_hdr->size;
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
        hdr_free(pseudo_hdr);
    }
    return 0;
}

static field_t UDP_FIELDS[] = {
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

static hdr_t HDR_UDP = {
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
    def_offset(&HDR_IPV4_PSEUDO);
    def_offset(&HDR_IPV6_PSEUDO);

    hdr_tmpls[HDR_TMPL_UDP] = &HDR_UDP;
}

void udp_uninit() {
    uninit_frame_data(&HDR_UDP);
    uninit_frame_data(&HDR_IPV4_PSEUDO);
    uninit_frame_data(&HDR_IPV6_PSEUDO);

    hdr_tmpls[HDR_TMPL_UDP] = 0;
}
