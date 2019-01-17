#include <stdio.h>
#include "ef.h"

static int ipv6_fill_defaults(struct frame *f, int stack_idx) {
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
    field_t *next = find_field(h, "next");
    field_t *len = find_field(h, "len");

    if (!next->val) {
        if (stack_idx + 1 < f->stack_size) {
            snprintf(buf, 16, "%d", f->stack[stack_idx + 1]->type);
        } else {
            // default to UDP
            snprintf(buf, 16, "17");
        }
        buf[15] = 0;
        next->val = parse_bytes(buf, 1);
    }

    if (!len->val) {
        int i, ip_len = 0;
        for (i = stack_idx + 1; i < f->stack_size; ++i) {
            //printf("got one\n");
            ip_len += f->stack[i]->size;
        }

        //printf("IP len: %d\n", ip_len);
        snprintf(buf, 16, "%d", ip_len);
        buf[15] = 0;
        len->val = parse_bytes(buf, 2);
    }

    return 0;
}

static field_t IPV6_FIELDS[] = {
    { .name = "ver",
      .help = "Four-bit version field, e.g. 6 for IPv6",
      .bit_width =  4  },
    { .name = "dscp",
      .help = "Differentiated Services Code Point",
      .bit_width =  6  },
    { .name = "ecn",
      .help = "Explicit Congestion Notification",
      .bit_width =  2  },
    { .name = "flow",
      .help = "Flow label",
      .bit_width =  20 },
    { .name = "len",
      .help = "Payload Length of Extension Headers and Upper Layer data",
      .bit_width =  16 },
    { .name = "next",
      .help = "Next Header, i.e. type of header that follows the IPv6 header",
      .bit_width =  8  },
    { .name = "hlim",
      .help = "Hop Limit - same as TTL in IPv4",
      .bit_width =  8  },
    { .name = "sip",
      .help = "Source IP Address, e.g. 2001:db8::1",
      .bit_width = 128 },
    { .name = "dip",
      .help = "Destination IP Address, e.g. 2001:db8::2",
      .bit_width = 128 },
};

static hdr_t HDR_IPV6 = {
    .name = "ipv6",
    .help = "Internet Protocol version 6, e.g. ipv6 sip 2001:db8::1 dip 2001:db8::2",
    .type = 0x86dd,
    .fields = IPV6_FIELDS,
    .fields_size = sizeof(IPV6_FIELDS) / sizeof(IPV6_FIELDS[0]),
    .frame_fill_defaults = ipv6_fill_defaults,
    .parser = hdr_parse_fields,
};

void ipv6_init() {
    def_offset(&HDR_IPV6);
    def_val(&HDR_IPV6, "ver", "6");
    def_val(&HDR_IPV6, "hlim", "31");

    hdr_tmpls[HDR_TMPL_IPV6] = &HDR_IPV6;
}

void ipv6_uninit() {
    uninit_frame_data(&HDR_IPV6);

    hdr_tmpls[HDR_TMPL_IPV6] = 0;
}
