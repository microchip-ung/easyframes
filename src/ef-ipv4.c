#include <stdio.h>
#include "ef.h"

static int ipv4_fill_defaults(struct frame *f, int stack_idx) {
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
    field_t *chksum = find_field(h, "chksum");
    field_t *proto = find_field(h, "proto");
    field_t *len = find_field(h, "len");

    if (!proto->val) {
        if (stack_idx + 1 < f->stack_size) {
            snprintf(buf, 16, "%d", f->stack[stack_idx + 1]->type);
        } else {
            // default to UDP
            snprintf(buf, 16, "17");
        }
        buf[15] = 0;
        proto->val = parse_bytes(buf, 1);
    }

    if (!len->val) {
        int i, ip_len = 0;
        for (i = stack_idx; i < f->stack_size; ++i) {
            printf("got one\n");
            ip_len += f->stack[i]->size;
        }

        printf("IP len: %d\n", ip_len);
        snprintf(buf, 16, "%d", ip_len);
        buf[15] = 0;
        len->val = parse_bytes(buf, 2);
    }

    if (!chksum->val) {
        // TODO, include ip options if present
        uint16_t sum;
        buf_t *b = balloc(20);
        hdr_copy_to_buf(h, 0, b);
        sum = inet_chksum(0, (uint16_t *)b->data, b->size);

        snprintf(buf, 16, "%d", sum);
        buf[15] = 0;
        chksum->val = parse_bytes(buf, 2);

        bfree(b);
    }

    return 0;
}


field_t IPV4_FIELDS[] = {
    { .name = "ver",    .bit_width =  4  },
    { .name = "ihl",    .bit_width =  4  },
    { .name = "dscp",   .bit_width =  6  },
    { .name = "ecn",    .bit_width =  2  },
    { .name = "len",    .bit_width =  16 },
    { .name = "id",     .bit_width =  16 },
    { .name = "flags",  .bit_width =  3  },
    { .name = "offset", .bit_width =  13 },
    { .name = "ttl",    .bit_width =  8  },
    { .name = "proto",  .bit_width =  8  },
    { .name = "chksum", .bit_width =  16 },
    { .name = "sa",     .bit_width =  32 },
    { .name = "da",     .bit_width =  32 },
};

hdr_t HDR_IPV4 = {
    .name = "ipv4",
    .type = 0x0800,
    .fields = IPV4_FIELDS,
    .fields_size = sizeof(IPV4_FIELDS) / sizeof(IPV4_FIELDS[0]),
    .frame_fill_defaults = ipv4_fill_defaults,
};

void ipv4_init() {
    def_offset(&HDR_IPV4);
    def_val(&HDR_IPV4, "ver", "4");
    def_val(&HDR_IPV4, "ihl", "5");
    def_val(&HDR_IPV4, "ttl", "31");

    hdr_tmpls[HDR_TMPL_IPV4] = &HDR_IPV4;
}

void ipv4_uninit() {
    uninit_frame_data(&HDR_IPV4);

    hdr_tmpls[HDR_TMPL_IPV4] = 0;
}
