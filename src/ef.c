#include "ef.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

///////////////////////////////////////////////////////////////////////////////

// ipv6
// udp
// tcp
// icmp
// icmpv6
// dhcp (maybe)
// ifh (jr2, ocelot, maybe-other)

///////////////////////////////////////////////////////////////////////////////
field_t ETH_FIELDS[] = {
    { .name = "dmac", .bit_width =  48 },
    { .name = "smac", .bit_width =  48 },
    { .name = "et",   .bit_width =  16 },
};

hdr_t HDR_ETH = {
    .name = "eth",
    .fields = ETH_FIELDS,
    .fields_size = sizeof(ETH_FIELDS) / sizeof(ETH_FIELDS[0]),
};

///////////////////////////////////////////////////////////////////////////////
field_t VLAN_FIELDS[] = {
    //{ .name = "tpid", .bit_width =  16 },
    { .name = "pcp",  .bit_width =   3 },
    { .name = "dei",  .bit_width =   1 },
    { .name = "vid",  .bit_width =  12 },
    { .name = "et",   .bit_width =  16 },
};

hdr_t HDR_VLAN = {
    .name = "vlan",
    .fields = VLAN_FIELDS,
    .fields_size = sizeof(VLAN_FIELDS) / sizeof(VLAN_FIELDS[0]),
};

///////////////////////////////////////////////////////////////////////////////
field_t ARP_FIELDS[] = {
    { .name = "htype", .bit_width =  16 },
    { .name = "ptype", .bit_width =  16 },
    { .name = "hlen",  .bit_width =  8  },
    { .name = "plen",  .bit_width =  8  },
    { .name = "oper",  .bit_width =  16 },
    { .name = "sha",   .bit_width =  48 },
    { .name = "spa",   .bit_width =  32 },
    { .name = "tha",   .bit_width =  48 },
    { .name = "tpa",   .bit_width =  32 },
};

hdr_t HDR_ARP = {
    .name = "arp",
    .type = 0x0806,
    .fields = ARP_FIELDS,
    .fields_size = sizeof(ARP_FIELDS) / sizeof(ARP_FIELDS[0]),
};

///////////////////////////////////////////////////////////////////////////////
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
};

///////////////////////////////////////////////////////////////////////////////

static void def_offset(hdr_t *h) {
    int i;
    int offset = 0;

    for (i = 0; i < h->fields_size; ++i) {
        h->fields[i].bit_offset = offset;
        offset += h->fields[i].bit_width;
    }

    h->size = BIT_TO_BYTE(offset);
}

field_t *find_field(hdr_t *h, const char *field) {
    int i;

    for (i = 0; i < h->fields_size; ++i)
        if (!strcmp(field, h->fields[i].name))
            return &h->fields[i];

    return 0;
}

static void def_val(hdr_t *h, const char *field,
                    const char *def) {
    field_t *f = find_field(h, field);

    if (!f)
        return;

    f->def = parse_bytes(def, BIT_TO_BYTE(f->bit_width));
}

///////////////////////////////////////////////////////////////////////////////

void init_frame_data_all() {
    def_offset(&HDR_ETH);
    def_offset(&HDR_VLAN);
    def_offset(&HDR_ARP);
    def_offset(&HDR_IPV4);

    //def_val(&HDR_VLAN, "tpid",  "0x8100");
    def_val(&HDR_ARP,  "htype", "0x0001");
    def_val(&HDR_ARP,  "ptype", "0x0800");
    def_val(&HDR_ARP,  "hlen",  "6");
    def_val(&HDR_ARP,  "plen",  "4");

    def_val(&HDR_IPV4, "ver", "4");
    def_val(&HDR_IPV4, "ihl", "5");
    def_val(&HDR_IPV4, "ttl", "31");
}

void uninit_frame_data(hdr_t *h) {
    int i;

    for (i = 0; i < h->fields_size; ++i)
        bfree(h->fields[i].def);
}

void uninit_frame_data_all() {
    uninit_frame_data(&HDR_ETH);
    uninit_frame_data(&HDR_VLAN);
    uninit_frame_data(&HDR_ARP);
}

static int bit_get(const buf_t *val, size_t bit_pos)
{
    size_t byte_pos        =      bit_pos / 8;
    size_t bit_within_byte = 7 - (bit_pos % 8);

    assert(byte_pos < val->size);

    return (val->data[byte_pos] >> bit_within_byte) & 0x1;
}

static void bit_set(buf_t *b, size_t bit_pos, int value)
{
     size_t byte_pos        =      bit_pos / 8;
     size_t bit_within_byte = 7 - (bit_pos % 8);

     assert(byte_pos < b->size);

     if (value) {
         b->data[byte_pos] |= (1 << bit_within_byte);
     } else {
         b->data[byte_pos] &= ~(1 << bit_within_byte);
     }
}

void hdr_write_field(buf_t *b, int offset, const field_t *f, const buf_t *val)
{
    size_t pos, bits_to_1st_valid;

    // b             = Output
    // b->size       = Number of bytes in output
    // b->data       = Buffer of b->size bytes.
    // f             = Field to encode
    // f->bit_width  = Number of bits to take from #val and place in #b
    // f->bit_offset = Position of msbit of #val when put in #b
    // val           = Value to write
    // val->size     = Number of bytes in value to write
    // val->data     = Buffer of val->size bytes.
    assert(8 * b->size >= f->bit_width + f->bit_offset + offset * 8);

    // How many bits do we have to move into the value to encode before we reach
    // the first valid bit given the field width?
    bits_to_1st_valid = 8 * val->size - f->bit_width;

    for (pos = 0; pos < f->bit_width; pos++)
        bit_set(b, f->bit_offset + pos + (8 * offset),
                bit_get(val, pos + bits_to_1st_valid));
 }


buf_t *frame_def(hdr_t *hdr) {
    int i;
    buf_t *b = balloc(hdr->size);

    if (!b)
        return b;

    for (i = 0; i < hdr->fields_size; ++i) {
        field_t *f = &hdr->fields[i];
        if (!f->def)
            continue;

        hdr_write_field(b, 0, f, f->def);
    }

    return b;
}

void frame_reset(frame_t *f) {
    int i;

    for (i = 0; i < FRAME_STACK_MAX; ++i) {
        if (f->stack[i]) {
            if (f->stack[i]->fields)
                free(f->stack[i]->fields);

            free(f->stack[i]);
        }
    }

    memset(f, 0, sizeof(*f));
}

hdr_t *frame_clone_and_push_hdr(frame_t *f, hdr_t *h) {
    hdr_t *new_hdr;
    field_t *new_fields;
    new_hdr = malloc(sizeof(*new_hdr));
    new_fields = malloc(sizeof(*new_fields) * h->fields_size);

    if (!new_hdr || !new_fields) {
        if (new_hdr)
            free(new_hdr);
        if (new_fields)
            free(new_fields);

        return 0;
    }

    assert(f->stack_size < FRAME_STACK_MAX);
    assert(!f->stack[f->stack_size]);

    memcpy(new_hdr, h, sizeof(*h));
    memcpy(new_fields, h->fields, sizeof(*new_fields) * h->fields_size);
    new_hdr->fields = new_fields;

    f->stack[f->stack_size] = new_hdr;

    f->stack_size ++;

    return new_hdr;
}

int hdr_parse_fields(hdr_t *hdr, int argc, const char *argv[]) {
    int i;
    field_t *f;

    for (i = 0; i < argc; ++i) {
        f = find_field(hdr, argv[i]);

        if (!f)
            return i;

        i += 1;

        // Check to see if we have a value argument
        if (i >= argc)
            return -1;

        printf("Assigned value for %s\n", f->name);
        f->val = parse_bytes(argv[i], BIT_TO_BYTE(f->bit_width));
    }

    return i;
}

int hdr_copy_to_buf(hdr_t *hdr, int offset, buf_t *buf) {
    int i;
    buf_t *v;
    field_t *f;

    for (i = 0, f = hdr->fields; i < hdr->fields_size; ++i, ++f) {
        if (BIT_TO_BYTE(f->bit_width) + offset > buf->size) {
            printf("Buf over flow\n");
            return -1;
        }

        if (f->val) {
            printf("val %s\n", f->name);
            v = f->val;
        } else if (f->def) {
            printf("def %s\n", f->name);
            v = f->def;
        } else {
            v = 0;
        }

        if (v)
            hdr_write_field(buf, offset, f, v);
    }

    return i;
}

buf_t *frame_to_buf(frame_t *f) {
    int i;
    buf_t *buf;
    int frame_size = 0, offset = 0;

    printf("Stack size: %d\n", f->stack_size);
    for (i = 0; i < f->stack_size; ++i)
        frame_size += f->stack[i]->size;

    if (frame_size < 64)
        frame_size = 64;

    buf = balloc(frame_size);

    for (i = 0; i < f->stack_size; ++i) {
        hdr_copy_to_buf(f->stack[i], offset, buf);
        offset += f->stack[i]->size;
    }

    return buf;
}

