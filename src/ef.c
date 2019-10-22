#include "ef.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

hdr_t *hdr_tmpls[HDR_TMPL_SIZE];

void hexdump(void *_d, int s) {
    int i;
    uint8_t *d = (uint8_t *)_d;
    uint8_t *e = d + s;

    while (d != e) {
        po("%08tx: ", (void *)d - (void *)_d);
        for (i = 0; i < 16 && d != e; ++i, ++d)
            po("%02hhx ", *d);
        po("\n");
    }
}

void print_hex_str(int fd, void *_d, int s) {
    uint8_t *d = (uint8_t *)_d;
    uint8_t *e = d + s;

    for (; d != e; ++d) {
        dprintf(fd, "%02hhx", *d);
    }
}

typedef void (*destruct_cb_t)(void *buf);

void destruct_free(void *buf, void *cb_) {
    destruct_cb_t cb = (destruct_cb_t)cb_;
    if (!buf)
        return;

    cb(buf);
    free(buf);
}


void field_destruct(field_t *f) {
    if (!f)
        return;

    if (f->def)
        bfree(f->def);

    if (f->val)
        bfree(f->val);

    memset(f, 0, sizeof(*f));
};

int field_copy(field_t *dst, const field_t *src) {
    memcpy(dst, src, sizeof(*src));
    dst->val = bclone(src->val);
    dst->def = bclone(src->def);

    // TODO, handle error

    return 0;
}

void hdr_destruct(hdr_t *h) {
    int i;

    if (!h)
        return;

    for (i = 0; i < h->fields_size; ++i) {
        field_destruct(&(h->fields[i]));
    }

    if (h->fields)
        free(h->fields);

    memset(h, 0, sizeof(*h));
}

int hdr_copy(hdr_t *dst, const hdr_t *src) {
    int i;
    memcpy(dst, src, sizeof(*src));

    if (src->fields_size && src->fields) {
        dst->fields = malloc(src->fields_size * sizeof(field_t));
        if (!dst->fields)
            return -1;
    }

    for (i = 0; i < src->fields_size; ++i) {
        field_copy(&dst->fields[i], &src->fields[i]);
        // TODO, handle error
    }

    return 0;
}

void frame_destruct(frame_t *f) {
    int i;

    for (i = 0; i < f->stack_size; ++i) {
        hdr_free(f->stack[i]);
    }

    memset(f, 0, sizeof(*f));
}

int frame_copy(frame_t *dst, const frame_t *src) {
    int i;
    memcpy(dst, src, sizeof(*src));

    for (i = 0; i < src->stack_size; ++i) {
        dst->stack[i] = hdr_clone(src->stack[i]);

        // TODO, handle error
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////

// ipv6
// tcp
// icmp
// icmpv6
// dhcp (maybe)
// ifh (jr2, ocelot, maybe-other)

uint16_t inet_chksum(uint32_t sum, const uint16_t *buf, int length) {
    while (length > 1) {
        sum += *buf++;
        length -= 2;
    }

    if (length == 1) {
        uint16_t tmp = *(uint8_t *)buf;
#ifdef __BIG_ENDIAN__
        tmp <<= 8;
#endif
        sum += tmp;
    }

    sum = ~((sum >> 16) + (sum & 0xffff));
    sum &= 0xffff;

    return htons(sum);
}

///////////////////////////////////////////////////////////////////////////////
int ether_type_fill_defaults(struct frame *f, int stack_idx) {
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
    field_t *et = find_field(h, "et");

    if (et->val)
        return 0;

    if (stack_idx + 1 < f->stack_size) {
        snprintf(buf, 16, "%d", f->stack[stack_idx + 1]->type);
        buf[15] = 0;

        et->val = parse_bytes(buf, 2);
    }

    return 0;
}

void def_offset(hdr_t *h) {
    int i;
    int offset = 0;
    field_t *f;

    for (i = 0; i < h->fields_size; ++i) {
        f = &h->fields[i];
        if (f->bit_offset) {
            if (f->bit_offset < offset)
                continue;
            else
                po("ERROR: Fields with explicit bit_offset must be "
                       "specified after the one it overloads in field_t\n");
        }
        f->bit_offset = offset;
        offset += f->bit_width;
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

void def_val(hdr_t *h, const char *field, const char *def) {
    field_t *f = find_field(h, field);

    if (!f)
        return;

    f->def = parse_bytes(def, BIT_TO_BYTE(f->bit_width));
}

///////////////////////////////////////////////////////////////////////////////

void uninit_frame_data(hdr_t *h) {
    int i;

    for (i = 0; i < h->fields_size; ++i)
        bfree(h->fields[i].def);
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
    hdr_t *new_hdr = hdr_clone(h);

    f->stack[f->stack_size] = new_hdr;
    f->stack_size ++;

    return new_hdr;
}

int hdr_parse_fields(frame_t *frame, struct hdr *hdr, int offset,
                     int argc, const char *argv[]) {
    int i, j;
    field_t *f;
    int field_ignore = 0;

    for (i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "help") == 0) {
            hdr_help(&hdr, 1, 0, 1);
            return -1;
        }

        // If "ign" flag is set as the first argument in a header, then all
        // fields should be ignored by default
        if ((strcmp(argv[i], "ign") == 0 || strcmp(argv[i], "ignore") == 0) &&
            i == 0) {

            for (j = 0; j < hdr->fields_size; ++j)
                hdr->fields[j].rx_match_skip = 1;

            frame->has_mask = 1;
            continue;
        }

        f = find_field(hdr, argv[i]);

        if (!f)
            return i;

        if (field_ignore) {
            field_ignore = 0;
            f->rx_match_skip = 1;
            continue;
        }

        i += 1;

        // Check to see if we have a value argument
        if (i >= argc) {
            po("ERROR: Missing argument to %s\n", argv[i - 1]);
            return -1;
        }

        if (strcmp(argv[i], "ign") == 0 || strcmp(argv[i], "ignore") == 0) {
            frame->has_mask = 1;
            f->rx_match_skip = 1;
            continue;
        }

        if (strcmp(argv[i], "help") == 0) {
            field_help(f, 0);
            return -1;
        }

        //po("Assigned value for %s\n", f->name);
        if (f->parser != NULL) {
            f->val = f->parser(hdr, offset, argv[i], BIT_TO_BYTE(f->bit_width));
        } else {
            f->val = parse_bytes(argv[i], BIT_TO_BYTE(f->bit_width));
        }
        f->rx_match_skip = 0;
    }

    return i;
}

static int hdr_copy_to_buf_(hdr_t *hdr, int offset, buf_t *buf, int mask) {
    int i;
    buf_t *v = 0;
    field_t *f = 0;
    buf_t *maskb = 0;


    for (i = 0, f = hdr->fields; i < hdr->fields_size; ++i, ++f) {
        if (BIT_TO_BYTE(f->bit_width) + offset > buf->size) {
            //po("Buf over flow\n");
            return -1;
        }


        if (f->val) {
            //po("val %s\n", f->name);
            v = f->val;
        } else if (f->def) {
            //po("def %s\n", f->name);
            v = f->def;
        } else {
            v = 0;
        }

        if (mask)
            v = 0;

        if (mask && !f->rx_match_skip) {
            maskb = balloc(BIT_TO_BYTE(f->bit_width));
            memset(maskb->data, 0xff, maskb->size);
            v = maskb;
        }

        if (v)
            hdr_write_field(buf, offset, f, v);

        if (maskb) {
            bfree(maskb);
            maskb = 0;
        }
    }

    return i;
}

int hdr_copy_to_buf_mask(hdr_t *hdr, int offset, buf_t *buf) {
    return hdr_copy_to_buf_(hdr, offset, buf, 1);
}

int hdr_copy_to_buf(hdr_t *hdr, int offset, buf_t *buf) {
    return hdr_copy_to_buf_(hdr, offset, buf, 0);
}


buf_t *frame_to_buf(frame_t *f) {
    int i;
    buf_t *buf;
    int frame_size = 0, offset = 0;

    //po("Stack size: %d\n", f->stack_size);
    for (i = 0; i < f->stack_size; ++i) {
        f->stack[i]->offset_in_frame = frame_size;
        frame_size += f->stack[i]->size;
    }

    if (frame_size < 60)
        frame_size = 60;

    for (i = f->stack_size - 1; i >= 0; --i)
        if (f->stack[i]->frame_fill_defaults)
            f->stack[i]->frame_fill_defaults(f, i);

    buf = balloc(frame_size);

    for (i = 0; i < f->stack_size; ++i) {
        hdr_copy_to_buf(f->stack[i], offset, buf);
        offset += f->stack[i]->size;
    }

    return buf;
}

buf_t *frame_mask_to_buf(frame_t *f) {
    int i;
    buf_t *buf;
    int frame_size = 0, offset = 0;
    int frame_size_no_padding;

    for (i = 0; i < f->stack_size; ++i) {
        f->stack[i]->offset_in_frame = frame_size;
        frame_size += f->stack[i]->size;
    }

    frame_size_no_padding = frame_size;
    if (frame_size < 60)
        frame_size = 60;

    buf = balloc(frame_size);
    if (frame_size > frame_size_no_padding) {
        memset(buf->data + frame_size_no_padding, 0xff,
               buf->size - frame_size_no_padding);
    }

    for (i = 0; i < f->stack_size; ++i) {
        hdr_copy_to_buf_mask(f->stack[i], offset, buf);
        offset += f->stack[i]->size;
    }

    return buf;
}

void field_help(field_t *f, int indent)
{
    int i;

    for (i = 0; i < indent; ++i) {
        po(" ");
    }

    po("%-20s", f->name);
    po("+%3d:%3d ", f->bit_offset, f->bit_width);

    if (f->help)
        po(" %s", f->help);
    else
        po(" %s", "MISSING FIELD HELP TEXT!");

    po("\n");
}

void hdr_help(hdr_t **hdr, int size, int indent, int show_fields)
{
    int i, j;
    hdr_t *h;

    for (i = 0; i < size; ++i) {
        h = hdr[i];

        if (!h || !h->name)
            continue;

        for (j = 0; j < indent; ++j) {
            po(" ");
        }
        po("%-16s", h->name);

        if (h->help)
            po(" %s", h->help);
        else
            po(" %s", "MISSING HDR HELP TEXT!");

        po("\n");

        if (show_fields) {
            po("\n");
            po("Specify the %s header by using one or more of the following fields:\n",
                   h->name);
            for (j = 0; j < indent; ++j) {
                po(" ");
            }
            po("- Name ------------ offset:width --- Description --------------------------\n");
            for (j = 0; j < h->fields_size; ++j) {
                field_help(&h->fields[j], indent + 2);
            }
        }
    }
}

void ifh_init();
void eth_init();
void vlan_init();
void arp_init();
void ipv4_init();
void ipv6_init();
void icmp_init();
void igmp_init();
void udp_init();
void payload_init();
void padding_init();
void oam_init();
void ts_init();
void profinet_init();

void init() __attribute__ ((constructor));
void init() {
    ifh_init();
    eth_init();
    vlan_init();
    arp_init();
    ipv4_init();
    ipv6_init();
    icmp_init();
    igmp_init();
    udp_init();
    payload_init();
    padding_init();
    oam_init();
    ts_init();
    profinet_init();
}

void ifh_uninit();
void eth_uninit();
void vlan_uninit();
void arp_uninit();
void ipv4_uninit();
void ipv6_uninit();
void icmp_uninit();
void igmp_uninit();
void udp_uninit();
void payload_uninit();
void padding_uninit();
void oam_uninit();
void ts_uninit();
void profinet_uninit();

void uninit() __attribute__ ((destructor));
void uninit() {
    ifh_uninit();
    eth_uninit();
    vlan_uninit();
    arp_uninit();
    ipv4_uninit();
    ipv6_uninit();
    icmp_uninit();
    igmp_uninit();
    udp_uninit();
    payload_uninit();
    padding_uninit();
    oam_uninit();
    ts_uninit();
    profinet_uninit();
}

