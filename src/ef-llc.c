#include <stdio.h>
#include "ef.h"

// IEEE 802.2 Logical Link Control. llc writes the 802.3 length into the
// "et" field of the header below it: eth, or the outermost VLAN tag.
static int llc_fill_defaults(struct frame *f, int stack_idx) {
    char buf[16];
    int i, len = 0;
    hdr_t *ll;
    field_t *et;

    if (stack_idx < 1)
        return 0;

    ll = f->stack[stack_idx - 1];
    et = find_field(ll, "et");

    // An explicit "et" on the command line wins over the computed length.
    if (!et || et->val)
        return 0;

    for (i = stack_idx; i < f->stack_size; ++i)
        len += f->stack[i]->size;

    // 802.3 clause 3.2.6: a type/length value above 1500 is not a length,
    // and from 1536 up it is read as an EtherType. Refuse to emit one rather
    // than silently write a frame the receiver will misparse.
    if (len > 1500) {
        pe("llc: 802.3 length %d exceeds 1500, set \"et\" explicitly\n",
           len);
        return -1;
    }

    snprintf(buf, 16, "%d", len);
    buf[15] = 0;
    et->val = parse_bytes(buf, 2);

    return 0;
}

static field_t LLC_FIELDS[] = {
    { .name = "dsap",
      .help = "Destination Service Access Point, e.g. 0x42 for STP",
      .bit_width =   8 },
    { .name = "ssap",
      .help = "Source Service Access Point, e.g. 0x42 for STP",
      .bit_width =   8 },
    { .name = "ctrl",
      .help = "Control, one byte for U-format frames, e.g. 0x03 for UI",
      .bit_width =   8 },
};

static hdr_t HDR_LLC = {
    .name = "llc",
    .help = "IEEE 802.2 LLC, sets the 802.3 length below it, e.g. llc stp",
    .fields = LLC_FIELDS,
    .fields_size = sizeof(LLC_FIELDS) / sizeof(LLC_FIELDS[0]),
    .frame_fill_defaults = llc_fill_defaults,
    .parser = hdr_parse_fields,
};

void llc_init() {
    def_offset(&HDR_LLC);
    def_val(&HDR_LLC, "dsap", "0x42");
    def_val(&HDR_LLC, "ssap", "0x42");
    def_val(&HDR_LLC, "ctrl", "0x03");

    hdr_tmpls[HDR_TMPL_LLC] = &HDR_LLC;
}

void llc_uninit() {
    uninit_frame_data(&HDR_LLC);

    hdr_tmpls[HDR_TMPL_LLC] = 0;
}
