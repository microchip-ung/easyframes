#include "ef.h"
#include <stdio.h>

static int eth_fill_defaults(struct frame *f, int stack_idx) {
    return ether_type_fill_defaults(f, stack_idx);
}

static field_t ETH_FIELDS[] = {
    { .name = "dmac",
      .help = "Destination MAC address, e.g. 00:00:c1:a0:b1:c2, ::1, 1 or 0x1",
      .bit_width =  48 },
    { .name = "smac",
      .help = "Source MAC address, e.g. 00:00:c1:a5:b6:c7, ::1, 1 or 0x1",
      .bit_width =  48 },
    { .name = "et",
      .help = "EtherType, e.g. 0x0800",
      .bit_width =  16 },
};

static hdr_t HDR_ETH = {
    .name = "eth",
    .help = "Ethernet frame, e.g. eth dmac 00:00:c1:a0:b1:c2 smac 00:00:c1:a5:b6:c7 et 0x0800",
    .fields = ETH_FIELDS,
    .fields_size = sizeof(ETH_FIELDS) / sizeof(ETH_FIELDS[0]),
    .frame_fill_defaults = eth_fill_defaults,
};

void eth_init() {
    def_offset(&HDR_ETH);
    hdr_tmpls[HDR_TMPL_ETH] = &HDR_ETH;
}

void eth_uninit() {
    uninit_frame_data(&HDR_ETH);
    hdr_tmpls[HDR_TMPL_ETH] = 0;
}

