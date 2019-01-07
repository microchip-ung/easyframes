#include "ef.h"
#include <stdio.h>

static int eth_fill_defaults(struct frame *f, int stack_idx) {
    return ether_type_fill_defaults(f, stack_idx);
}

static field_t ETH_FIELDS[] = {
    { .name = "dmac", .bit_width =  48 },
    { .name = "smac", .bit_width =  48 },
    { .name = "et",   .bit_width =  16 },
};

static hdr_t HDR_ETH = {
    .name = "eth",
    .fields = ETH_FIELDS,
    .fields_size = sizeof(ETH_FIELDS) / sizeof(ETH_FIELDS[0]),
    .frame_fill_defaults = eth_fill_defaults,
};

void eth_init() {
    printf("init - eth\n");
    def_offset(&HDR_ETH);
    hdr_tmpls[HDR_TMPL_ETH] = &HDR_ETH;
}

void eth_uninit() {
    uninit_frame_data(&HDR_ETH);
    hdr_tmpls[HDR_TMPL_ETH] = 0;
}

