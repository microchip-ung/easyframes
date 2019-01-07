#include "ef.h"

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

void arp_init() __attribute__ ((constructor));
void arp_uninit() __attribute__ ((destructor));

void arp_init() {
    def_offset(&HDR_ARP);
    def_val(&HDR_ARP, "htype", "0x0001");
    def_val(&HDR_ARP, "ptype", "0x0800");
    def_val(&HDR_ARP, "hlen",  "6");
    def_val(&HDR_ARP, "plen",  "4");

}

void arp_uninit() {
    uninit_frame_data(&HDR_ARP);
}
