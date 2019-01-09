#include "ef.h"

field_t ARP_FIELDS[] = {
    { .name = "htype",
      .help = "Hardware type, e.g. 0x0001 for Ethernet",
      .bit_width =  16 },
    { .name = "ptype",
      .help = "Protocol type, e.g. 0x0800 for IPv4",
      .bit_width =  16 },
    { .name = "hlen",
      .help = "Hardware length, e.g. 6 for Ethernet",
      .bit_width =  8  },
    { .name = "plen",
      .help = "Protocol length, e.g. 4 for IPv4",
      .bit_width =  8  },
    { .name = "oper",
      .help = "Operation, 1 for request, 2 for reply",
      .bit_width =  16 },
    { .name = "sha",
      .help = "Sender hardware address, e.g. 00:00:c1:a0:b1:c2",
      .bit_width =  48 },
    { .name = "spa",
      .help = "Sender protocol address, e.g. 10.10.10.1",
      .bit_width =  32 },
    { .name = "tha",
      .help = "Target hardware address, e.g. 00:00:c1:a0:b1:c3",
      .bit_width =  48 },
    { .name = "tpa",
      .help = "Target protocol address, e.g. 10.10.10.2",
      .bit_width =  32 },
};

hdr_t HDR_ARP = {
    .name = "arp",
    .help = "Address Resolution Protocol, e.g. arp oper 1 spa 10.10.10.1",
    .type = 0x0806,
    .fields = ARP_FIELDS,
    .fields_size = sizeof(ARP_FIELDS) / sizeof(ARP_FIELDS[0]),
};

void arp_init() {
    def_offset(&HDR_ARP);
    def_val(&HDR_ARP, "htype", "0x0001");
    def_val(&HDR_ARP, "ptype", "0x0800");
    def_val(&HDR_ARP, "hlen",  "6");
    def_val(&HDR_ARP, "plen",  "4");

    hdr_tmpls[HDR_TMPL_ARP] = &HDR_ARP;
}

void arp_uninit() {
    uninit_frame_data(&HDR_ARP);

    hdr_tmpls[HDR_TMPL_ARP] = 0;
}
