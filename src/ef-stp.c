#include "ef.h"

// IEEE 802.1D and 802.1Q Bridge Protocol Data Units. A BPDU rides on an
// 802.2 LLC header, so the usual invocation is "eth ... llc stp ...".

static field_t STP_FIELDS[] = {
    { .name = "proto",
      .help = "Protocol identifier, 0x0000 for STP",
      .bit_width =  16 },
    { .name = "ver",
      .help = "Protocol version identifier, 0 for STP; for RSTP use stp_rst",
      .bit_width =   8 },
    { .name = "type",
      .help = "BPDU type, 0x00 for configuration",
      .bit_width =   8 },
    { .name = "flags",
      .help = "Flags, bit 0 is topology change, bit 7 topology change ack",
      .bit_width =   8 },
    { .name = "tc",
      .help = "Topology change flag, bit 0 of flags",
      .bit_width =   1,
      .bit_offset = 39 },
    { .name = "tcack",
      .help = "Topology change acknowledgement flag, bit 7 of flags",
      .bit_width =   1,
      .bit_offset = 32 },
    { .name = "root_prio",
      .help = "Root identifier priority, e.g. 0x8000",
      .bit_width =  16 },
    { .name = "root_mac",
      .help = "Root identifier MAC address, e.g. 00:11:22:33:44:00",
      .bit_width =  48 },
    { .name = "root_cost",
      .help = "Root path cost",
      .bit_width =  32 },
    { .name = "bridge_prio",
      .help = "Bridge identifier priority, e.g. 0x8000",
      .bit_width =  16 },
    { .name = "bridge_mac",
      .help = "Bridge identifier MAC address, e.g. 00:11:22:33:44:00",
      .bit_width =  48 },
    { .name = "port",
      .help = "Port identifier, e.g. 0x8001",
      .bit_width =  16 },
    { .name = "msg_age",
      .help = "Message age in units of 1/256 second, e.g. 0x0100 for 1 s",
      .bit_width =  16 },
    { .name = "max_age",
      .help = "Max age in units of 1/256 second, e.g. 0x1400 for 20 s",
      .bit_width =  16 },
    { .name = "hello",
      .help = "Hello time in units of 1/256 second, e.g. 0x0200 for 2 s",
      .bit_width =  16 },
    { .name = "fwd_delay",
      .help = "Forward delay in units of 1/256 second, e.g. 0x0f00 for 15 s",
      .bit_width =  16 },
};

static hdr_t HDR_STP = {
    .name = "stp",
    .help = "STP configuration BPDU, e.g. llc stp root_prio 0x8000 tc 1",
    .fields = STP_FIELDS,
    .fields_size = sizeof(STP_FIELDS) / sizeof(STP_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t STP_TCN_FIELDS[] = {
    { .name = "proto",
      .help = "Protocol identifier, 0x0000 for STP",
      .bit_width =  16 },
    { .name = "ver",
      .help = "Protocol version identifier, 0 for STP",
      .bit_width =   8 },
    { .name = "type",
      .help = "BPDU type, 0x80 for topology change notification",
      .bit_width =   8 },
};

static hdr_t HDR_STP_TCN = {
    .name = "stp_tcn",
    .help = "STP topology change notification BPDU, e.g. llc stp_tcn",
    .fields = STP_TCN_FIELDS,
    .fields_size = sizeof(STP_TCN_FIELDS) / sizeof(STP_TCN_FIELDS[0]),
    .parser = hdr_parse_fields,
};

void stp_init() {
    // Defaults describe a root bridge advertising the IEEE 802.1D-1998
    // table 8-3 recommended timer values: max age 20 s, hello 2 s and
    // forward delay 15 s, each scaled by 256.
    def_offset(&HDR_STP);
    def_val(&HDR_STP, "proto",     "0x0000");
    def_val(&HDR_STP, "ver",       "0x00");
    def_val(&HDR_STP, "type",      "0x00");
    def_val(&HDR_STP, "flags",     "0x00");
    def_val(&HDR_STP, "root_prio", "0x8000");
    def_val(&HDR_STP, "root_cost", "0");
    def_val(&HDR_STP, "bridge_prio", "0x8000");
    def_val(&HDR_STP, "port",      "0x8001");
    def_val(&HDR_STP, "msg_age",   "0x0000");
    def_val(&HDR_STP, "max_age",   "0x1400");
    def_val(&HDR_STP, "hello",     "0x0200");
    def_val(&HDR_STP, "fwd_delay", "0x0f00");

    def_offset(&HDR_STP_TCN);
    def_val(&HDR_STP_TCN, "proto", "0x0000");
    def_val(&HDR_STP_TCN, "ver",   "0x00");
    def_val(&HDR_STP_TCN, "type",  "0x80");

    hdr_tmpls[HDR_TMPL_STP] =     &HDR_STP;
    hdr_tmpls[HDR_TMPL_STP_TCN] = &HDR_STP_TCN;
}

void stp_uninit() {
    uninit_frame_data(&HDR_STP);
    uninit_frame_data(&HDR_STP_TCN);

    hdr_tmpls[HDR_TMPL_STP] = 0;
    hdr_tmpls[HDR_TMPL_STP_TCN] = 0;
}
