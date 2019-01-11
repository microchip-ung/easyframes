#include <stdio.h>
#include "ef.h"

field_t SP_OC1_FIELDS[] = {
    { .name = "et",
      .help = "Ethertype for short prefix. Defaults to 0x8880",
      .bit_width =  16 },
    { .name = "id",
      .help = "Id for short prefix. Defaults to 0x000a",
      .bit_width =  16 },
};

hdr_t HDR_SP_OC1 = {
    .name = "sp-oc1",
    .help = "Short prefix for injection and extraction of frames for Ocelot1",
    .fields = SP_OC1_FIELDS,
    .fields_size = sizeof(SP_OC1_FIELDS) / sizeof(SP_OC1_FIELDS[0]),
};

field_t LP_OC1_FIELDS[] = {
    { .name = "dmac",
      .help = "Destination MAC address. Defaults to ff:ff:ff:ff:ff:ff",
      .bit_width =  48 },
    { .name = "smac",
      .help = "Source MAC address. Defaults to ff:ff:ff:ff:ff:ff",
      .bit_width =  48 },
    { .name = "et",
      .help = "Ethertype for long prefix. Defaults to 0x8880",
      .bit_width =  16 },
    { .name = "id",
      .help = "Id for long prefix. Defaults to 0x000a",
      .bit_width =  16 },
};

hdr_t HDR_LP_OC1 = {
    .name = "lp-oc1",
    .help = "Long prefix for injection and extraction of frames for Ocelot1",
    .fields = LP_OC1_FIELDS,
    .fields_size = sizeof(LP_OC1_FIELDS) / sizeof(LP_OC1_FIELDS[0]),
};

field_t IFH_OC1_FIELDS[] = {
    { .name = "bypass",
      .help = "Skip analyzer processing",
      .bit_width =   1 },
    { .name = "rew-mac",
      .help = "Replace SMAC address. Only used when BYPASS = 1",
      .bit_width =   1 },
    { .name = "rew-op",
      .help = "Rewriter operation command. Only used when BYPASS = 1",
      .bit_width =   9 },

    /* The following two fields overloads the two previous fields.
       They must be specified after the fields they overload.
       Otherwise def_offset() won't work. */
    { .name = "masq",
      .help = "Enable masquerading Overlads REW_MAC. Only used when BYPASS = 0",
      .bit_width =   1,
      .bit_offset =  1 },
    { .name = "masq-port",
      .help = "Masquerading port. Overloads REW_OP. Only used when BYPASS = 0",
      .bit_width =   4,
      .bit_offset =  2 },

    { .name = "rew-val",
      .help = "Receive time stamp",
      .bit_width =  32 },
    { .name = "res1",
      .help = "Reserved",
      .bit_width =  17 },
    { .name = "dest",
      .help = "Destination set for the frame. Dest[11] is the CPU",
      .bit_width =  12 },
    { .name = "res2",
      .help = "Reserved",
      .bit_width =   9 },
    { .name = "src-port",
      .help = "The port number where the frame was injected (0-12)",
      .bit_width =   4 },
    { .name = "res3",
      .help = "Reserved",
      .bit_width =   2 },
    { .name = "trfm-timer",
      .help = "Timer for periodic transmissions (1..8). If zero then normal injection",
      .bit_width =   4 },
    { .name = "res4",
      .help = "Reserved",
      .bit_width =   6 },
    { .name = "dp",
      .help = "Drop precedence level after policing",
      .bit_width =   1 },
    { .name = "pop-cnt",
      .help = "Number of VLAN tags that must be popped",
      .bit_width =   2 },
    { .name = "cpuq",
      .help = "CPU extraction queue mask",
      .bit_width =   8 },
    { .name = "qos-class",
      .help = "Classified QoS class",
      .bit_width =   3 },
    { .name = "tag-type",
      .help = "Tag information's associated Tag Protocol Identifier (TPID)",
      .bit_width =   1 },
    { .name = "pcp",
      .help = "Classified PCP",
      .bit_width =   3 },
    { .name = "dei",
      .help = "Classified DEI",
      .bit_width =   1 },
    { .name = "vid",
      .help = "Classified VID",
      .bit_width =  12 },
};

hdr_t HDR_IFH_OC1 = {
    .name = "ifh-oc1",
    .help = "Injection Frame Header for Ocelot1",
    .fields = IFH_OC1_FIELDS,
    .fields_size = sizeof(IFH_OC1_FIELDS) / sizeof(IFH_OC1_FIELDS[0]),
};

field_t EFH_OC1_FIELDS[] = {
    { .name = "res1",
      .help = "Reserved",
      .bit_width =   1 },
    { .name = "rew-mac",
      .help = "Replace SMAC address.",
      .bit_width =   1 },
    { .name = "rew-op",
      .help = "Rewriter operation command.",
      .bit_width =   9 },
    { .name = "rew-val",
      .help = "Receive time stamp",
      .bit_width =  32 },
    { .name = "llen",
      .help = "Frame length in bytes: 60 * WLEN + LLEN - 80",
      .bit_width =   6 },
    { .name = "wlen",
      .help = "See LLEN",
      .bit_width =   8 },
    { .name = "res2",
      .help = "Reserved",
      .bit_width =  24 },
    { .name = "src-port",
      .help = "The port number where the frame was injected (0-12)",
      .bit_width =   4 },
    { .name = "acl-id",
      .help = "The combined ACL_ID action of the rules in IS2",
      .bit_width =   6 },
    { .name = "res3",
      .help = "Reserved",
      .bit_width =   1 },
    { .name = "sflow-id",
      .help = "sFlow sampling ID",
      .bit_width =   4 },
    { .name = "acl-hit",
      .help = "Set if frame has hit a rule in IS2",
      .bit_width =   1 },
    { .name = "dp",
      .help = "Drop precedence level after policing",
      .bit_width =   1 },
    { .name = "lrn-flags",
      .help = "MAC address learning action",
      .bit_width =   2 },
    { .name = "cpuq",
      .help = "CPU extraction queue mask",
      .bit_width =   8 },
    { .name = "qos-class",
      .help = "Classified QoS class",
      .bit_width =   3 },
    { .name = "tag-type",
      .help = "Tag information's associated Tag Protocol Identifier (TPID)",
      .bit_width =   1 },
    { .name = "pcp",
      .help = "Classified PCP",
      .bit_width =   3 },
    { .name = "dei",
      .help = "Classified DEI",
      .bit_width =   1 },
    { .name = "vid",
      .help = "Classified VID",
      .bit_width =  12 },
};

hdr_t HDR_EFH_OC1 = {
    .name = "efh-oc1",
    .help = "Extraction Frame Header for Ocelot1",
    .fields = EFH_OC1_FIELDS,
    .fields_size = sizeof(EFH_OC1_FIELDS) / sizeof(EFH_OC1_FIELDS[0]),
};

void ifh_init() {
    def_offset(&HDR_SP_OC1);
    def_val(&HDR_SP_OC1, "et",   "0x8880");
    def_val(&HDR_SP_OC1, "id",   "0x000a");

    def_offset(&HDR_LP_OC1);
    def_val(&HDR_LP_OC1, "dmac", "ff:ff:ff:ff:ff:ff");
    def_val(&HDR_LP_OC1, "smac", "ff:ff:ff:ff:ff:ff");
    def_val(&HDR_LP_OC1, "et",   "0x8880");
    def_val(&HDR_LP_OC1, "id",   "0x000a");

    def_offset(&HDR_IFH_OC1);
    def_offset(&HDR_EFH_OC1);

    hdr_tmpls[HDR_TMPL_SP_OC1] = &HDR_SP_OC1;
    hdr_tmpls[HDR_TMPL_LP_OC1] = &HDR_LP_OC1;
    hdr_tmpls[HDR_TMPL_IFH_OC1] = &HDR_IFH_OC1;
    hdr_tmpls[HDR_TMPL_EFH_OC1] = &HDR_EFH_OC1;
}

void ifh_uninit() {
    uninit_frame_data(&HDR_SP_OC1);
    uninit_frame_data(&HDR_LP_OC1);
    uninit_frame_data(&HDR_IFH_OC1);
    uninit_frame_data(&HDR_EFH_OC1);

    hdr_tmpls[HDR_TMPL_SP_OC1] = 0;
    hdr_tmpls[HDR_TMPL_LP_OC1] = 0;
    hdr_tmpls[HDR_TMPL_IFH_OC1] = 0;
    hdr_tmpls[HDR_TMPL_EFH_OC1] = 0;
}
