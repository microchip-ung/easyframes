#include <stdio.h>
#include "ef.h"

static field_t SP_OC1_FIELDS[] = {
    { .name = "et",
      .help = "Ethertype for short prefix. Defaults to 0x8880",
      .bit_width =  16 },
    { .name = "id",
      .help = "Id for short prefix. Defaults to 0x000a",
      .bit_width =  16 },
};

static hdr_t HDR_SP_OC1 = {
    .name = "sp-oc1",
    .help = "Short prefix for injection and extraction of frames for Ocelot1",
    .fields = SP_OC1_FIELDS,
    .fields_size = sizeof(SP_OC1_FIELDS) / sizeof(SP_OC1_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t LP_OC1_FIELDS[] = {
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

static hdr_t HDR_LP_OC1 = {
    .name = "lp-oc1",
    .help = "Long prefix for injection and extraction of frames for Ocelot1",
    .fields = LP_OC1_FIELDS,
    .fields_size = sizeof(LP_OC1_FIELDS) / sizeof(LP_OC1_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t IFH_OC1_FIELDS[] = {
    { .name = "bypass",
      .help = "Skip analyzer processing",
      .bit_width =   1 },

    /* The following fields are valid when BYPASS = 1.
       All fields are prefixed with "b1-" */
    { .name = "b1-rew-mac",
      .help = "Replace SMAC address",
      .bit_width =   1 },
    { .name = "b1-rew-op",
      .help = "Rewriter operation command",
      .bit_width =   9 },

    /* The following fields are valid when BYPASS = 0.
       All fields are prefixed with "b0-" */
    { .name = "b0-masq",
      .help = "Enable masquerading",
      .bit_offset =  1,
      .bit_width =   1 },
    { .name = "b0-masq-port",
      .help = "Masquerading port",
      .bit_offset =  2,
      .bit_width =   4 },

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

static hdr_t HDR_IFH_OC1 = {
    .name = "ifh-oc1",
    .help = "Injection Frame Header for Ocelot1",
    .fields = IFH_OC1_FIELDS,
    .fields_size = sizeof(IFH_OC1_FIELDS) / sizeof(IFH_OC1_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t EFH_OC1_FIELDS[] = {
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
      .bit_width =  14 },
    { .name = "isdx",
      .help = "Classified ISDX",
      .bit_width =  10 },
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

static hdr_t HDR_EFH_OC1 = {
    .name = "efh-oc1",
    .help = "Extraction Frame Header for Ocelot1",
    .fields = EFH_OC1_FIELDS,
    .fields_size = sizeof(EFH_OC1_FIELDS) / sizeof(EFH_OC1_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t SP_JR2_FIELDS[] = {
    { .name = "dmac",
      .help = "Destination MAC address. Defaults to ff:ff:ff:ff:ff:ff",
      .bit_width =  48 },
    { .name = "smac",
      .help = "Source MAC address. Defaults to ff:ff:ff:ff:ff:ff",
      .bit_width =  48 },
    { .name = "et",
      .help = "Ethertype for short prefix. Defaults to 0x8880",
      .bit_width =  16 },
    { .name = "id",
      .help = "Id for short prefix. Defaults to 0x0009",
      .bit_width =  16 },
};

static hdr_t HDR_SP_JR2 = {
    .name = "sp-jr2",
    .help = "Short prefix for injection and extraction of frames for Jaguar2",
    .fields = SP_JR2_FIELDS,
    .fields_size = sizeof(SP_JR2_FIELDS) / sizeof(SP_JR2_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t LP_JR2_FIELDS[] = {
    { .name = "dmac",
      .help = "Destination MAC address. Defaults to ff:ff:ff:ff:ff:ff",
      .bit_width =  48 },
    { .name = "smac",
      .help = "Source MAC address. Defaults to ff:ff:ff:ff:ff:ff",
      .bit_width =  48 },
    { .name = "tpid",
      .help = "Ethertype for VLAN header. Defaults to 0x8100",
      .bit_width =  16 },
    { .name = "pcp",
      .help = "Priority Code Point",
      .bit_width =   3 },
    { .name = "dei",
      .help = "Drop Elegible Indicator",
      .bit_width =   1 },
    { .name = "vid",
      .help = "VLAN Identifier. Defaults to 1",
      .bit_width =  12 },
    { .name = "et",
      .help = "Ethertype for long prefix. Defaults to 0x8880",
      .bit_width =  16 },
    { .name = "id",
      .help = "Id for long prefix. Defaults to 0x0009",
      .bit_width =  16 },
};

static hdr_t HDR_LP_JR2 = {
    .name = "lp-jr2",
    .help = "Long prefix for injection and extraction of frames for Jaguar2",
    .fields = LP_JR2_FIELDS,
    .fields_size = sizeof(LP_JR2_FIELDS) / sizeof(LP_JR2_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t IFH_JR2_FIELDS[] = {
    { .name = "ts",
      .help = "Arrival time stamp",
      .bit_width =  32 },

    /* DST when FWD.DST_MODE is ENCAP.
       All fields are prefixed with "de-" */
    { .name = "de-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   2 },
    { .name = "de-rt-fwd",
      .help = "Update IP4 TTL and chksum/IP6 Hopcnt",
      .bit_width =   1 },
    { .name = "de-swap-mac",
      .help = "Instruct rewriter to swap MAC addresses",
      .bit_width =   1 },
    { .name = "de-tag-tpid",
      .help = "Tag protocol IDs",
      .bit_width =   2 },
    { .name = "de-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_width =   2 },
    { .name = "de-gen-idx",
      .help = "Generic index. VSI when GEN_IDX_MODE = 1",
      .bit_width =  10 },
    { .name = "de-gen-idx-mode",
      .help = "Generic index mode. 0: Reserved. 1: VSI",
      .bit_width =   1 },
    { .name = "de-prot-active",
      .help = "Protect is active",
      .bit_width =   1 },
    { .name = "de-pdu-w16-offset",
      .help = "PDU WORD16 (= 2 bytes) offset from W16_POP_CNT to Protocol data unit (PDU)",
      .bit_width =   6 },
    { .name = "de-pdu-type",
      .help = "PDU type used to handle OAM, PTP and SAT",
      .bit_width =   3 },
    { .name = "de-cl-rslt",
      .help = "Classified MATCH_ID combined from VCAP CLM and VCAP IS2.",
      .bit_width =  16 },
    { .name = "de-mpls-ttl",
      .help = "TTL value for possible use in MPLS label",
      .bit_width =   8 },
    { .name = "de-mpls-sbit",
      .help = "SBIT of last popped MPLS label for possible use in MPLS label",
      .bit_width =   1 },
    { .name = "de-mpls-tc",
      .help = "TC value for possible use in MPLS label",
      .bit_width =   3 },
    { .name = "de-type-after-pop",
      .help = "Type after pop",
      .bit_width =   2 },
    { .name = "de-w16-pop-cnt",
      .help = "Number of WORD16 (= 2 bytes) to be popped by rewriter",
      .bit_width =   5 },

    /* DST when FWD.DST_MODE is INJECT.
       All fields are prefixed with "di-" */
    { .name = "di-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 32,
      .bit_width =  11 },
    { .name = "di-dst-port-mask",
      .help = "Destination port mask. (only used for injection)",
      .bit_offset = 43,
      .bit_width =  53 },

    /* DST when FWD.DST_MODE is L3UC (only used for extraction).
       All fields are prefixed with "du-" */
    { .name = "du-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 32,
      .bit_width =   9 },
    { .name = "du-erleg",
      .help = "Egress router leg for unicast",
      .bit_offset = 41,
      .bit_width =   7 },
    { .name = "du-next-hop-dmac",
      .help = "Next hop DMAC. Only used for unicast routing",
      .bit_offset = 48,
      .bit_width =  48 },

    /* DST when FWD.DST_MODE is L3MC (only used for extraction).
       All fields are prefixed with "dm-" */
    { .name = "dm-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 32,
      .bit_width =  40 },
    { .name = "dm-l3mc-grp-idx",
      .help = "IP multicast group used for L3 multicast copies",
      .bit_offset = 72,
      .bit_width =  10 },
    { .name = "dm-erleg",
      .help = "Egress router leg for multicast",
      .bit_offset = 82,
      .bit_width =   7 },
    { .name = "dm-copy-cnt",
      .help = "Number of multicast routed copies. Only used for multicast routing",
      .bit_offset = 89,
      .bit_width =   7 },

    /* VSTAX header.
       All fields are prefixed with "v-" */
    { .name = "v-rsv1",
      .help = "Reserved field. Must be 1",
      .bit_width =   1 },

    /* VSTAX MISC when ANA_AC:PS_COMMON.VSTAX2_MISC_ISDX_ENA=0.
       All fields are prefixed with "vm0-" */
    { .name = "vm0-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =  11 },
    { .name = "vm0-ac",
      .help = "GLAG aggregation code",
      .bit_width =   4 },

    /* VSTAX MISC when ANA_AC:PS_COMMON.VSTAX2_MISC_ISDX_ENA=1.
       All fields are prefixed with "vm1-" */
    { .name = "vm1-cosid",
      .help = "Class of service",
      .bit_offset =  97,
      .bit_width =    3 },
    { .name = "vm1-isdx",
      .help = "Ingress service index",
      .bit_offset = 100,
      .bit_width =   12 },

    { .name = "v-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_width =   2 },

    /* VSTAX QOS.
       All fields are prefixed with "vq-" */
    { .name = "vq-cl-dp",
      .help = "Classified drop precedence level",
      .bit_width =   2 },
    { .name = "vq-sp",
      .help = "Super priority",
      .bit_width =   1 },
    { .name = "vq-cl-qos",
      .help = "Classified quality of service value (internal priority)",
      .bit_width =   3 },
    { .name = "vq-ingr-drop-mode",
      .help = "Congestion management information",
      .bit_width =   1 },

    { .name = "v-rsv3",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },

    /* VSTAX GENERAL.
       All fields are prefixed with "vg-" */
    { .name = "vg-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "vg-ttl",
      .help = "Time to live",
      .bit_width =   5 },
    { .name = "vg-lrn-mode",
      .help = "Learning mode",
      .bit_width =   1 },
    { .name = "vg-fwd-mode",
      .help = "Forward mode",
      .bit_width =   3 },

    { .name = "v-rsv4",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_LOGICAL.
       All fields are prefixed with "vdl-" */
    { .name = "vdl-dst-port-type",
      .help = "Destination port type",
      .bit_width =   1 },
    { .name = "vdl-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_width =   5 },
    { .name = "vdl-dst-pn",
      .help = "Logical destination port at unit identified by dst_upsid",
      .bit_width =   5 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_PHYSICAL.
       All fields are prefixed with "vdp-" */
    { .name = "vdp-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 133,
      .bit_width =    1 },
    { .name = "vdp-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_offset = 134,
      .bit_width =    5 },
    { .name = "vdp-dst-pn",
      .help = "Physical destination port at unit identified by dst_upsid",
      .bit_offset = 139,
      .bit_width =    5 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_MULTICAST.
       All fields are prefixed with "vdm-" */
    { .name = "vdm-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 133,
      .bit_width =    1 },
    { .name = "vdm-mc-idx",
      .help = "Forward to ports part of this multicast group index",
      .bit_offset = 134,
      .bit_width =   10 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_GCPU_UPS.
       All fields are prefixed with "vdu-" */
    { .name = "vdu-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 133,
      .bit_width =    1 },
    { .name = "vdu-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_offset = 134,
      .bit_width =    5 },
    { .name = "vdu-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_offset = 139,
      .bit_width =    1 },
    { .name = "vdu-dst-pn",
      .help = "CPU destination port at unit identified by dst_upsid",
      .bit_offset = 140,
      .bit_width =    4 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_GCPU_ALL.
       All fields are prefixed with "vda-" */
    { .name = "vda-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 133,
      .bit_width =    1 },
    { .name = "vda-ttl-keep",
      .help = "Special TTL handling used for neighbor discovery",
      .bit_offset = 134,
      .bit_width =    1 },
    { .name = "vda-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_offset = 135,
      .bit_width =    5 },
    { .name = "vda-dst-pn",
      .help = "CPU destination port at unit identified by dst_upsid",
      .bit_offset = 140,
      .bit_width =    4 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_LOOKUP or FWD_GMIRROR.
       All fields are prefixed with "vdg-" */
    { .name = "vdg-rew-cmd",
      .help = "VCAP IS2 action REW_CMD",
      .bit_offset = 133,
      .bit_width =   11 },

    /* VSTAX TAG.
       All fields are prefixed with "vt-" */
    { .name = "vt-cl-pcp",
      .help = "Classified priority code point value",
      .bit_width =   3 },
    { .name = "vt-cl-dei",
      .help = "Classified drop eligible indicator value",
      .bit_width =   1 },
    { .name = "vt-cl-vid",
      .help = "Classified VID",
      .bit_width =  12 },
    { .name = "vt-was-tagged",
      .help = "If set, frame was VLAN-tagged at reception",
      .bit_width =   1 },
    { .name = "vt-tag-type",
      .help = "Tag type",
      .bit_width =   1 },
    { .name = "vt-ingr-port-type",
      .help = "Ingress port type",
      .bit_width =   2 },

    /* VSTAX SRC.
       All fields are prefixed with "vs-" */
    { .name = "vs-src-port-type",
      .help = "Source port type",
      .bit_width =   1 },
    { .name = "vs-src-addr-mode",
      .help = "Source address mode",
      .bit_width =   1 },

    /* VSTAX SRC when SRC_PORT_TYPE is 1 and SRC_ADDR_MODE is 0.
       All fields are prefixed with "vs10-" */
    { .name = "vs10-src-upsid",
      .help = "ID of stack unit port set, where the frame was initially received",
      .bit_width =   5 },
    { .name = "vs10-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "vs10-src-intpn",
      .help = "Internal port number",
      .bit_width =   4 },

    /* VSTAX SRC when SRC_PORT_TYPE is 0 and SRC_ADDR_MODE is 0.
       All fields are prefixed with "vs00-" */
    { .name = "vs00-src-upsid",
      .help = "ID of stack unit port set, where the frame was initially received",
      .bit_offset = 166,
      .bit_width =    5 },
    { .name = "vs00-src-upspn",
      .help = "Logical port number of the port, where the frame was initially received",
      .bit_offset = 171,
      .bit_width =    5 },

    /* VSTAX SRC when SRC_PORT_TYPE is 0 and SRC_ADDR_MODE is 1.
       All fields are prefixed with "vs01-" */
    { .name = "vs01-src-glagid",
      .help = "ID of the GLAG",
      .bit_offset = 166,
      .bit_width =   10 },

    /* FWD header.
       All fields are prefixed with "f-" */
    { .name = "f-afi-inj",
      .help = "Injected into AFI",
      .bit_width =   1 },
    { .name = "f-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "f-es0-isdx-key-ena",
      .help = "Controls use of ISDX in ES0 key",
      .bit_width =   1 },
    { .name = "f-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "f-vstax-avail",
      .help = "True if VSTAX section is valid",
      .bit_width =   1 },
    { .name = "f-update-fcs",
      .help = "Force update of FCS",
      .bit_width =   1 },
    { .name = "f-rsv3",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "f-dst-mode",
      .help = "Controls format of IFH.DST",
      .bit_width =   3 },
    { .name = "f-sflow-marking",
      .help = "Frame forwarded to CPU due to sFlow sampling",
      .bit_width =   1 },
    { .name = "f-aged",
      .help = "Must be set to 0. Set if frame is aged by QSYS",
      .bit_width =   1 },
    { .name = "f-rx-mirror",
      .help = "Signals that the frame is Rx mirrored",
      .bit_width =   1 },
    { .name = "f-mirror-probe",
      .help = "Signals mirror probe for mirrored traffic",
      .bit_width =   2 },
    { .name = "f-src-port",
      .help = "Physical source port number",
      .bit_width =   6 },
    { .name = "f-do-not-rew",
      .help = "Prevents the rewriter from making any changes of frames",
      .bit_width =   1 },

    /* MISC header.
       All fields are prefixed with "m-" */
    { .name = "m-pipeline-act",
      .help = "Pipeline action",
      .bit_width =    3 },
    { .name = "m-pipeline-pt",
      .help = "Pipeline point",
      .bit_width =    5 },
    { .name = "m-cpu-mask",
      .help = "CPU extraction queue mask",
      .bit_width =    8 },

    /* TAGGING header.
       All fields are prefixed with "t-" */
    { .name = "t-pop-cnt",
      .help = "Number of VLAN tags popped",
      .bit_width =   2 },

    /* QOS header.
       All fields are prefixed with "q-" */
    { .name = "q-transp-dscp",
      .help = "Prevents rewriter from remapping DSCP values of frames",
      .bit_width =   1 },
    { .name = "q-update-dscp",
      .help = "Causes rewriter to update the DSCP value with IFH.QOS.DSCP",
      .bit_width =   1 },
    { .name = "q-dscp",
      .help = "DSCP value",
      .bit_width =   6 },
};

static hdr_t HDR_IFH_JR2 = {
    .name = "ifh-jr2",
    .help = "Internal Frame Header for Jaguar2",
    .fields = IFH_JR2_FIELDS,
    .fields_size = sizeof(IFH_JR2_FIELDS) / sizeof(IFH_JR2_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t IFH_FA_FIELDS[] = {
    { .name = "rsv",
      .help = "Reserved",
      .bit_width =  16 },
    { .name = "ts",
      .help = "Arrival time stamp",
      .bit_width =  40 },

    /* DST when FWD.DST_MODE is ENCAP.
       All fields are prefixed with "de-" */
    { .name = "de-rleg-mode",
      .help = "RLEG mode",
      .bit_width =   2 },
    { .name = "de-rleg",
      .help = "RLEG value",
      .bit_width =  10 },
    { .name = "de-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "de-rt-fwd",
      .help = "Router forward flag",
      .bit_width =   1 },
    { .name = "de-swap-mac",
      .help = "Instruct rewriter to swap MAC addresses",
      .bit_width =   1 },
    { .name = "de-tag-tpid",
      .help = "Tag protocol IDs",
      .bit_width =   2 },
    { .name = "de-gvid",
      .help = "Generic VID",
      .bit_width =  12 },
    { .name = "de-xvid-ext",
      .help = "Classified VID extension",
      .bit_width =   1 },
    { .name = "de-prot-active",
      .help = "Protect is active",
      .bit_width =   1 },
    { .name = "de-pdu-w16-offset",
      .help = "PDU WORD16 (= 2 bytes) offset from W16_POP_CNT to Protocol data unit (PDU)",
      .bit_width =   6 },
    { .name = "de-pdu-type",
      .help = "PDU type used to handle OAM, PTP and SAT",
      .bit_width =   4 },
    { .name = "de-cl-rslt",
      .help = "Classified MATCH_ID combined from VCAP CLM and VCAP IS2.",
      .bit_width =  16 },
    { .name = "de-mpls-ttl",
      .help = "TTL value for possible use in MPLS label",
      .bit_width =   9 },
    { .name = "de-mpls-sbit",
      .help = "SBIT of last popped MPLS label for possible use in MPLS label",
      .bit_width =   1 },
    { .name = "de-mpls-tc",
      .help = "TC value for possible use in MPLS label",
      .bit_width =   3 },
    { .name = "de-action-after-pop",
      .help = "Action after pop",
      .bit_width =   1 },
    { .name = "de-type-after-pop",
      .help = "Type after pop",
      .bit_width =   2 },
    { .name = "de-w16-pop-cnt",
      .help = "Number of WORD16 (= 2 bytes) to be popped by rewriter",
      .bit_width =   6 },

    /* DST when FWD.DST_MODE is L3UC (only used for extraction).
       All fields are prefixed with "du-" */
    { .name = "du-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 56,
      .bit_width =  22 },
    { .name = "du-erleg",
      .help = "Egress router leg for unicast",
      .bit_offset = 78,
      .bit_width =   9 },
    { .name = "du-next-hop-dmac",
      .help = "Next hop DMAC. Only used for unicast routing",
      .bit_offset = 87,
      .bit_width =  48 },

    /* DST when FWD.DST_MODE is L3MC (only used for extraction).
       All fields are prefixed with "dm-" */
    { .name = "dm-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset =  56,
      .bit_width =   50 },
    { .name = "dm-l3mc-grp-idx",
      .help = "IP multicast group used for L3 multicast copies",
      .bit_offset = 106,
      .bit_width =   11 },
    { .name = "dm-erleg",
      .help = "Egress router leg for multicast",
      .bit_offset = 117,
      .bit_width =    9 },
    { .name = "dm-copy-cnt",
      .help = "Number of multicast routed copies. Only used for multicast routing",
      .bit_offset = 126,
      .bit_width =    9 },

    /* VSTAX header.
       All fields are prefixed with "v-" */
    { .name = "v-rsv1",
      .help = "Reserved field. Must be 1",
      .bit_width =   1 },

    /* VSTAX MISC when ANA_AC:PS_COMMON.VSTAX2_MISC_ISDX_ENA=0.
       All fields are prefixed with "vm0-" */
    { .name = "vm0-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =  11 },
    { .name = "vm0-ac",
      .help = "GLAG aggregation code",
      .bit_width =   4 },

    /* VSTAX MISC when ANA_AC:PS_COMMON.VSTAX2_MISC_ISDX_ENA=1.
       All fields are prefixed with "vm1-" */
    { .name = "vm1-cosid",
      .help = "Class of service",
      .bit_offset = 136,
      .bit_width =    3 },
    { .name = "vm1-isdx",
      .help = "Ingress service index",
      .bit_offset = 139,
      .bit_width =   12 },

    { .name = "v-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_width =   2 },

    /* VSTAX QOS.
       All fields are prefixed with "vq-" */
    { .name = "vq-cl-dp",
      .help = "Classified drop precedence level",
      .bit_width =   2 },
    { .name = "vq-sp",
      .help = "Super priority",
      .bit_width =   1 },
    { .name = "vq-cl-qos",
      .help = "Classified quality of service value (internal priority)",
      .bit_width =   3 },
    { .name = "vq-ingr-drop-mode",
      .help = "Congestion management information",
      .bit_width =   1 },

    { .name = "v-rsv3",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },

    /* VSTAX GENERAL.
       All fields are prefixed with "vg-" */
    { .name = "vg-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "vg-ttl",
      .help = "Time to live",
      .bit_width =   5 },
    { .name = "vg-lrn-mode",
      .help = "Learning mode",
      .bit_width =   1 },
    { .name = "vg-fwd-mode",
      .help = "Forward mode",
      .bit_width =   3 },

    { .name = "v-rsv4",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_LOGICAL.
       All fields are prefixed with "vdl-" */
    { .name = "vdl-dst-port-type",
      .help = "Destination port type",
      .bit_width =   1 },
    { .name = "vdl-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_width =   5 },
    { .name = "vdl-dst-pn",
      .help = "Logical destination port at unit identified by dst_upsid",
      .bit_width =   5 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_PHYSICAL.
       All fields are prefixed with "vdp-" */
    { .name = "vdp-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 172,
      .bit_width =    1 },
    { .name = "vdp-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_offset = 173,
      .bit_width =    5 },
    { .name = "vdp-dst-pn",
      .help = "Physical destination port at unit identified by dst_upsid",
      .bit_offset = 178,
      .bit_width =    5 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_MULTICAST.
       All fields are prefixed with "vdm-" */
    { .name = "vdm-mc-idx",
      .help = "Forward to ports part of this multicast group index",
      .bit_offset = 172,
      .bit_width =   11 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_GCPU_UPS.
       All fields are prefixed with "vdu-" */
    { .name = "vdu-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 172,
      .bit_width =    1 },
    { .name = "vdu-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_offset = 173,
      .bit_width =    5 },
    { .name = "vdu-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_offset = 178,
      .bit_width =    1 },
    { .name = "vdu-dst-pn",
      .help = "CPU destination port at unit identified by dst_upsid",
      .bit_offset = 179,
      .bit_width =    4 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_GCPU_ALL.
       All fields are prefixed with "vda-" */
    { .name = "vda-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 172,
      .bit_width =    1 },
    { .name = "vda-ttl-keep",
      .help = "Special TTL handling used for neighbor discovery",
      .bit_offset = 173,
      .bit_width =    1 },
    { .name = "vda-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_offset = 174,
      .bit_width =    5 },
    { .name = "vda-dst-pn",
      .help = "CPU destination port at unit identified by dst_upsid",
      .bit_offset = 179,
      .bit_width =    4 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_LOOKUP or FWD_GMIRROR.
       All fields are prefixed with "vdg-" */
    { .name = "vdg-rew-cmd",
      .help = "VCAP IS2 action REW_CMD",
      .bit_offset = 172,
      .bit_width =   11 },

    /* VSTAX TAG.
       All fields are prefixed with "vt-" */
    { .name = "vt-cl-pcp",
      .help = "Classified priority code point value",
      .bit_width =   3 },
    { .name = "vt-cl-dei",
      .help = "Classified drop eligible indicator value",
      .bit_width =   1 },
    { .name = "vt-cl-vid",
      .help = "Classified VID",
      .bit_width =  12 },
    { .name = "vt-was-tagged",
      .help = "If set, frame was VLAN-tagged at reception",
      .bit_width =   1 },
    { .name = "vt-tag-type",
      .help = "Tag type",
      .bit_width =   1 },
    { .name = "vt-ingr-port-type",
      .help = "Ingress port type",
      .bit_width =   2 },

    /* VSTAX SRC.
       All fields are prefixed with "vs-" */
    { .name = "vs-src-port-type",
      .help = "Source port type",
      .bit_width =   1 },
    { .name = "vs-src-addr-mode",
      .help = "Source address mode",
      .bit_width =   1 },

    /* VSTAX SRC when SRC_PORT_TYPE is 1 and SRC_ADDR_MODE is 0.
       All fields are prefixed with "vs10-" */
    { .name = "vs10-src-upsid",
      .help = "ID of stack unit port set, where the frame was initially received",
      .bit_width =   5 },
    { .name = "vs10-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "vs10-src-intpn",
      .help = "Internal port number",
      .bit_width =   4 },

    /* VSTAX SRC when SRC_PORT_TYPE is 0 and SRC_ADDR_MODE is 0.
       All fields are prefixed with "vs00-" */
    { .name = "vs00-src-upsid",
      .help = "ID of stack unit port set, where the frame was initially received",
      .bit_offset = 205,
      .bit_width =    5 },
    { .name = "vs00-src-upspn",
      .help = "Logical port number of the port, where the frame was initially received",
      .bit_offset = 210,
      .bit_width =    5 },

    /* VSTAX SRC when SRC_PORT_TYPE is 0 and SRC_ADDR_MODE is 1.
       All fields are prefixed with "vs01-" */
    { .name = "vs01-src-glagid",
      .help = "ID of the GLAG",
      .bit_offset = 205,
      .bit_width =   10 },

    /* FWD header.
       All fields are prefixed with "f-" */
    { .name = "f-afi-inj",
      .help = "Injected into AFI",
      .bit_width =   1 },
    { .name = "f-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "f-es0-isdx-key-ena",
      .help = "Controls use of ISDX in ES0 key",
      .bit_width =   1 },
    { .name = "f-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "f-vstax-avail",
      .help = "True if VSTAX section is valid",
      .bit_width =   1 },
    { .name = "f-update-fcs",
      .help = "Force update of FCS",
      .bit_width =   1 },
    { .name = "f-rsv3",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "f-dst-mode",
      .help = "Controls format of IFH.DST",
      .bit_width =   2 },
    { .name = "f-sflow-id",
      .help = "sFlow sampling ID",
      .bit_width =   7 },
    { .name = "f-aged",
      .help = "Must be set to 0. Set if frame is aged by QSYS",
      .bit_width =   1 },
    { .name = "f-rx-mirror",
      .help = "Signals that the frame is Rx mirrored",
      .bit_width =   1 },
    { .name = "f-mirror-probe",
      .help = "Signals mirror probe for mirrored traffic",
      .bit_width =   2 },
    { .name = "f-src-port",
      .help = "Physical source port number",
      .bit_width =   7 },
    { .name = "f-do-not-rew",
      .help = "Prevents the rewriter from making any changes of frames",
      .bit_width =   1 },

    /* MISC header.
       All fields are prefixed with "m-" */
    { .name = "m-pipeline-act",
      .help = "Pipeline action",
      .bit_width =    3 },
    { .name = "m-pipeline-pt",
      .help = "Pipeline point",
      .bit_width =    5 },
    { .name = "m-cpu-mask",
      .help = "CPU extraction queue mask",
      .bit_width =    8 },

    /* TAGGING header.
       All fields are prefixed with "t-" */
    { .name = "t-pop-cnt",
      .help = "Number of VLAN tags popped",
      .bit_width =   2 },
    { .name = "t-push-cnt",
      .help = "Number of VLAN tags pushed",
      .bit_width =   2 },
    { .name = "t-rtag-etag-avail",
      .help = "True if frame contains R-tag or E-tag",
      .bit_width =   1 },
    { .name = "t-seq-no",
      .help = "802.1CB sequence number",
      .bit_width =  16 },

    /* QOS header.
       All fields are prefixed with "q-" */
    { .name = "q-transp-dscp",
      .help = "Prevents rewriter from remapping DSCP values of frames",
      .bit_width =   1 },
    { .name = "q-update-dscp",
      .help = "Causes rewriter to update the DSCP value with IFH.QOS.DSCP",
      .bit_width =   1 },
    { .name = "q-dscp",
      .help = "DSCP value",
      .bit_width =   6 },
};

static hdr_t HDR_IFH_FA = {
    .name = "ifh-fa",
    .help = "Internal Frame Header for FireAnt",
    .fields = IFH_FA_FIELDS,
    .fields_size = sizeof(IFH_FA_FIELDS) / sizeof(IFH_FA_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t IFH_LA_FIELDS[] = {
    { .name = "rsv",
      .help = "Reserved - IFH must be 288 bits - 36 bytes",
      .bit_width =  9 },

    { .name = "rb-cmd",
      .help = "RedBox CMD",
      .bit_width =  5 },
    { .name = "rb-src",
      .help = "RedBox CMD",
      .bit_width =  1 },
    { .name = "rb-tag",
      .help = "RedBox TAG",
      .bit_width =  1 },

    { .name = "ts",
      .help = "Arrival time stamp",
      .bit_width =  40 },

    { .name = "lbk-fill",
      .help = "Fill bits. LBK must be 40 bits",
      .bit_offset = 16,
      .bit_width =  26 },
    { .name = "lbk-cos-nxt",
      .help = "LBK_COS_NXT_SEL",
      .bit_offset = 42,
      .bit_width =  2 },
    { .name = "lbk-cos-mask",
      .help = "LBK_COS_MASK",
      .bit_offset = 44,
      .bit_width =  8 },
    { .name = "lbk-cosid-ena",
      .help = "LBK_CHG_IFH_COSID_ENA",
      .bit_offset = 52,
      .bit_width =  1 },
    { .name = "lbk-tc-ena",
      .help = "LBK_CHG_IFH_TC_ENA",
      .bit_offset = 53,
      .bit_width =  1 },
    { .name = "lbk-pcp-ena",
      .help = "LBK_CHG_IFH_PCP_ENA",
      .bit_offset = 54,
      .bit_width =  1 },
    { .name = "lbk-outer-pcp-ena",
      .help = "LBK_CHG_OUTER_PCP_ENA",
      .bit_offset = 55,
      .bit_width =  1 },

    /* DST when FWD.DST_MODE is ENCAP.
       All fields are prefixed with "de-" */
    { .name = "de-fill",
      .help = "Fill bits. DST be 79 bits",
      .bit_width =  3 },
    { .name = "de-rleg-mode",
      .help = "RLEG mode",
      .bit_width =   2 },
    { .name = "de-rleg",
      .help = "RLEG value",
      .bit_width =  8 },
    { .name = "de-first-copy",
      .help = "IS_FIRST_COPY",
      .bit_width =   1 },
    { .name = "de-rt-fwd",
      .help = "Router forward flag",
      .bit_width =   1 },
    { .name = "de-swap-mac",
      .help = "Instruct rewriter to swap MAC addresses",
      .bit_width =   1 },
    { .name = "de-tag-tpid",
      .help = "Tag protocol IDs",
      .bit_width =   2 },
    { .name = "de-gvid",
      .help = "Generic VID",
      .bit_width =  12 },
    { .name = "de-xvid-ext",
      .help = "Classified VID extension",
      .bit_width =   1 },
    { .name = "de-prot-active",
      .help = "Protect is active",
      .bit_width =   1 },
    { .name = "de-pdu-w16-offset",
      .help = "PDU WORD16 (= 2 bytes) offset from W16_POP_CNT to Protocol data unit (PDU)",
      .bit_width =   6 },
    { .name = "de-pdu-type",
      .help = "PDU type used to handle OAM, PTP and SAT",
      .bit_width =   4 },
    { .name = "de-match-id",
      .help = "Classified MATCH_ID combined from VCAP CLM and VCAP IS2.",
      .bit_width =  16 },
    { .name = "de-mpls-ttl",
      .help = "TTL value for possible use in MPLS label",
      .bit_width =   8 },
    { .name = "de-mpls-sbit",
      .help = "SBIT of last popped MPLS label for possible use in MPLS label",
      .bit_width =   1 },
    { .name = "de-mpls-tc",
      .help = "TC value for possible use in MPLS label",
      .bit_width =   3 },
    { .name = "de-action-after-pop",
      .help = "Action after pop",
      .bit_width =   1 },
    { .name = "de-type-after-pop",
      .help = "Type after pop",
      .bit_width =   2 },
    { .name = "de-w16-pop-cnt",
      .help = "Number of WORD16 (= 2 bytes) to be popped by rewriter",
      .bit_width =   6 },

    /* DST when FWD.DST_MODE is L3UC (only used for extraction).
       All fields are prefixed with "du-" */
    { .name = "du-fill",
      .help = "Fill bits. DST must be 79 bits",
      .bit_offset = 56,
      .bit_width =  24 },
    { .name = "du-erleg",
      .help = "Egress router leg for unicast",
      .bit_offset = 80,
      .bit_width =   7 },
    { .name = "du-next-hop-dmac",
      .help = "Next hop DMAC. Only used for unicast routing",
      .bit_offset = 87,
      .bit_width =  48 },

    /* DST when FWD.DST_MODE is L3MC (only used for extraction).
       All fields are prefixed with "dm-" */
    { .name = "du-fill",
      .help = "Fill bits. DST must be 79 bits",
      .bit_offset = 56,
      .bit_width =  50 },
    { .name = "dm-l3mc-grp-idx",
      .help = "IP multicast group used for L3 multicast copies",
      .bit_offset = 106,
      .bit_width =   11 },
    { .name = "dm-erleg",
      .help = "Egress router leg for multicast",
      .bit_offset = 117,
      .bit_width =    9 },
    { .name = "dm-copy-cnt",
      .help = "Number of multicast routed copies. Only used for multicast routing",
      .bit_offset = 126,
      .bit_width =    9 },

    /* VSTAX header.
       All fields are prefixed with "v-" */
    { .name = "v-rsv1",
      .help = "Reserved field. Must be 1",
      .bit_width =   1 },

    /* VSTAX MISC when ANA_AC:PS_COMMON.VSTAX2_MISC_ISDX_ENA=0.
       All fields are prefixed with "vm0-" */
    { .name = "vm0-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =  11 },
    { .name = "vm0-ac",
      .help = "GLAG aggregation code",
      .bit_width =   4 },

    /* VSTAX MISC when ANA_AC:PS_COMMON.VSTAX2_MISC_ISDX_ENA=1.
       All fields are prefixed with "vm1-" */
    { .name = "vm1-cosid",
      .help = "Class of service",
      .bit_offset = 136,
      .bit_width =    3 },
    { .name = "vm1-isdx",
      .bit_offset = 139,
      .help = "Ingress service index",
      .bit_width =   12 },

    { .name = "v-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_width =   2 },

    /* VSTAX QOS.
       All fields are prefixed with "vq-" */
    { .name = "vq-cl-dp",
      .help = "Classified drop precedence level",
      .bit_width =   2 },
    { .name = "vq-sp",
      .help = "Super priority",
      .bit_width =   1 },
    { .name = "vq-cl-qos",
      .help = "Classified quality of service value (internal priority)",
      .bit_width =   3 },
    { .name = "vq-ingr-drop-mode",
      .help = "Congestion management information",
      .bit_width =   1 },

    { .name = "v-rsv3",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },

    /* VSTAX GENERAL.
       All fields are prefixed with "vg-" */
    { .name = "vg-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "vg-ttl",
      .help = "Time to live",
      .bit_width =   5 },
    { .name = "vg-lrn-mode",
      .help = "Learning mode",
      .bit_width =   1 },
    { .name = "vg-fwd-mode",
      .help = "Forward mode",
      .bit_width =   3 },

    { .name = "v-rsv4",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_LOGICAL.
       All fields are prefixed with "vdl-" */
    { .name = "vdl-dst-port-type",
      .help = "Destination port type",
      .bit_width =   1 },
    { .name = "vdl-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_width =   5 },
    { .name = "vdl-dst-pn",
      .help = "Logical destination port at unit identified by dst_upsid",
      .bit_width =   5 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_PHYSICAL.
       All fields are prefixed with "vdp-" */
    { .name = "vdp-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 172,
      .bit_width =    1 },
    { .name = "vdp-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_offset = 173,
      .bit_width =    5 },
    { .name = "vdp-dst-pn",
      .help = "Physical destination port at unit identified by dst_upsid",
      .bit_offset = 178,
      .bit_width =    5 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_MULTICAST.
       All fields are prefixed with "vdm-" */
    { .name = "vdm-mc-idx",
      .help = "Forward to ports part of this multicast group index",
      .bit_offset = 172,
      .bit_width =   11 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_GCPU_UPS.
       All fields are prefixed with "vdu-" */
    { .name = "vdu-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 172,
      .bit_width =    1 },
    { .name = "vdu-dst-upsid",
      .help = "Destination unit port set ID",
      .bit_offset = 173,
      .bit_width =    5 },
    { .name = "vdu-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_offset = 178,
      .bit_width =    1 },
    { .name = "vdu-dst-pn",
      .help = "CPU destination port at unit identified by dst_upsid",
      .bit_offset = 179,
      .bit_width =    4 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_GCPU_ALL.
       All fields are prefixed with "vda-" */
    { .name = "vda-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_offset = 172,
      .bit_width =    1 },
    { .name = "vda-ttl-keep",
      .help = "Special TTL handling used for neighbor discovery",
      .bit_offset = 173,
      .bit_width =    1 },
    { .name = "vda-rsv2",
      .help = "Reserved field. Must be 0",
      .bit_offset = 174,
      .bit_width =    5 },
    { .name = "vda-dst-pn",
      .help = "CPU destination port at unit identified by dst_upsid",
      .bit_offset = 179,
      .bit_width =    4 },

    /* VSTAX DST when VSTAX.FWD_MODE is FWD_LOOKUP or FWD_GMIRROR.
       All fields are prefixed with "vdg-" */
    { .name = "vdg-rew-cmd",
      .help = "VCAP IS2 action REW_CMD",
      .bit_offset = 172,
      .bit_width =   11 },

    /* VSTAX TAG.
       All fields are prefixed with "vt-" */
    { .name = "vt-cl-pcp",
      .help = "Classified priority code point value",
      .bit_width =   3 },
    { .name = "vt-cl-dei",
      .help = "Classified drop eligible indicator value",
      .bit_width =   1 },
    { .name = "vt-cl-vid",
      .help = "Classified VID",
      .bit_width =  12 },
    { .name = "vt-was-tagged",
      .help = "If set, frame was VLAN-tagged at reception",
      .bit_width =   1 },
    { .name = "vt-tag-type",
      .help = "Tag type",
      .bit_width =   1 },
    { .name = "vt-ingr-port-type",
      .help = "Ingress port type",
      .bit_width =   2 },

    /* VSTAX SRC.
       All fields are prefixed with "vs-" */
    { .name = "vs-src-port-type",
      .help = "Source port type",
      .bit_width =   1 },
    { .name = "vs-src-addr-mode",
      .help = "Source address mode",
      .bit_width =   1 },

    /* VSTAX SRC when SRC_PORT_TYPE is 1 and SRC_ADDR_MODE is 0.
       All fields are prefixed with "vs10-" */
    { .name = "vs10-src-upsid",
      .help = "ID of stack unit port set, where the frame was initially received",
      .bit_width =   5 },
    { .name = "vs10-rsv1",
      .help = "Reserved field. Must be 0",
      .bit_width =   1 },
    { .name = "vs10-src-intpn",
      .help = "Internal port number",
      .bit_width =   4 },

    /* VSTAX SRC when SRC_PORT_TYPE is 0 and SRC_ADDR_MODE is 0.
       All fields are prefixed with "vs00-" */
    { .name = "vs00-src-upsid",
      .help = "ID of stack unit port set, where the frame was initially received",
      .bit_offset = 205,
      .bit_width =    5 },
    { .name = "vs00-src-upspn",
      .help = "Logical port number of the port, where the frame was initially received",
      .bit_offset = 210,
      .bit_width =    5 },

    /* VSTAX SRC when SRC_PORT_TYPE is 0 and SRC_ADDR_MODE is 1.
       All fields are prefixed with "vs01-" */
    { .name = "vs01-src-glagid",
      .help = "ID of the GLAG",
      .bit_offset = 205,
      .bit_width =   10 },

    /* FWD header.
       All fields are prefixed with "f-" */
    { .name = "f-fill",
      .help = "FWD must be 28 bit wide",
      .bit_width =   1 },
    { .name = "f-afi-inj",
      .help = "Injected into AFI",
      .bit_width =   1 },
    { .name = "f-do_lbk",
      .help = "Do LBK field",
      .bit_width =   1 },
    { .name = "f-es0-isdx-key-ena",
      .help = "Controls use of ISDX in ES0 key",
      .bit_width =   1 },
    { .name = "f-ts-mode",
      .help = "TS mode",
      .bit_width =   1 },
    { .name = "f-vstax-avail",
      .help = "True if VSTAX section is valid",
      .bit_width =   1 },
    { .name = "f-update-fcs",
      .help = "Force update of FCS",
      .bit_width =   1 },
    { .name = "f-lrn_all",
      .help = "Learn all field",
      .bit_width =   1 },
    { .name = "f-dst-mode",
      .help = "Controls format of IFH.DST",
      .bit_width =   2 },
    { .name = "f-sflow-id",
      .help = "sFlow sampling ID",
      .bit_width =   7 },
    { .name = "f-aged",
      .help = "Must be set to 0. Set if frame is aged by QSYS",
      .bit_width =   1 },
    { .name = "f-rx-mirror",
      .help = "Signals that the frame is Rx mirrored",
      .bit_width =   1 },
    { .name = "f-mirror-probe",
      .help = "Signals mirror probe for mirrored traffic",
      .bit_width =   2 },
    { .name = "f-src-port",
      .help = "Physical source port number",
      .bit_width =   6 },
    { .name = "f-do-not-rew",
      .help = "Prevents the rewriter from making any changes of frames",
      .bit_width =   1 },

    /* MISC header.
       All fields are prefixed with "m-" */
    { .name = "m-pipeline-act",
      .help = "Pipeline action",
      .bit_width =    3 },
    { .name = "m-pipeline-pt",
      .help = "Pipeline point",
      .bit_width =    5 },
    { .name = "m-inj-dport",
      .help = "Injection destination port",
      .bit_width =    8 },

    /* TAGGING header.
       All fields are prefixed with "t-" */
    { .name = "t-pop-cnt",
      .help = "Number of VLAN tags popped",
      .bit_width =   2 },
    { .name = "t-push-cnt",
      .help = "Number of VLAN tags pushed",
      .bit_width =   2 },
    { .name = "t-rtag-etag-avail",
      .help = "True if frame contains R-tag or E-tag",
      .bit_width =   1 },
    { .name = "t-seq-no",
      .help = "802.1CB sequence number",
      .bit_width =  16 },

    /* QOS header.
       All fields are prefixed with "q-" */
    { .name = "q-transp-dscp",
      .help = "Prevents rewriter from remapping DSCP values of frames",
      .bit_width =   1 },
    { .name = "q-update-dscp",
      .help = "Causes rewriter to update the DSCP value with IFH.QOS.DSCP",
      .bit_width =   1 },
    { .name = "q-dscp",
      .help = "DSCP value",
      .bit_width =   6 },
};

static hdr_t HDR_IFH_LA = {
    .name = "ifh-la",
    .help = "Internal Frame Header for Laguna",
    .fields = IFH_LA_FIELDS,
    .fields_size = sizeof(IFH_LA_FIELDS) / sizeof(IFH_LA_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t IFH_CRCL_FIELDS[] = {
    { .name = "bypass",
      .help = "Skip analyzer processing",
      .bit_width =  1 },
    { .name = "ptp",
      .help = "PTP action",
      .bit_width =  2 },
    { .name = "ptp-id",
      .help = "PTP ID",
      .bit_width =  2 },
    { .name = "dest",
      .help = "Destination port set",
      .bit_width =  27 },
    { .name = "resv",
      .help = "Reserved field",
      .bit_width =  2 },
    { .name = "pop-cnt",
      .help = "VLAN tag pop count",
      .bit_width =  2 },
    { .name = "cpuq",
      .help = "CPU extraction queue mask",
      .bit_width =   8 },
    { .name = "qos-class",
      .help = "Classified QoS class",
      .bit_width =   3 },
    { .name = "tag-type",
      .help = "C-tag (0) or S-tag (1)",
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

static hdr_t HDR_IFH_CRCL = {
    .name = "ifh-crcl",
    .help = "Injection Frame Header for Caracal",
    .fields = IFH_CRCL_FIELDS,
    .fields_size = sizeof(IFH_CRCL_FIELDS) / sizeof(IFH_CRCL_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t EFH_CRCL_FIELDS[] = {
    { .name = "signature",
      .help = "Must be 0xff",
      .bit_width =  8 },
    { .name = "src-port",
      .help = "Source port",
      .bit_width =  5 },
    { .name = "dscp",
      .help = "Classified DSCP",
      .bit_width =  6 },
    { .name = "acl-id",
      .help = "ACL ID",
      .bit_width =  8 },
    { .name = "sflow-id",
      .help = "SFlow sampling ID",
      .bit_width =  5 },
    { .name = "acl-hit",
      .help = "ACL hit flag",
      .bit_width =  1 },
    { .name = "dp",
      .help = "Drop precedence",
      .bit_width =  1 },
    { .name = "lrn-flags",
      .help = "Learn flags",
      .bit_width =  2 },
    { .name = "cpuq",
      .help = "CPU extraction queue mask",
      .bit_width =   8 },
    { .name = "qos-class",
      .help = "Classified QoS class",
      .bit_width =   3 },
    { .name = "tag-type",
      .help = "C-tag (0) or S-tag (1)",
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

static hdr_t HDR_EFH_CRCL = {
    .name = "efh-crcl",
    .help = "Extraction Frame Header for Caracal",
    .fields = EFH_CRCL_FIELDS,
    .fields_size = sizeof(EFH_CRCL_FIELDS) / sizeof(EFH_CRCL_FIELDS[0]),
    .parser = hdr_parse_fields,
};

static field_t IFH_MAS_FIELDS[] = {
    { .name = "ts",
      .help = "Arrival time stamp",
      .bit_width = 32 },
    { .name = "bypass",
      .help = "Skip analyzer processing (injection)",
      .bit_width = 1 },
    { .name = "masq",
      .help = "Enable masquerading (injection)",
      .bit_width = 1 },
    { .name = "masq-port",
      .help = "Masquerading port (injection)",
      .bit_width = 4 },
    { .name = "rsv1",
      .help = "Reserved field (injection)",
      .bit_width = 8 },
    { .name = "len",
      .help = "Length (extraction)",
      .bit_offset = 32,
      .bit_width = 14 },
    { .name = "smallc",
      .help = "Small Cell",
      .bit_width = 2 },
    { .name = "rtag48",
      .help = "R-tag removed",
      .bit_width = 1 },
    { .name = "rtag",
      .help = "R-tag present",
      .bit_width = 1 },
    { .name = "ct",
      .help = "Cut-through",
      .bit_width = 1 },
    { .name = "rew-cmd",
      .help = "Rewriter command",
      .bit_width = 10 },
    { .name = "rew-oam",
      .help = "Rewriter OAM",
      .bit_width = 1 },
    { .name = "pdu-type",
      .help = "PDU type",
      .bit_width = 4 },
    { .name = "fcs-upd",
      .help = "FCS update",
      .bit_width = 1 },
    { .name = "dscp",
      .help = "DSCP",
      .bit_width = 6 },
    { .name = "dp",
      .help = "Drop Precedence",
      .bit_width = 1 },
    { .name = "rte-inb-upd",
      .help = "RTE inbound update",
      .bit_width = 1 },
    { .name = "pop-cnt",
      .help = "VLAN tag pop count",
      .bit_width = 2 },
    { .name = "etype-offs",
      .help = "Number of tags before Ethernet Type",
      .bit_width = 2 },
    { .name = "src-port",
      .help = "Source port",
      .bit_width = 4 },
    { .name = "rsv2",
      .help = "Reserved field",
      .bit_width = 5 },
    { .name = "seq-no",
      .help = "Sequence number",
      .bit_width = 16 },
    { .name = "tag-type",
      .help = "Tag information's associated Tag Protocol Identifier (TPID)",
      .bit_width = 1 },
    { .name = "pcp",
      .help = "Classified PCP",
      .bit_width = 3 },
    { .name = "dei",
      .help = "Classified DEI",
      .bit_width = 1 },
    { .name = "vid",
      .help = "Classified VID",
      .bit_width = 12 },
    { .name = "qos-class",
      .help = "Classified QoS class",
      .bit_width = 3 },
    { .name = "cpuq",
      .help = "CPU extraction queue mask",
      .bit_width = 8 },
    { .name = "lrn-flags",
      .help = "Learn flags",
      .bit_width = 2 },
    { .name = "sflow-id",
      .help = "SFlow sampling ID",
      .bit_width = 4 },
    { .name = "acl-hit",
      .help = "ACL hit flag",
      .bit_width = 1 },
    { .name = "acl-id",
      .help = "ACL ID",
      .bit_width = 6 },
    { .name = "isdx",
      .help = "Classified ISDX",
      .bit_width = 8 },
    { .name = "dest",
      .help = "Destination set",
      .bit_width = 9 },
    { .name = "flood",
      .help = "Storm policer",
      .bit_width = 2 },
    { .name = "seq-op",
      .help = "Sequence operation",
      .bit_width = 2 },
    { .name = "ipv",
      .help = "Internal priority value",
      .bit_width = 3 },
    { .name = "afi",
      .help = "Injected into AFI",
      .bit_width = 1 },
    { .name = "aged",
      .help = "Ageing value",
      .bit_width = 2},
    { .name = "rtp-id",
      .help = "RTP Identifier",
      .bit_width = 10 },
    { .name = "rtp-subid",
      .help = "RTP MRPD flow",
      .bit_width = 1 },
    { .name = "pn-data-status",
      .help = "Profinet data status",
      .bit_width = 8 },
    { .name = "pn-tf-status_zero",
      .help = "Profinet transfer status",
      .bit_width = 1 },
    { .name = "pn-cc",
      .help = "Profinet cycle counter",
      .bit_width = 16 },
    { .name = "rsv3",
      .help = "Reserved field",
      .bit_width = 16 },
};

static hdr_t HDR_IFH_MAS = {
    .name = "ifh-mas",
    .help = "Internal Frame Header for Maserati",
    .fields = IFH_MAS_FIELDS,
    .fields_size = sizeof(IFH_MAS_FIELDS) / sizeof(IFH_MAS_FIELDS[0]),
    .parser = hdr_parse_fields,
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

    def_offset(&HDR_SP_JR2);
    def_val(&HDR_SP_JR2, "dmac", "ff:ff:ff:ff:ff:ff");
    def_val(&HDR_SP_JR2, "smac", "ff:ff:ff:ff:ff:ff");
    def_val(&HDR_SP_JR2, "et",   "0x8880");
    def_val(&HDR_SP_JR2, "id",   "0x0009");

    def_offset(&HDR_LP_JR2);
    def_val(&HDR_LP_JR2, "dmac", "ff:ff:ff:ff:ff:ff");
    def_val(&HDR_LP_JR2, "smac", "ff:ff:ff:ff:ff:ff");
    def_val(&HDR_LP_JR2, "tpid", "0x8100");
    def_val(&HDR_LP_JR2, "vid",  "1");
    def_val(&HDR_LP_JR2, "et",   "0x8880");
    def_val(&HDR_LP_JR2, "id",   "0x0009");

    def_offset(&HDR_IFH_JR2);
    def_val(&HDR_IFH_JR2, "v-rsv1", "1");

    def_offset(&HDR_IFH_FA);
    def_val(&HDR_IFH_FA, "v-rsv1", "1");

    def_offset(&HDR_IFH_CRCL);
    def_offset(&HDR_EFH_CRCL);
    def_val(&HDR_EFH_CRCL, "signature", "0xff");

    def_offset(&HDR_IFH_MAS);
    def_offset(&HDR_IFH_LA);

    hdr_tmpls[HDR_TMPL_SP_OC1] =  &HDR_SP_OC1;
    hdr_tmpls[HDR_TMPL_LP_OC1] =  &HDR_LP_OC1;
    hdr_tmpls[HDR_TMPL_IFH_OC1] = &HDR_IFH_OC1;
    hdr_tmpls[HDR_TMPL_EFH_OC1] = &HDR_EFH_OC1;
    hdr_tmpls[HDR_TMPL_SP_JR2] =  &HDR_SP_JR2;
    hdr_tmpls[HDR_TMPL_LP_JR2] =  &HDR_LP_JR2;
    hdr_tmpls[HDR_TMPL_IFH_JR2] = &HDR_IFH_JR2;
    hdr_tmpls[HDR_TMPL_IFH_FA] =  &HDR_IFH_FA;
    hdr_tmpls[HDR_TMPL_IFH_CRCL] = &HDR_IFH_CRCL;
    hdr_tmpls[HDR_TMPL_EFH_CRCL] = &HDR_EFH_CRCL;
    hdr_tmpls[HDR_TMPL_IFH_MAS] =  &HDR_IFH_MAS;
    hdr_tmpls[HDR_TMPL_IFH_LA] =  &HDR_IFH_LA;
}

void ifh_uninit() {
    uninit_frame_data(&HDR_SP_OC1);
    uninit_frame_data(&HDR_LP_OC1);
    uninit_frame_data(&HDR_IFH_OC1);
    uninit_frame_data(&HDR_EFH_OC1);
    uninit_frame_data(&HDR_SP_JR2);
    uninit_frame_data(&HDR_LP_JR2);
    uninit_frame_data(&HDR_IFH_JR2);
    uninit_frame_data(&HDR_IFH_FA);
    uninit_frame_data(&HDR_IFH_CRCL);
    uninit_frame_data(&HDR_EFH_CRCL);
    uninit_frame_data(&HDR_IFH_MAS);
    uninit_frame_data(&HDR_IFH_LA);

    hdr_tmpls[HDR_TMPL_SP_OC1] = 0;
    hdr_tmpls[HDR_TMPL_LP_OC1] = 0;
    hdr_tmpls[HDR_TMPL_IFH_OC1] = 0;
    hdr_tmpls[HDR_TMPL_EFH_OC1] = 0;
    hdr_tmpls[HDR_TMPL_SP_JR2] = 0;
    hdr_tmpls[HDR_TMPL_LP_JR2] = 0;
    hdr_tmpls[HDR_TMPL_IFH_JR2] = 0;
    hdr_tmpls[HDR_TMPL_IFH_FA] = 0;
    hdr_tmpls[HDR_TMPL_IFH_CRCL] = 0;
    hdr_tmpls[HDR_TMPL_EFH_CRCL] = 0;
    hdr_tmpls[HDR_TMPL_IFH_MAS] = 0;
    hdr_tmpls[HDR_TMPL_IFH_LA] = 0;
}
