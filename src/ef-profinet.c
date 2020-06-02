#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ef.h"

enum {
    PNET_RTC_FIELD_FRAMEID,
    PNET_RTC_FIELD_DATA,
    PNET_RTC_FIELD_CYCLE,
    PNET_RTC_FIELD_DATA_STATUS_IGN,
    PNET_RTC_FIELD_DATA_STATUS_RESERVED2,
    PNET_RTC_FIELD_DATA_STATUS_PROBLEM,
    PNET_RTC_FIELD_DATA_STATUS_PROVIDER,
    PNET_RTC_FIELD_DATA_STATUS_RESERVED1,
    PNET_RTC_FIELD_DATA_STATUS_VALID,
    PNET_RTC_FIELD_DATA_STATUS_REDUNDANCY,
    PNET_RTC_FIELD_DATA_STATUS_PRIMARY,
    PNET_RTC_FIELD_TRANSFER_STATUS,

    PNET_RTC_FIELD_LAST,
};

static buf_t *profinet_data_parser(hdr_t *hdr, int hdr_offset, const char *s,
                                   int bytes) {
    int i, offset = 0;
    buf_t *b;

    b = parse_var_bytes_hex(s, 40);
    hdr->fields[PNET_RTC_FIELD_DATA].bit_width = b->size * 8;

    for (i = 0; i < PNET_RTC_FIELD_LAST; ++i) {
        hdr->fields[i].bit_offset = offset;
        offset = hdr->fields[i].bit_offset + hdr->fields[i].bit_width;
    }

    hdr->size = offset / 8;

    return b;
}

static field_t PNET_RTC_FIELDS[] = {
    [PNET_RTC_FIELD_FRAMEID] = {
        .name = "frameid",
        .help = "Profinet frame ID. Common used ranges:\n"
                "                                0x0000-0x00FF Time-aware==1. RT_CLASS_STREAM    Multicast CRs\n"
                "                                0x0100-0x04FF Time-aware==1. RT_CLASS_STREAM    Unicast (input or output CRs)\n"
                "                                0x0100-0x06FF Time-aware==0. RT_CLASS_3 (RED)   Uni/multi-cast non-redundant\n"
                "                                0x0700-0x0FFF Time-aware==0. RT_CLASS_3 (RED)   Uni/multi-cast redundant\n"
                "                                0x8000-0xBBFF                RT_CLASS_1 (GREEN) Unicast non-redundant\n"
                "                                0xBC00-0xBFFF                RT_CLASS_1 (GREEN) Multicast non-redundant\n"
                "                                See IEC CDV 61158-6-10 section 4.2.2.6 for more details",
        .bit_width = 16,
    },
    [PNET_RTC_FIELD_DATA] = {
        .name = "data",
        .help = "Variable length data. The encoding of this data depends on configuration",
        .bit_width = 40 * 8,
        .parser = profinet_data_parser,
    },
    [PNET_RTC_FIELD_CYCLE] = {
        .name = "cycle",
        .help = "Cycle counter",
        .bit_width = 16
    },
    [PNET_RTC_FIELD_DATA_STATUS_IGN] = {
        .name = "ignore",
        .help = "Data status: Ignore bit. Default 0",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_RESERVED2] = {
        .name = "reserved2",
        .help = "Data status: Reserved bit 2. Default 0",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_PROBLEM] = {
        .name = "station-ok",
        .help = "Data status: station problem idendicator (default 1, which means no problem)",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_PROVIDER] = {
        .name = "provider-state-run",
        .help = "Data status: provider state Run:1/Stop:0. Default 1",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_RESERVED1] = {
        .name = "reserved1",
        .help = "Data status: Reserved bit 1. Default 0",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_VALID] = {
        .name = "data-valid",
        .help = "Data status: data valid. Default 1",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_REDUNDANCY] = {
        .name = "redundancy",
        .help = "Data status: Redundancy bit. Default 0",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_PRIMARY] = {
        .name = "primary",
        .help = "Data status: State Primary:1/Backup:0. Default 1",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_TRANSFER_STATUS] = {
        .name = "transfer-status",
        .help = "",
        .bit_width = 8
    },
};

static hdr_t HDR_PNET_RTC = {
    .name = "profinet-rtc",
    .help = "Profinet RTC",
    .type = 0x8892,
    .fields = PNET_RTC_FIELDS,
    .fields_size = sizeof(PNET_RTC_FIELDS) / sizeof(PNET_RTC_FIELDS[0]),
    .parser = hdr_parse_fields,
};


void profinet_init() {
    def_offset(&HDR_PNET_RTC);
    def_val(&HDR_PNET_RTC, "station-ok", "1");
    def_val(&HDR_PNET_RTC, "provider-state-run", "1");
    def_val(&HDR_PNET_RTC, "data-valid", "1");
    def_val(&HDR_PNET_RTC, "primary", "1");
    def_val(&HDR_PNET_RTC, "data", "00");

    hdr_tmpls[HDR_TMPL_PNET_RTC] =  &HDR_PNET_RTC;
}

void profinet_uninit() {
    uninit_frame_data(&HDR_PNET_RTC);
    hdr_tmpls[HDR_TMPL_PNET_RTC] = 0;
}

