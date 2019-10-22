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

    hdr->size = offset/8;

    return b;
}

static field_t PNET_RTC_FIELDS[] = {
    [PNET_RTC_FIELD_FRAMEID] = {
        .name = "frameid",
        .help = "Profinet frame ID. For RTC this should be in the range: x-y.",
        .bit_width = 16,
    },
    [PNET_RTC_FIELD_DATA] = {
        .name = "data",
        .help = "Variable length data. The encoding of this data depends on configuration",
        .bit_offset = 16,
        .bit_width = 0,
        .parser = profinet_data_parser,
    },

    [PNET_RTC_FIELD_CYCLE] = {
        .name = "cycle",
        .help = "",
        .bit_width = 16
    },

    [PNET_RTC_FIELD_DATA_STATUS_IGN] = {
        .name = "ignore",
        .help = "",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_RESERVED2] = {
        .name = "reserved2",
        .help = "",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_PROBLEM] = {
        .name = "station-ok",
        .help = "",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_PROVIDER] = {
        .name = "provider-state-run",
        .help = "",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_RESERVED1] = {
        .name = "reserved1",
        .help = "",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_VALID] = {
        .name = "data-valid",
        .help = "",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_REDUNDANCY] = {
        .name = "redundancy",
        .help = "",
        .bit_width = 1
    },
    [PNET_RTC_FIELD_DATA_STATUS_PRIMARY] = {
        .name = "primary",
        .help = "",
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
    hdr_tmpls[HDR_TMPL_PNET_RTC] =  &HDR_PNET_RTC;

    def_val(&HDR_PNET_RTC, "station-ok", "1");
    def_val(&HDR_PNET_RTC, "provider-state-run", "1");
    def_val(&HDR_PNET_RTC, "data-valid", "1");
    def_val(&HDR_PNET_RTC, "primary", "1");
}

void profinet_uninit() {
    uninit_frame_data(&HDR_PNET_RTC);
    hdr_tmpls[HDR_TMPL_PNET_RTC] = 0;
}

