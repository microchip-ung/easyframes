#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ef.h"

static int sync_req_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t SYNC_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-reserved",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-versionPTP",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-messageLength",
      .help = "",
      .bit_offset =  0,
      .bit_width =   16 },
    { .name = "hdr-domainNumber",
      .help = "",
      .bit_offset =  0,
      .bit_width =   8 },
    { .name = "hdr-reserved1",
      .help = "",
      .bit_offset =  0,
      .bit_width =   8 },
    { .name = "hdr-flagField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   16 },
    { .name = "hdr-correctionField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   64 },
    { .name = "hdr-reserved2",
      .help = "",
      .bit_offset =  0,
      .bit_width =   32 },
    { .name = "hdr-clockId",
      .help = "",
      .bit_offset =  0,
      .bit_width =    64 },
    { .name = "hdr-portNumber",
      .help = "",
      .bit_width =   16 },
    { .name = "hdr-sequenceId",
      .help = "",
      .bit_offset =  0,
      .bit_width =   16 },
    { .name = "hdr-controlField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   8 },
    { .name = "hdr-logMessageInterval",
      .help = "",
      .bit_offset =  0,
      .bit_width =   8 },

    /* Origin Time Stamp - All fields are prefixed with "ots-" */
    { .name = "ots-secondsField",
      .help = "",
      .bit_offset =  0,
      .bit_width =    48 },
    { .name = "ots-nanosecondsField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   32 },

    /* Padding to get 64 bytes frame */
    { .name = "padding",
      .help = "",
      .bit_width =  6*8 }
};

static hdr_t HDR_SYNC = {
    .name = "ptp-sync",
    .help = "PTP-SYNC frame",
    .type = 0x88F7,
    .fields = SYNC_FIELDS,
    .fields_size = sizeof(SYNC_FIELDS) / sizeof(SYNC_FIELDS[0]),
    .frame_fill_defaults = sync_req_fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t REQ_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-reserved",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-versionPTP",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-messageLength",
      .help = "",
      .bit_offset =  0,
      .bit_width =   16 },
    { .name = "hdr-domainNumber",
      .help = "",
      .bit_offset =  0,
      .bit_width =   8 },
    { .name = "hdr-reserved1",
      .help = "",
      .bit_offset =  0,
      .bit_width =   8 },
    { .name = "hdr-flagField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   16 },
    { .name = "hdr-correctionField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   64 },
    { .name = "hdr-reserved2",
      .help = "",
      .bit_offset =  0,
      .bit_width =   32 },
    { .name = "hdr-clockId",
      .help = "",
      .bit_offset =  0,
      .bit_width =    64 },
    { .name = "hdr-portNumber",
      .help = "",
      .bit_width =   16 },
    { .name = "hdr-sequenceId",
      .help = "",
      .bit_offset =  0,
      .bit_width =   16 },
    { .name = "hdr-controlField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   8 },
    { .name = "hdr-logMessageInterval",
      .help = "",
      .bit_offset =  0,
      .bit_width =   8 },

    /* Origin Time Stamp - All fields are prefixed with "ots-" */
    { .name = "ots-secondsField",
      .help = "",
      .bit_offset =  0,
      .bit_width =    48 },
    { .name = "ots-nanosecondsField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   32 },

    /* Padding to get 64 bytes frame */
    { .name = "padding",
      .help = "",
      .bit_width =  6*8 }
};


static hdr_t HDR_REQUEST = {
    .name = "ptp-request",
    .help = "PTP-REQUEST frame",
    .type = 0x88F7,
    .fields = REQ_FIELDS,
    .fields_size = sizeof(REQ_FIELDS) / sizeof(REQ_FIELDS[0]),
    .frame_fill_defaults = sync_req_fill_defaults,
    .parser = hdr_parse_fields,
};

static int response_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t RESPONSE_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-reserved",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-versionPTP",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-messageLength",
      .help = "",
      .bit_width =   16 },
    { .name = "hdr-domainNumber",
      .help = "",
      .bit_width =   8 },
    { .name = "hdr-reserved1",
      .help = "",
      .bit_width =   8 },
    { .name = "hdr-flagField",
      .help = "",
      .bit_width =   16 },
    { .name = "hdr-correctionField",
      .help = "",
      .bit_width =   64 },
    { .name = "hdr-reserved2",
      .help = "",
      .bit_width =   32 },
    { .name = "hdr-clockId",
      .help = "",
      .bit_width =    64 },
    { .name = "hdr-portNumber",
      .help = "",
      .bit_width =   16 },
    { .name = "hdr-sequenceId",
      .help = "",
      .bit_width =   16 },
    { .name = "hdr-controlField",
      .help = "",
      .bit_width =   8 },
    { .name = "hdr-logMessageInterval",
      .help = "",
      .bit_width =   8 },

    /* Receive Time Stamp - All fields are prefixed with "rts-" */
    { .name = "rts-secondsField",
      .help = "",
      .bit_width =    48 },
    { .name = "rts-nanosecondsField",
      .help = "",
      .bit_width =   32 },

    /* Requesting Port Identity - All fields are prefixed with "rpi-" */
    { .name = "rpi-clockId",
      .help = "",
      .bit_width =    64 },
    { .name = "rpi-portNumber",
      .help = "",
      .bit_width =   16 },

    /* Padding to get 64 bytes frame */
    { .name = "padding",
      .help = "",
      .bit_width =  2*8 },
};

static hdr_t HDR_RESPONSE = {
    .name = "ptp-response",
    .help = "PTP-RESPONSE frame",
    .type = 0x88F7,
    .fields = RESPONSE_FIELDS,
    .fields_size = sizeof(RESPONSE_FIELDS) / sizeof(RESPONSE_FIELDS[0]),
    .frame_fill_defaults = response_fill_defaults,
    .parser = hdr_parse_fields,
};

void ts_init() {
    def_offset(&HDR_SYNC);
    def_val(&HDR_SYNC, "hdr-messageType", "0");
    def_val(&HDR_SYNC, "hdr-messageLength", "44");
    def_val(&HDR_SYNC, "ots-secondsField", "0");
    def_val(&HDR_SYNC, "ots-nanosecondsField", "0");

    def_val(&HDR_REQUEST, "hdr-messageType", "1");
    def_val(&HDR_REQUEST, "hdr-messageLength", "44");
    def_val(&HDR_REQUEST, "ots-secondsField", "0");
    def_val(&HDR_REQUEST, "ots-nanosecondsField", "0");

    def_offset(&HDR_RESPONSE);
    def_val(&HDR_RESPONSE, "hdr-messageType", "9");
    def_val(&HDR_RESPONSE, "hdr-messageLength", "54");
    def_val(&HDR_RESPONSE, "rts-secondsField", "0");
    def_val(&HDR_RESPONSE, "rts-nanosecondsField", "0");

    hdr_tmpls[HDR_TMPL_TS_SYNC] = &HDR_SYNC;
    hdr_tmpls[HDR_TMPL_TS_REQUEST] = &HDR_REQUEST;
    hdr_tmpls[HDR_TMPL_TS_RESPONSE] = &HDR_RESPONSE;
}

void ts_uninit() {
    uninit_frame_data(&HDR_SYNC);
    uninit_frame_data(&HDR_REQUEST);
    uninit_frame_data(&HDR_RESPONSE);

    hdr_tmpls[HDR_TMPL_TS_SYNC] = 0;
    hdr_tmpls[HDR_TMPL_TS_REQUEST] = 0;
    hdr_tmpls[HDR_TMPL_TS_RESPONSE] = 0;
}
