#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ef.h"

static int sync_req_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t SYNC_REQ_FIELDS[] = {
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
      .bit_width =   32 }
};

static hdr_t HDR_SYNC = {
    .name = "ts-sync",
    .help = "TS-SYNC frame",
    .type = 0x88F7,
    .fields = SYNC_REQ_FIELDS,
    .fields_size = sizeof(SYNC_REQ_FIELDS) / sizeof(SYNC_REQ_FIELDS[0]),
    .frame_fill_defaults = sync_req_fill_defaults,
    .parser = hdr_parse_fields,
};

static hdr_t HDR_REQUEST = {
    .name = "ts-request",
    .help = "TS-REQUEST frame",
    .type = 0x88F7,
    .fields = SYNC_REQ_FIELDS,
    .fields_size = sizeof(SYNC_REQ_FIELDS) / sizeof(SYNC_REQ_FIELDS[0]),
    .frame_fill_defaults = sync_req_fill_defaults,
    .parser = hdr_parse_fields,
};

static int responce_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t RESPONCE_FIELDS[] = {
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
      .bit_offset =  0,
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

    /* Receive Time Stamp - All fields are prefixed with "rts-" */
    { .name = "rts-secondsField",
      .help = "",
      .bit_offset =  0,
      .bit_width =    48 },
    { .name = "rts-nanosecondsField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   32 },

    /* Requesting Port Identity - All fields are prefixed with "rpi-" */
    { .name = "rpi-clockId",
      .help = "",
      .bit_offset =  0,
      .bit_width =    64 },
    { .name = "rpi-portNumber",
      .help = "",
      .bit_offset =  0,
      .bit_width =   16 }, 
};

static hdr_t HDR_RESPONCE = {
    .name = "ts-responce",
    .help = "TS-RESPONCE frame",
    .type = 0x88F7,
    .fields = RESPONCE_FIELDS,
    .fields_size = sizeof(RESPONCE_FIELDS) / sizeof(RESPONCE_FIELDS[0]),
    .frame_fill_defaults = responce_fill_defaults,
    .parser = hdr_parse_fields,
};

void ts_init() {
    def_offset(&HDR_SYNC);
    def_val(&HDR_SYNC, "hdr-messageType", "0");
    def_val(&HDR_SYNC, "hdr-messageLength", "44");
    def_val(&HDR_SYNC, "hdr-clockId", "0xAABBCCDDEEFFAABB");
    def_val(&HDR_SYNC, "hdr-portNumber", "0xAABB");
    def_val(&HDR_SYNC, "ots-secondsField", "0");
    def_val(&HDR_SYNC, "ots-nanosecondsField", "0");

    def_offset(&HDR_REQUEST);
    def_val(&HDR_REQUEST, "hdr-messageType", "1");
    def_val(&HDR_REQUEST, "hdr-messageLength", "44");
    def_val(&HDR_REQUEST, "hdr-clockId", "0xAABBCCDDEEFFAABB");
    def_val(&HDR_REQUEST, "hdr-portNumber", "0xAABB");
    def_val(&HDR_REQUEST, "ots-secondsField", "0");
    def_val(&HDR_REQUEST, "ots-nanosecondsField", "0");

    def_offset(&HDR_RESPONCE);
    def_val(&HDR_RESPONCE, "hdr-messageType", "9");
    def_val(&HDR_RESPONCE, "hdr-messageLength", "54");
    def_val(&HDR_RESPONCE, "hdr-clockId", "0xAABBCCDDEEFFAABB");
    def_val(&HDR_RESPONCE, "hdr-portNumber", "0xAABB");
    def_val(&HDR_RESPONCE, "rts-secondsField", "0");
    def_val(&HDR_RESPONCE, "rts-nanosecondsField", "0");
    def_val(&HDR_RESPONCE, "rpi-clockId", "0xAABBCCDDEEFFAABB");
    def_val(&HDR_RESPONCE, "rpi-portNumber", "0xAABB");

    hdr_tmpls[HDR_TMPL_TS_SYNC] = &HDR_SYNC;
    hdr_tmpls[HDR_TMPL_TS_REQUEST] = &HDR_REQUEST;
    hdr_tmpls[HDR_TMPL_TS_RESPONCE] = &HDR_RESPONCE;
}

void ts_uninit() {
    uninit_frame_data(&HDR_SYNC);
    uninit_frame_data(&HDR_REQUEST);
    uninit_frame_data(&HDR_RESPONCE);

    hdr_tmpls[HDR_TMPL_TS_SYNC] = 0;
    hdr_tmpls[HDR_TMPL_TS_REQUEST] = 0;
    hdr_tmpls[HDR_TMPL_TS_RESPONCE] = 0;
}
