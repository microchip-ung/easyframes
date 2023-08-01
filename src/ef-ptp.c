#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ef.h"

static int fill_defaults(struct frame *f, int stack_idx) {
    char buf[16];
    int i, hdr_len;
    hdr_t *h = f->stack[stack_idx];
    field_t *len = find_field(h, "hdr-messageLength");

    if (!len || len->val)
        return 0;

    hdr_len = 0;

    for (i = stack_idx; i < f->stack_size; ++i) {
        hdr_len += f->stack[i]->size;
    }

    snprintf(buf, 16, "%d", hdr_len);
    buf[15] = 0;
    len->val = parse_bytes(buf, 2);

    return 0;
}

static int tlv_fill_defaults(struct frame *f, int stack_idx) {
    char buf[16];
    int i, hdr_len;
    hdr_t *h = f->stack[stack_idx];
    field_t *len = find_field(h, "tlv-length");

    if (!len || len->val)
        return 0;

    hdr_len = 0;

    for (i = stack_idx; i < f->stack_size; ++i) {
        hdr_len += f->stack[i]->size;
    }

    // Substract the tlv type and length
    hdr_len -= 4;

    snprintf(buf, 16, "%d", hdr_len);
    buf[15] = 0;
    len->val = parse_bytes(buf, 2);

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
    { .name = "hdr-minorVersionPTP",
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
      .bit_width =  2*8 }
};

static hdr_t HDR_SYNC = {
    .name = "ptp-sync",
    .help = "PTP-SYNC frame",
    .type = 0x88F7,
    .fields = SYNC_FIELDS,
    .fields_size = sizeof(SYNC_FIELDS) / sizeof(SYNC_FIELDS[0]),
    .frame_fill_defaults = fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t FOLLOW_UP_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-minorVersionPTP",
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

    /* Precise Origin Time Stamp - All fields are prefixed with "pts-" */
    { .name = "pts-secondsField",
      .help = "",
      .bit_offset =  0,
      .bit_width =    48 },
    { .name = "pts-nanosecondsField",
      .help = "",
      .bit_offset =  0,
      .bit_width =   32 },
};

static hdr_t HDR_FOLLOW_UP = {
    .name = "ptp-follow-up",
    .help = "PTP-FOLLOW-UP frame",
    .type = 0x88F7,
    .fields = FOLLOW_UP_FIELDS,
    .fields_size = sizeof(FOLLOW_UP_FIELDS) / sizeof(FOLLOW_UP_FIELDS[0]),
    .frame_fill_defaults = fill_defaults,
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
    { .name = "hdr-minorVersionPTP",
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
};

static hdr_t HDR_REQUEST = {
    .name = "ptp-request",
    .help = "PTP-REQUEST frame",
    .type = 0x88F7,
    .fields = REQ_FIELDS,
    .fields_size = sizeof(REQ_FIELDS) / sizeof(REQ_FIELDS[0]),
    .frame_fill_defaults = fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t RESPONSE_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-minotrVersionPTP",
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
};

static hdr_t HDR_RESPONSE = {
    .name = "ptp-response",
    .help = "PTP-RESPONSE frame",
    .type = 0x88F7,
    .fields = RESPONSE_FIELDS,
    .fields_size = sizeof(RESPONSE_FIELDS) / sizeof(RESPONSE_FIELDS[0]),
    .frame_fill_defaults = fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t PEER_REQUEST_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_offset =  0,
      .bit_width =   4 },
    { .name = "hdr-minorVersionPTP",
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

    { .name = "rpi-reserved",
      .help = "",
      .bit_offset =  0,
      .bit_width =  160 },
};

static hdr_t HDR_PEER_REQUEST = {
    .name = "ptp-peer-request",
    .help = "PTP-PEER-REQUEST frame",
    .type = 0x88F7,
    .fields = PEER_REQUEST_FIELDS,
    .fields_size = sizeof(PEER_REQUEST_FIELDS) / sizeof(PEER_REQUEST_FIELDS[0]),
    .frame_fill_defaults = fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t PEER_RESPONSE_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-minorVersionPTP",
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

    /* Request Time Stamp - All fields are prefixed with "rts-" */
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
};

static hdr_t HDR_PEER_RESPONSE = {
    .name = "ptp-peer-response",
    .help = "PTP-PEEER-RESPONSE frame",
    .type = 0x88F7,
    .fields = PEER_RESPONSE_FIELDS,
    .fields_size = sizeof(PEER_RESPONSE_FIELDS) / sizeof(PEER_RESPONSE_FIELDS[0]),
    .frame_fill_defaults = fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t PEER_RESPONSE_FOLLOW_UP_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-minorVersionPTP",
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

    /* Response origin Time Stamp - All fields are prefixed with "rots-" */
    { .name = "rots-secondsField",
      .help = "",
      .bit_width =    48 },
    { .name = "rots-nanosecondsField",
      .help = "",
      .bit_width =   32 },

    /* Requesting Port Identity - All fields are prefixed with "rpi-" */
    { .name = "rpi-clockId",
      .help = "",
      .bit_width =    64 },
    { .name = "rpi-portNumber",
      .help = "",
      .bit_width =   16 },
};

static hdr_t HDR_PEER_RESPONSE_FOLLOW_UP = {
    .name = "ptp-peer-response-follow-up",
    .help = "PTP-PEEER-RESPONSE-FOLLOW-UP frame",
    .type = 0x88F7,
    .fields = PEER_RESPONSE_FOLLOW_UP_FIELDS,
    .fields_size = sizeof(PEER_RESPONSE_FOLLOW_UP_FIELDS) /
                   sizeof(PEER_RESPONSE_FOLLOW_UP_FIELDS[0]),
    .frame_fill_defaults = fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t ANNOUNCE_FIELDS[] = {
    /* HEADER - All fields are prefixed with "hdr-" */
    { .name = "hdr-transportSpecific",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-messageType",
      .help = "",
      .bit_width =   4 },
    { .name = "hdr-minorVersionPTP",
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

    /* Announce - All fields are prefixed with "ann-" */
    { .name = "ann-reserved1",
      .help = "",
      .bit_width =  80 },
    { .name = "ann-offset",
      .help = "",
      .bit_width =  16 },
    { .name = "ann-reserved1",
      .help = "",
      .bit_width =   8 },
    { .name = "ann-gmPrio1",
      .help = "",
      .bit_width =   8 },
    { .name = "ann-clockClass",
      .help = "",
      .bit_width =   8 },
    { .name = "ann-clockAcc",
      .help = "",
      .bit_width =   8 },
    { .name = "ann-offsetScaledLogVariance",
      .help = "",
      .bit_width =   16 },
    { .name = "ann-gmPrio2",
      .help = "",
      .bit_width =   8 },
    { .name = "ann-gmIdentity",
      .help = "",
      .bit_width =   64 },
    { .name = "ann-stepsRemoved",
      .help = "",
      .bit_width =   16 },
    { .name = "ann-timeSource",
      .help = "",
      .bit_width =    8 },
};

static hdr_t HDR_ANNOUNCE = {
    .name = "ptp-announce",
    .help = "PTP-ANNOUNCE frame",
    .type = 0x88F7,
    .fields = ANNOUNCE_FIELDS,
    .fields_size = sizeof(ANNOUNCE_FIELDS) / sizeof(ANNOUNCE_FIELDS[0]),
    .frame_fill_defaults = fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t TLV_ORG_FIELDS[] = {
    { .name = "tlv-type",
      .help = "",
      .bit_width =   16 },
    { .name = "tlv-length",
      .help = "",
      .bit_width =   16 },
    { .name = "tlv-org-id",
      .help = "",
      .bit_width =   24 },
    { .name = "tlv-org-sub-type",
      .help = "",
      .bit_width =   24 },
    { .name = "tlv-csro",
      .help = "",
      .bit_width =   32 },
    { .name = "tlv-gm-time-base-indicator",
      .help = "",
      .bit_width =   16 },
    { .name = "tlv-gm-phase-change-msb-nsec",
      .help = "",
      .bit_width =   16 },
    { .name = "tlv-gm-phase-change-lsb-nsec",
      .help = "",
      .bit_width =   64 },
    { .name = "tlv-gm-phase-change-frac-nsec",
      .help = "",
      .bit_width =   16 },
    { .name = "tlv-gm-freq-change",
      .help = "",
      .bit_width =   32 },
};

static hdr_t HDR_TLV_ORG = {
    .name = "ptp-tlv-org",
    .help = "PTP-TLV-ORG frame",
    .type = 6,
    .fields = TLV_ORG_FIELDS,
    .fields_size = sizeof(TLV_ORG_FIELDS) / sizeof(TLV_ORG_FIELDS[0]),
    .frame_fill_defaults = tlv_fill_defaults,
    .parser = hdr_parse_fields,
};

static field_t TLV_PATH_FIELDS[] = {
    { .name = "tlv-type",
      .help = "",
      .bit_width =   16 },
    { .name = "tlv-length",
      .help = "",
      .bit_width =   16 },
};

static hdr_t HDR_TLV_PATH = {
    .name = "ptp-tlv-path",
    .help = "PTP-TLV-PATH frame",
    .type = 6,
    .fields = TLV_PATH_FIELDS,
    .fields_size = sizeof(TLV_PATH_FIELDS) / sizeof(TLV_PATH_FIELDS[0]),
    .frame_fill_defaults = tlv_fill_defaults,
    .parser = hdr_parse_fields,
};

void ts_init() {
    def_offset(&HDR_SYNC);
    def_val(&HDR_SYNC, "hdr-messageType", "0");
    def_val(&HDR_SYNC, "ots-secondsField", "0");
    def_val(&HDR_SYNC, "ots-nanosecondsField", "0");

    def_offset(&HDR_FOLLOW_UP);
    def_val(&HDR_FOLLOW_UP, "hdr-messageType", "8");

    def_offset(&HDR_REQUEST);
    def_val(&HDR_REQUEST, "hdr-messageType", "1");

    def_offset(&HDR_RESPONSE);
    def_val(&HDR_RESPONSE, "hdr-messageType", "9");

    def_offset(&HDR_PEER_REQUEST);
    def_val(&HDR_PEER_REQUEST, "hdr-messageType", "2");

    def_offset(&HDR_PEER_RESPONSE);
    def_val(&HDR_PEER_RESPONSE, "hdr-messageType", "3");

    def_offset(&HDR_PEER_RESPONSE_FOLLOW_UP);
    def_val(&HDR_PEER_RESPONSE_FOLLOW_UP, "hdr-messageType", "10");

    def_offset(&HDR_ANNOUNCE);
    def_val(&HDR_ANNOUNCE, "hdr-messageType", "11");

    def_offset(&HDR_TLV_ORG);
    def_val(&HDR_TLV_ORG, "tlv-type", "3");

    def_offset(&HDR_TLV_PATH);
    def_val(&HDR_TLV_PATH, "tlv-path", "8");

    hdr_tmpls[HDR_TMPL_TS_SYNC] = &HDR_SYNC;
    hdr_tmpls[HDR_TMPL_TS_FOLLOW_UP] = &HDR_FOLLOW_UP;
    hdr_tmpls[HDR_TMPL_TS_REQUEST] = &HDR_REQUEST;
    hdr_tmpls[HDR_TMPL_TS_RESPONSE] = &HDR_RESPONSE;
    hdr_tmpls[HDR_TMPL_TS_PEER_REQUEST] = &HDR_PEER_REQUEST;
    hdr_tmpls[HDR_TMPL_TS_PEER_RESPONSE] = &HDR_PEER_RESPONSE;
    hdr_tmpls[HDR_TMPL_TS_PEER_RESPONSE_FOLLOW_UP] = &HDR_PEER_RESPONSE_FOLLOW_UP;
    hdr_tmpls[HDR_TMPL_TS_ANNOUNCE] = &HDR_ANNOUNCE;
    hdr_tmpls[HDR_TMPL_TS_TLV_ORG] = &HDR_TLV_ORG;
    hdr_tmpls[HDR_TMPL_TS_TLV_PATH] = &HDR_TLV_PATH;
}

void ts_uninit() {
    uninit_frame_data(&HDR_SYNC);
    uninit_frame_data(&HDR_FOLLOW_UP);
    uninit_frame_data(&HDR_REQUEST);
    uninit_frame_data(&HDR_RESPONSE);
    uninit_frame_data(&HDR_PEER_REQUEST);
    uninit_frame_data(&HDR_PEER_RESPONSE);
    uninit_frame_data(&HDR_PEER_RESPONSE_FOLLOW_UP);
    uninit_frame_data(&HDR_ANNOUNCE);
    uninit_frame_data(&HDR_TLV_ORG);
    uninit_frame_data(&HDR_TLV_PATH);

    hdr_tmpls[HDR_TMPL_TS_SYNC] = 0;
    hdr_tmpls[HDR_TMPL_TS_FOLLOW_UP] = 0;
    hdr_tmpls[HDR_TMPL_TS_REQUEST] = 0;
    hdr_tmpls[HDR_TMPL_TS_RESPONSE] = 0;
    hdr_tmpls[HDR_TMPL_TS_PEER_REQUEST] = 0;
    hdr_tmpls[HDR_TMPL_TS_PEER_RESPONSE] = 0;
    hdr_tmpls[HDR_TMPL_TS_PEER_RESPONSE_FOLLOW_UP] = 0;
    hdr_tmpls[HDR_TMPL_TS_ANNOUNCE] = 0;
    hdr_tmpls[HDR_TMPL_TS_TLV_ORG] = 0;
    hdr_tmpls[HDR_TMPL_TS_TLV_PATH] = 0;
}
