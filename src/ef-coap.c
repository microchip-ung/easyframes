﻿#include "ef.h"


enum {
    COAP_FIELD_VERSION,
    COAP_FIELD_TYPE,
    COAP_FIELD_TOKEN_LENGTH,
    COAP_FIELD_CODE,
    COAP_FIELD_MESSAGE_ID,
    COAP_FIELD_TOKEN,
    COAP_FIELD_OPTIONS,
    COAP_FIELD_PARMS,

    COAP_FIELD_LAST
};

static buf_t *coap_parse_code(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
    buf_t *b = balloc(1);
    uint8_t tmp;
    uint8_t valid = 0;

    if (s[0] >= '0' && s[0] <= '7') {
        if (s[1] == '.') {
            if (s[2] >= '0' && s[2] <= '3'){
                tmp = s[2] - '0';
                if (s[3] >= '0' && s[2] <= '9') {
                    tmp = tmp * 10 + s[3] - '0';
                    if (tmp < 32){
                        tmp = ((s[0] - '0') << 5) + tmp;
                        valid = 1;
                    }
                }
            }
        }
    }

    if (valid) {
        b->size = 1;
        b->data[0] = tmp;
    }
    else {
        b = NULL;
    }

    return b;
}

buf_t *coap_parse_token(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
    int i, offset = 0;
    buf_t *b;

    b = parse_var_bytes_hex(s,1);

    if (!b) {
        return 0;
    }

    if (b->size > 8 || b->size == 0) {
        return 0;
    }
    hdr->fields[COAP_FIELD_TOKEN].bit_width = b->size * 8;

    for (i = 0; i < COAP_FIELD_LAST; ++i) {
        hdr->fields[i].bit_offset = offset;
        offset = hdr->fields[i].bit_offset + hdr->fields[i].bit_width;
    }

    hdr->size = offset / 8;


    return b;
}

buf_t *coap_parse_options(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
    int i, offset = 0;
    buf_t *b;

    b = parse_var_bytes_hex(s,1);

    if (!b) {
        return 0;
    }

    hdr->fields[COAP_FIELD_OPTIONS].bit_width = b->size * 8;

    for (i = 0; i < COAP_FIELD_LAST; ++i) {
        hdr->fields[i].bit_offset = offset;
        offset = hdr->fields[i].bit_offset + hdr->fields[i].bit_width;
    }

    hdr->size = offset / 8;


    return b;
}

buf_t *coap_parse_parms(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
    int i, offset = 0;
    buf_t *bb, *b;

    bb = parse_var_bytes_hex(s, 1);

    if (!bb) {
        return 0;
    }

    b = balloc(bb->size + 1);
    if (!b) {
        return 0;
    }
    memcpy(b->data + 1, bb->data, bb->size);
    *(b->data) = 0xFF;


    hdr->fields[COAP_FIELD_PARMS].bit_width = b->size * 8;

    for (i = 0; i < COAP_FIELD_LAST; ++i) {
        hdr->fields[i].bit_offset = offset;
        offset = hdr->fields[i].bit_offset + hdr->fields[i].bit_width;
    }

    hdr->size = offset / 8;


    return b;
}

static field_t COAP_FIELDS[] = {  
    [COAP_FIELD_VERSION] = 
    { .name = "ver",
      .help = "CoAP version number, has to be 1",
      .bit_width =  2 },
    [COAP_FIELD_TYPE]  
    { .name = "type",
      .help = "message type: Confirmable (0), Non-confirmable (1), Acknowledgement (2), or Reset (3)",
      .bit_width =  2 },
    [COAP_FIELD_TOKEN_LENGTH]
    { .name = "tkl",
      .help = "Token length, 0-8 bytes",
      .bit_width =  4  },
    [COAP_FIELD_CODE]
    { .name = "code",
      .help = "message code, split into a 3-bit class and a 5-bit detail e.g. 0.01 (GET) or 4.04 (Not found)",
      .bit_width =  8,
      .parser = coap_parse_code },
    [COAP_FIELD_MESSAGE_ID]
    { .name = "msgid",
      .help = "Used to detect message duplication and to match messages",
      .bit_width =  16 },
    [COAP_FIELD_TOKEN]
    { .name = "token",
      .help = "Token length must not greater than 8 bytes. (optional)",
      .bit_width = 0,
      .parser = coap_parse_token },  
    [COAP_FIELD_OPTIONS]
    { .name = "opt",
      .help = "Options, provided as hex string.  (optional)",
      .bit_width = 0,
      .parser = coap_parse_options },  
    [COAP_FIELD_PARMS]
    { .name = "par",
      .help = "Parameters. (optional)",
      .bit_width = 0,
      .parser = coap_parse_parms }  
};

static hdr_t HDR_COAP = {
    .name = "coap",
    .help = "Constrained Application Protocol",
//    .type = 0x0806,  /*! \TODO RWI:  */
    .fields = COAP_FIELDS,
    .fields_size = sizeof(COAP_FIELDS) / sizeof(COAP_FIELDS[0]),
    .parser = hdr_parse_fields,
};

void coap_init() {
    def_offset(&HDR_COAP);
    def_val(&HDR_COAP, "ver",   "1"); 
    def_val(&HDR_COAP, "type",  "0");
    def_val(&HDR_COAP, "tkl",   "0");
    def_val(&HDR_COAP, "code",  "0");
    def_val(&HDR_COAP, "msgid", "0");

    hdr_tmpls[HDR_TMPL_COAP] = &HDR_COAP;
}

void coap_uninit() {
    uninit_frame_data(&HDR_COAP);
/*! \TODO RWI: free the buffers */
    hdr_tmpls[HDR_TMPL_COAP] = 0;
}