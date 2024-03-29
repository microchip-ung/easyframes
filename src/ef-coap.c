﻿#include <stdio.h>
#include "ef.h"


enum {
    COAP_FIELD_VERSION,
    COAP_FIELD_TYPE,
    COAP_FIELD_TOKEN_LENGTH,
    COAP_FIELD_CODE,
    COAP_FIELD_MESSAGE_ID,
    COAP_FIELD_TOKEN,

    COAP_FIELD_LAST
};

enum {
    COAP_OPT_FIELD_NUM,
    COAP_OPT_FIELD_VAL,

    COAP_OPT_FIELD_LAST
};

enum {
    COAP_PARMS_FIELD_PAR,

    COAP_PARMS_FIELD_LAST
};

static buf_t *coap_parse_code(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
    buf_t   *b = NULL;
    uint8_t tmp;
    uint8_t valid = 0;

    if ((strlen(s) == 4)
        && (s[0] >= '0' && s[0] <= '7')
        && (s[1] == '.')
        && (s[2] >= '0' && s[2] <= '3')
        && (s[3] >= '0' && s[2] <= '9')) {
        tmp = s[2] - '0';
        tmp = tmp * 10 + s[3] - '0';
        if (tmp < 32) {
            tmp = ((s[0] - '0') << 5) + tmp;
            valid = 1;
        }
    }

    if (valid) {
        b = balloc(1);
        b->data[0] = tmp;
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

int coap_parse_parms(hdr_t *hdr, int hdr_offset, struct field *f, int argc, const char *argv[]){
    int res;
    buf_t *b, *bb = 0;

    res = parse_var_bytes(&b, argc, argv);

    if (res > 1 && res <= argc) {
        bb = balloc(b->size + 1);
        if (!bb) {
            return 0;
        }

        *(bb->data) = 0xFF;
        memcpy(bb->data + 1, b->data, b->size);

        f->val = bb;
        f->bit_width = bb->size * 8;
        hdr->size = bb->size;

        bfree(b);

        return res;
    }

    if (b)
        bfree(b);

    return 0;
}

static int coap_fill_defaults(struct frame *f, int stack_idx) {
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
    field_t *tkl = find_field(h, "tkl");
    field_t *token = find_field(h, "token");

    if (!tkl->val) {
        if (token->val) {
            snprintf(buf, 16, "%d", BIT_TO_BYTE(h->fields[COAP_FIELD_TOKEN].bit_width));
            tkl->val = parse_bytes(buf, 1);
        }
    }

    return 0;
}


static field_t COAP_FIELDS[] = {
    [COAP_FIELD_VERSION] =
    { .name = "ver",
      .help = "CoAP version number, has to be 1",
      .bit_width =  2 },
    [COAP_FIELD_TYPE] =
    { .name = "type",
      .help = "message type: Confirmable (0), Non-confirmable (1), Acknowledgement (2), or Reset (3)",
      .bit_width =  2 },
    [COAP_FIELD_TOKEN_LENGTH] =
    { .name = "tkl",
      .help = "Token length, 0-8 bytes",
      .bit_width =  4  },
    [COAP_FIELD_CODE] =
    { .name = "code",
      .help = "message code, split into a 3-bit class and a 5-bit detail e.g. 0.01 (GET) or 4.04 (Not found)",
      .bit_width =  8,
      .parser = coap_parse_code },
    [COAP_FIELD_MESSAGE_ID] =
    { .name = "msgid",
      .help = "Used to detect message duplication and to match messages",
      .bit_width =  16 },
    [COAP_FIELD_TOKEN] =
    { .name = "token",
      .help = "Token length must not greater than 8 bytes. (optional)",
      .bit_width = 0,
      .parser = coap_parse_token }
};

static hdr_t HDR_COAP = {
    .name = "coap",
    .help = "Constrained Application Protocol",
    .fields = COAP_FIELDS,
    .fields_size = sizeof(COAP_FIELDS) / sizeof(COAP_FIELDS[0]),
    .frame_fill_defaults = coap_fill_defaults,
    .parser = hdr_parse_fields,
};

static int options_fill_defaults(struct frame *f, int stack_idx) {
    buf_t *bb, *b;

    uint16_t delta;
    uint16_t delta_ext = 0;
    uint16_t len = 0;
    uint16_t len_ext = 0;
    uint16_t i;
    int offset = 0;


    hdr_t   *hdr = f->stack[stack_idx];
    field_t *fnum = find_field(hdr, "num");
    field_t *fval = find_field(hdr, "val");

    if (!fnum->val || !fval->val) {
        return 0;
    }

    if (fval){
        len = fval->val->size;
    }

    delta = fnum->val->data[0] * 256 + fnum->val->data[1];

    b = balloc(5);

    i = 1;
    if (delta > 12) {
        if (delta > 268) {
            delta_ext        = delta - 269;
            delta            = 14;
            *(b->data + i++) = delta_ext >> 8;
            *(b->data + i++) = delta_ext & 0xFF;
        }
        else {
            delta_ext        = delta - 13;
            delta            = 13;
            *(b->data + i++) = delta_ext;
        }
    }
    *(b->data) = delta << 4;

    if (len > 12) {
        if (len > 268) {
            len_ext          = len - 269;
            len              = 14;
            *(b->data + i++) = len_ext >> 8;
            *(b->data + i++) = len_ext & 0xFF;
        }
        else {
            len_ext          = len - 13;
            len              = 13;
            *(b->data + i++) = len_ext;
        }
    }

    *(b->data) |= len & 0x0F;

    bb = balloc(i);
    memcpy(bb->data,b->data, i);

    bfree(fnum->val);
    fnum->val = bb;

    hdr->fields[COAP_OPT_FIELD_NUM].bit_width = fnum->val->size * 8;

    for (i = 0; i < COAP_OPT_FIELD_LAST; ++i) {
        hdr->fields[i].bit_offset = offset;
        offset = hdr->fields[i].bit_offset + hdr->fields[i].bit_width;
    }
    hdr->size = offset / 8;

    bfree(b);
    return 0;
}

//This is a wrapper around field_parse_multi_var_byte
//that is used to make sure that a zero value, uses zero length in the buffer.
static int coap_parse_option_value(struct hdr *hdr, int hdr_offset, struct field *f,
                                   int argc, const char *argv[])
{
    int result = 0;
    result = field_parse_multi_var_byte(hdr, hdr_offset, f, argc, argv);

    if ((result > 1) && (result <= argc))
    {
        //check for zero value
        int isZero = 1;
        for (int index = 0; index < ((int)(f->val->size)); index++)
        {
            if (f->val->data[index] != 0)
            {
                isZero = 0;
                break;
            }
        }
        if (isZero)
        {
            //truncate to zero length
            hdr->size -= f->val->size;
            f->val->size = 0;
            f->bit_width = 0;
        }
    }
    return result;
}

static field_t COAP_OPT_FIELDS[] = {
    [COAP_OPT_FIELD_NUM] =
    { .name = "num",                    /* holds num and len fields */
      .help = "CoAP Option Number",
      .bit_width = 16,                  /* will be fixed in options_fill_defaults() */
    },
    [COAP_OPT_FIELD_VAL] =
    { .name = "val",
      .help = "CoAP Option Value",
      .bit_width = 0,
      .parser_multi = coap_parse_option_value
    }
};

static hdr_t HDR_COAP_OPTIONS = {
    .name = "coap-opt",
    .help = "Constrained Application Protocol Options, several fields allowed. (optional)",
    .fields = COAP_OPT_FIELDS,
    .fields_size = sizeof(COAP_OPT_FIELDS) / sizeof(COAP_OPT_FIELDS[0]),
    .frame_fill_defaults = options_fill_defaults,
    .parser = hdr_parse_fields,
};

static int parameters_fill_defaults(struct frame *f, int stack_idx) {
    return 0;
}

static field_t COAP_PARMS_FIELDS[] = {
    [COAP_PARMS_FIELD_PAR] =
    { .name = "par",
      .help = "CoAP Parameter field.",
      .bit_width = 0,
      .parser_multi = coap_parse_parms }
};

static hdr_t HDR_COAP_PARMS = {
    .name = "coap-parms",
    .help = "Constrained Application Protocol Parameters. (optional)",
    .fields = COAP_PARMS_FIELDS,
    .fields_size = sizeof(COAP_PARMS_FIELDS) / sizeof(COAP_PARMS_FIELDS[0]),
    .frame_fill_defaults = parameters_fill_defaults,
    .parser = hdr_parse_fields,
};


void coap_init() {
    def_offset(&HDR_COAP);
    def_val(&HDR_COAP, "ver",   "1");
    def_val(&HDR_COAP, "type",  "0");
    def_val(&HDR_COAP, "tkl",   "0");
    def_val(&HDR_COAP, "code",  "0");
    def_val(&HDR_COAP, "msgid", "0");

    def_offset(&HDR_COAP_OPTIONS);
    def_offset(&HDR_COAP_PARMS);

    hdr_tmpls[HDR_TMPL_COAP]         = &HDR_COAP;
    hdr_tmpls[HDR_TMPL_COAP_OPTIONS] = &HDR_COAP_OPTIONS;
    hdr_tmpls[HDR_TMPL_COAP_PARMS]   = &HDR_COAP_PARMS;

}

void coap_uninit() {
    uninit_frame_data(&HDR_COAP);
    /*! \TODO  free the buffers */
    hdr_tmpls[HDR_TMPL_COAP]         = 0;
    hdr_tmpls[HDR_TMPL_COAP_OPTIONS] = 0;
    hdr_tmpls[HDR_TMPL_COAP_PARMS]   = 0;
}
