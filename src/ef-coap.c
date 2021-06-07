#include <stdio.h>
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

/* neede to calculate the option delta */
static uint8_t opt_num_last;
static buf_t *opt_num;
static buf_t *opt_val;


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

buf_t *coap_parse_opt_num(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
    opt_num = parse_bytes(s, 2);

    return 0;
}

buf_t *coap_parse_opt_val(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
    opt_val = parse_var_bytes_hex(s, 1);

    return 0;
}

buf_t *coap_parse_parms(hdr_t *hdr, int hdr_offset, const char *s, int bytes) {
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


    hdr->fields[0].bit_width = b->size * 8;

    bfree(bb);
    return b;
}

static int coap_fill_defaults(struct frame *f, int stack_idx) {
    char buf[16];
    hdr_t *h = f->stack[stack_idx];
    field_t *tkl = find_field(h, "tkl");

    if (!tkl->val) {
        snprintf(buf, 16, "%d", BIT_TO_BYTE(h->fields[COAP_FIELD_TOKEN].bit_width));

        tkl->val = parse_bytes(buf, 1);
    }

    return 0;
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
    uint16_t temp;
    int offset = 0;



    if (!opt_num) {
        return 0;
    }

    if (opt_val){
        len = opt_val->size; 
    }

    temp = opt_num->data[0] * 256 + opt_num->data[1];
    if (temp < opt_num_last) {
        return 0;
    }

    b = balloc(5);
    
    /* calculate delta and delta-ext values */
    delta = temp - opt_num_last;
    opt_num_last = temp;

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

    bb = balloc(i + opt_val->size);
    if (opt_val->size != 0) {
        memcpy(bb->data,b->data, i);
        memcpy(bb->data + i, opt_val->data, opt_val->size);
    }

    hdr_t   *hdr = f->stack[stack_idx];
    field_t *num = find_field(hdr, "num");

    if (num) {
        num->val = bb;
    }

    hdr->fields[COAP_OPT_FIELD_NUM].bit_width = num->val->size * 8;

    for (i = 0; i < COAP_OPT_FIELD_LAST; ++i) {
        hdr->fields[i].bit_offset = offset;
        offset = hdr->fields[i].bit_offset + hdr->fields[i].bit_width;
    }

    hdr->size = offset / 8;

    return 0;
}

static field_t COAP_OPT_FIELDS[] = {  
    [COAP_OPT_FIELD_NUM]
    { .name = "num",
      .help = "CoAP Option Number",
      .bit_width = 0,
      .parser = coap_parse_opt_num },
    [COAP_OPT_FIELD_VAL]
    { .name = "val",
      .help = "CoAP Option Value",
      .bit_width = 0,
      .parser = coap_parse_opt_val }
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
//    [COAP_FIELD_PARMS]
    { .name = "par",
      .help = "CoAP Parameter field.",
      .bit_width = 0,
      .parser = coap_parse_parms }
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

    opt_num_last = 0;
}

void coap_uninit() {
    uninit_frame_data(&HDR_COAP);
/*! \TODO  free the buffers */
    hdr_tmpls[HDR_TMPL_COAP]         = 0;
    hdr_tmpls[HDR_TMPL_COAP_OPTIONS] = 0;
    hdr_tmpls[HDR_TMPL_COAP_PARMS]   = 0;
}
