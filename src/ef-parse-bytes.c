#include "ef.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <arpa/inet.h>

struct start_with {
    uint32_t mask;
    const char *s;
};

enum {
    START_WITH_0x = (1 << 0),
    START_WITH_0o = (1 << 1),
    START_WITH_0b = (1 << 2),
};

static struct start_with start_withs[] = {
    {START_WITH_0x, "0x"},
    {START_WITH_0o, "0o"},
    {START_WITH_0b, "0b"},
};

struct has_char {
    uint32_t    mask;
    const char *char_set;
    uint32_t    cnt;
};

enum {
    HAS_BASE_2     = (1 << 0),
    HAS_BASE_8     = (1 << 1),
    HAS_BASE_10    = (1 << 2),
    HAS_BASE_16    = (1 << 3),
    HAS_DOT        = (1 << 4),
    HAS_COLON      = (1 << 5),
};

#define HAS_HEX_COL (HAS_BASE_2 | HAS_BASE_8 | HAS_BASE_10 | HAS_BASE_16 | \
                     HAS_COLON)
#define HAS_HEX_DOT (HAS_BASE_2 | HAS_BASE_8 | HAS_BASE_10 | HAS_BASE_16 | \
                     HAS_DOT)

static struct has_char has_chars[] = {
    {.mask = HAS_BASE_2,  .char_set = "01" },
    {.mask = HAS_BASE_8,  .char_set = "234567" },
    {.mask = HAS_BASE_10, .char_set = "89" },
    {.mask = HAS_BASE_16, .char_set = "aAbBcCdDeEfF" },
    {.mask = HAS_DOT,     .char_set = "." },
    {.mask = HAS_COLON,   .char_set = ":" },
};

buf_t *parse_bytes_binary(const char *s, int size) {
    buf_t *b;
    uint8_t *p_o, tmp;
    const char *p;
    int cnt_bits, has_others, has_align_issues, valid;

    p = s;
    cnt_bits = 0;
    has_others = 0;
    has_align_issues = 0;

    for (; *p; ++p) {
        if (*p == '0' || *p == '1') {
            cnt_bits++;
        } else {
            has_others = 1;
        }
    }

    if (cnt_bits % 8 != 0) {
        has_align_issues = 1;
    }

    if (has_others || cnt_bits == 0) {
        po("ERROR: Could not parse >%s< as a hex string\n", s);
        return 0;
    }

    if (has_align_issues) {
        po("ERROR: hex strings must be byte aligned, and if delimiters are then they must also be byte aligned.\n");
        return 0;
    }

    b = balloc(size);

    p = s;
    p_o = b->data + size - cnt_bits / 8;
    cnt_bits = 0;

    for (; *p; ++p) {
        if (*p == '0' || *p == '1') {
            valid = 1;
            tmp = *p - '0';
        } else {
            valid = 0;
        }

        if (valid) {
            *p_o |= tmp;
            cnt_bits++;

            if (cnt_bits % 8 == 0)
                p_o ++;
            else
                *p_o <<= 1;
        }
    }

    return b;
}

buf_t *parse_bytes_hex(const char *s, int size) {
    buf_t *b;
    uint8_t *p_o, tmp;
    const char *p;
    int cnt_nibble, has_others, has_align_issues, valid;

    p = s;
    cnt_nibble = 0;
    has_others = 0;
    has_align_issues = 0;

    for (; *p; ++p) {
        if (*p >= '0' && *p <= '9') {
            cnt_nibble ++;
        } else if (*p >= 'a' && *p <= 'f') {
            cnt_nibble ++;
        } else if (*p >= 'A' && *p <= 'F') {
            cnt_nibble ++;
        } else if (*p == '.' || *p == ':' || *p == '-' || *p == '_') {
            if (cnt_nibble % 2 != 0) {
                has_align_issues = 1;
            }
        } else {
            has_others = 1;
        }
    }

    if (cnt_nibble % 2 != 0) {
        has_align_issues = 1;
    }

    if (has_others || cnt_nibble == 0) {
        po("ERROR: Could not parse >%s< as a hex string\n", s);
        return 0;
    }

    if (has_align_issues) {
        po("ERROR: hex strings must be byte aligned, and if delimiters are then they must also be byte aligned.\n");
        return 0;
    }

    b = balloc(size);

    p = s;
    p_o = b->data + size - cnt_nibble / 2;
    cnt_nibble = 0;

    for (; *p; ++p) {
        if (*p >= '0' && *p <= '9') {
            valid = 1;
            tmp = *p - '0';

        } else if (*p >= 'a' && *p <= 'f') {
            valid = 1;
            tmp = (*p - 'a') + 10;

        } else if (*p >= 'A' && *p <= 'F') {
            valid = 1;
            tmp = (*p - 'A') + 10;

        } else {
            valid = 0;
        }

        if (valid) {
            *p_o |= tmp;
            cnt_nibble++;

            if (cnt_nibble % 2 == 1)
                *p_o <<= 4;
            else
                p_o++;
        }
    }

    return b;
}


buf_t *parse_bytes(const char *s, int bytes) {
    buf_t *b;
    size_t i;
    int base, s_size = strlen(s);
    const char *s_begin = s, *data_begin = s;
    const char *data_end = data_begin + s_size;
    uint32_t has_mask = 0;
    int has_other = 0;
    uint32_t start_mask = 0;

    // po("line: %d %s\n", __LINE__, s);
    for (i = 0; i < sizeof(start_withs)/sizeof(start_withs[0]); ++i) {
        int l = strlen(start_withs[i].s);
        if (s_size >= l && strncmp(s, start_withs[i].s, l) == 0) {
            start_mask |= start_withs[i].mask;
            data_begin = s_begin + l;
            break;
        }
    }

    for (s = data_begin; *s; ++s) {
        int match_found = 0;
        for (i = 0; i < sizeof(has_chars)/sizeof(has_chars[0]); ++i) {
            const char *set_i;

            for (set_i = has_chars[i].char_set; *set_i; ++set_i) {
                if (*s == *set_i) {
                    has_mask |= has_chars[i].mask;
                    match_found = 1;
                    has_chars[i].cnt++;
                }
            }
        }
        if (!match_found) {
            has_other = 1;
        }
    }

    base = 0;
    //po("line: %d %08x %08x %d %d\n", __LINE__, start_mask, has_mask, has_other, bytes);
    if (start_mask == START_WITH_0x && !has_other &&
        ((has_mask & ~(HAS_BASE_2 | HAS_BASE_8 | HAS_BASE_10 | HAS_BASE_16)) == 0)) {
        //po("line: %d\n", __LINE__);
        base = 16;

    } else if (start_mask == 0 && !has_other &&
               ((has_mask & ~(HAS_BASE_2 | HAS_BASE_8 | HAS_BASE_10)) == 0)) {
        //po("line: %d\n", __LINE__);
        base = 10;

    } else if (start_mask == START_WITH_0o && !has_other &&
               ((has_mask & ~(HAS_BASE_2 | HAS_BASE_8)) == 0)) {
        //po("line: %d\n", __LINE__);
        base = 8;

    } else if (start_mask == START_WITH_0b && !has_other &&
               ((has_mask & ~(HAS_BASE_2)) == 0)) {
        //po("line: %d\n", __LINE__);
        base = 2;
    }

    if (base && bytes <= 8) {
        char *endptr, *o;
        uint64_t val;

        errno = 0;
        val = strtoull(data_begin, &endptr, base);

        if (endptr != data_end || errno) {
            return 0;
        }

        val = htobe64(val);

        b = balloc(bytes);
        if (!b)
            return b;

        o = (char *)&val;
        o += 8 - bytes;
        memcpy(b->data, o, bytes);

        return b;
    } else if (base) {
        if (base == 16) {
            return parse_bytes_hex(data_begin, bytes);
        }
        if (base == 2) {
            return parse_bytes_binary(data_begin, bytes);
        }
    }

    //po("line: %d %d %d\n", __LINE__, bytes, has_other);
    //po("line: %d %d\n", __LINE__, has_mask & ~(HAS_HEX_COL));
    //po("line: %d b2:  %d\n", __LINE__, has_mask & HAS_BASE_2);
    //po("line: %d b8:  %d\n", __LINE__, has_mask & HAS_BASE_8);
    //po("line: %d b10: %d\n", __LINE__, has_mask & HAS_BASE_10);
    //po("line: %d b16: %d\n", __LINE__, has_mask & HAS_BASE_16);
    //po("line: %d has colon: %d\n", __LINE__, has_mask & HAS_COLON);
    //po("line: %d has dot:   %d\n", __LINE__, has_mask & HAS_DOT);
    //po("line: %d has other:   %d\n", __LINE__, has_other);

    if (start_mask == 0 && bytes == 4 && !has_other &&
        ((has_mask & ~(HAS_HEX_DOT)) == 0) && (has_mask & HAS_DOT)) {
        // This will be treated as an IPv4
        unsigned char buf[sizeof(struct in6_addr)];
        //po("line: %d\n", __LINE__);

        if (inet_pton(AF_INET, data_begin, buf) == 1) {
            b = balloc(4);
            if (!b)
                return b;
            memcpy(b->data, buf, 4);

            return b;

        } else {
            po("%s:%d: ERROR, could not parse input as an IPv4 address\n",
                   __FILE__, __LINE__);
            return 0;
        }

    } else if (start_mask == 0 && bytes == 6 && !has_other &&
               ((has_mask & ~(HAS_HEX_COL)) == 0) && (has_mask & HAS_COLON)) {
        // This will be treated as a mac-address
        uint8_t m[6] = {};
        const char *x;

        // We want to be able to write something like this (like we RFC2373
        // specifies for IPv6):
        //
        // ::      -> 00:00:00:00:00:00
        // ::1     -> 00:00:00:00:00:01
        // 1::     -> 01:00:00:00:00:00
        // 01::20  -> 01:00:00:00:00:20
        // 1::2    -> 01:00:00:00:00:02
        // 1:2::3  -> 01:02:00:00:00:03

        int idx = 0;
        int split = 0;
        int split_cnt = 0;
        int val_cnt = 0;
        int col_cnt = 0;
        int element_cnt = 0;
        int move_from, move_to, move_size;

        //po("line: %d data_begin: %s\n", __LINE__, data_begin);

        for (x = data_begin; *x; ++x) {
            int colon = 0;
            int val = 0;

            if (*x >= '0' && *x <= '9') {
                val = *x - '0';

            } else if (*x >= 'a' && *x <= 'f') {
                val = *x - 'a' + 0xa;

            } else if (*x >= 'A' && *x <= 'F') {
                val = *x - 'A' + 0xa;

            } else if (*x == ':') {
                colon = 1;

            } else {
                po("%s:%d: ERROR\n", __FILE__, __LINE__);
                return 0;

            }

            //po("%d val:%x val_cnt:%d col_cnt:%d, idx:%d colon:%d\n",
            //       __LINE__, val, val_cnt, col_cnt, idx, colon);

            if (idx > 5) {
                po("%s:%d: ERROR\n", __FILE__, __LINE__);
                return 0;
            }

            if (colon) {
                if (val_cnt != 0 && col_cnt == 0)
                    idx++;

                val_cnt = 0;
                col_cnt ++;

                if (col_cnt == 2) {
                    split_cnt ++;

                    if (split_cnt > 1) {
                        po("%s:%d: ERROR\n", __FILE__, __LINE__);
                        return 0;
                    }

                    if (split) {
                        po("%s:%d: ERROR\n", __FILE__, __LINE__);
                        return 0;
                    } else {
                        split = idx;
                    }
                } else if (col_cnt > 2) {
                    po("%s:%d: ERROR\n", __FILE__, __LINE__);
                    return 0;
                }

            } else {
                val_cnt ++;
                col_cnt = 0;

                if (val_cnt > 2) {
                    po("%s:%d: ERROR\n", __FILE__, __LINE__);
                    return 0;
                }

                if (val_cnt == 1)
                    element_cnt ++;
                m[idx] <<= 4;
                m[idx] |= val;

                //po("line: %d, idx: %d, %02x\n", __LINE__, idx, m[idx]);
            }
        }

        if (split_cnt > 1) {
            po("%s:%d: ERROR\n", __FILE__, __LINE__);
            return 0;
        }

        if (element_cnt > 6) {
            po("%s:%d: ERROR\n", __FILE__, __LINE__);
            return 0;
        }

        if (element_cnt >= 6 && split_cnt > 0) {
            po("%s:%d: ERROR\n", __FILE__, __LINE__);
            return 0;
        }

        move_from = split;
        move_to = 6 - element_cnt + split;
        move_size = element_cnt - split;

        //po("%d split:%d element_cnt:%d from:%d, to:%d, size:%d\n",
        //       __LINE__, split, element_cnt, move_from, move_to, move_size);

        //po("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0],  m[1], m[2], m[3], m[4], m[5]);

        memmove(m + move_to, m + move_from, move_size);
        //po("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0],  m[1], m[2], m[3], m[4], m[5]);
        memset(m + split, 0, move_to - move_from);

        //po("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0],  m[1], m[2], m[3], m[4], m[5]);

        b = balloc(6);
        if (!b) {
            po("%s:%d: ERROR\n", __FILE__, __LINE__);
            return b;
        }
        memcpy(b->data, m, 6);

        return b;


    } else if (start_mask == 0 && bytes == 16 && !has_other &&
               ((has_mask & ~(HAS_HEX_COL | HAS_DOT)) == 0) &&
               (has_mask & HAS_COLON)) {

        // This will be treated as an IPv6
        unsigned char buf[sizeof(struct in6_addr)];
        //po("line: %d\n", __LINE__);

        if (inet_pton(AF_INET6, data_begin, buf) == 1) {
            b = balloc(16);
            if (!b) {
                po("%s:%d: ERROR\n", __FILE__, __LINE__);
                return b;
            }
            memcpy(b->data, buf, 16);

            return b;

        } else {
            po("%s:%d: ERROR\n", __FILE__, __LINE__);
            return 0;

        }
    }

    return 0;
}

buf_t *parse_var_bytes_hex(const char *s, int min_size) {
    buf_t *b;
    uint8_t *p_o, tmp;
    const char *p;
    int cnt_nibble, has_others, has_align_issues, valid;

    p = s;
    cnt_nibble = 0;
    has_others = 0;
    has_align_issues = 0;

    for (; *p; ++p) {
        if (*p >= '0' && *p <= '9') {
            cnt_nibble ++;
        } else if (*p >= 'a' && *p <= 'f') {
            cnt_nibble ++;
        } else if (*p >= 'A' && *p <= 'F') {
            cnt_nibble ++;
        } else if (*p == '.' || *p == ':' || *p == '-' || *p == '_') {
            if (cnt_nibble % 2 != 0) {
                has_align_issues = 1;
            }
        } else {
            has_others = 1;
        }
    }

    if (cnt_nibble % 2 != 0) {
        has_align_issues = 1;
    }

    if (has_others || cnt_nibble == 0) {
        po("ERROR: Could not parse >%s< as a hex string\n", s);
        return 0;
    }

    if (has_align_issues) {
        po("ERROR: hex strings must be byte aligned, and if delimiters are then they must also be byte aligned.\n");
        return 0;
    }

    if (cnt_nibble / 2 > min_size) {
        b = balloc(cnt_nibble / 2);
    } else {
        b = balloc(min_size);
    }

    p = s;
    p_o = b->data;
    cnt_nibble = 0;

    for (; *p; ++p) {
        if (*p >= '0' && *p <= '9') {
            valid = 1;
            tmp = *p - '0';

        } else if (*p >= 'a' && *p <= 'f') {
            valid = 1;
            tmp = (*p - 'a') + 10;

        } else if (*p >= 'A' && *p <= 'F') {
            valid = 1;
            tmp = (*p - 'A') + 10;

        } else {
            valid = 0;
        }

        if (valid) {
            *p_o |= tmp;
            cnt_nibble++;

            if (cnt_nibble % 2 == 1)
                *p_o <<= 4;
            else
                p_o++;
        }
    }

    return b;
}

buf_t *parse_field_hex(struct hdr *hdr, int hdr_offset, const char *s, int bytes)
{
    buf_t *b;
    buf_t *b_ret = 0;

    b_ret = balloc(bytes);
    if (!b_ret) {
        po("%s:%d: ERROR: Memory alloc\n", __FILE__, __LINE__);
        return 0;
    }
    b = parse_var_bytes_hex(s, 0);
    if (!b) {
        bfree(b_ret);
        return 0;
    }

    if (b->size > (size_t)bytes) {
        po("%s:%d: ERROR: Parsed field size is too large\n", __FILE__, __LINE__);
        return 0;
    }

    memset(b_ret->data, 0, sizeof(bytes));
    memcpy(b_ret->data, b->data, b->size);
    bfree(b);

    return(b_ret);
}

buf_t *parse_var_bytes_ascii(const char *s) {
    buf_t *b;
    b = balloc(strlen(s));
    memcpy(b->data, s, b->size);

    return b;
}

buf_t *parse_var_bytes_ascii0(const char *s) {
    buf_t *b;
    b = balloc(strlen(s) + 1);
    memcpy(b->data, s, b->size);

    return b;
}

int parse_uint8(const char *s, uint8_t *o) {
    buf_t *b = parse_bytes(s, 1);

    if (!b)
        return -1;

    *o = b->data[0];
    bfree(b);

    return 0;
}

int parse_uint32(const char *s, uint32_t *o) {
    uint32_t *tmp;
    buf_t *b = parse_bytes(s, 4);

    if (!b)
        return -1;

    tmp = (uint32_t *)b->data;
    *o = be32toh(*tmp);
    bfree(b);

    return 0;
}

buf_t *parse_var_bytes_repeat(const char *cnt_, const char *val_) {
    buf_t *b;
    uint8_t val;
    uint32_t cnt;

    if (parse_uint32(cnt_, &cnt) != 0) {
        return 0;
    }

    if (parse_uint8(val_, &val) != 0) {
        return 0;
    }

    b = balloc(cnt);
    if (!b)
        return 0;

    memset(b->data, val, b->size);

    return b;
}

buf_t *parse_var_bytes_pattern(const char *pat, const char *len_) {
    buf_t *b;
    uint8_t val;
    uint32_t i, len;

    if (parse_uint32(len_, &len) != 0) {
        return 0;
    }

    b = balloc(len);
    if (!b)
        return 0;

    if (strcmp(pat, "cnt") == 0) {
        for (i = 0, val = 0; i < len; i++, val++)
            b->data[i] = val;

    } else if (strcmp(pat, "zero") == 0) {
        memset(b->data, 0, b->size);

    } else if (strcmp(pat, "ones") == 0) {
        memset(b->data, 0xff, b->size);

    } else {
        bfree(b);
        return 0;
    }

    return b;
}

// hex <hex-str>
// repeat <cnt> <val>
// pad cnt <cnt>
int parse_var_bytes_(buf_t **b_out, int argc, const char *argv[]) {
    buf_t *b;
    int i = 0;

    if (i >= argc)
        return 0;

    if (strcmp(argv[i], "help") == 0) {
        po("Supported sub-commands: hex <hex-str>, ascii <str>, ascii0 <str>, repeat <cnt> <val>, pattern (cnt|zero|ones) <cnt>\n");
        return -1;

    } else if (strcmp(argv[i], "hex") == 0) {
        i++;
        if (i >= argc) {
            return -1;
        }

        b = parse_var_bytes_hex(argv[i], 0);
        i += 1;

    } else if (strcmp(argv[i], "ascii") == 0) {
        i++;
        if (i >= argc) {
            return -1;
        }

        b = parse_var_bytes_ascii(argv[i]);
        i += 1;

    } else if (strcmp(argv[i], "ascii0") == 0) {
        i++;
        if (i >= argc) {
            return -1;
        }

        b = parse_var_bytes_ascii0(argv[i]);
        i += 1;

    } else if (strcmp(argv[i], "repeat") == 0) {
        i++;
        if (i + 2 > argc) {
            return -1;
        }

        b = parse_var_bytes_repeat(argv[i], argv[i + 1]);
        i += 2;

    } else if (strcmp(argv[i], "pattern") == 0) {
        i++;
        if (i + 2 > argc) {
            return -1;
        }

        b = parse_var_bytes_pattern(argv[i], argv[i + 1]);
        i += 2;

    } else {
        return 0;
    }

    if (b) {
        *b_out = b;
        return i;

    } else {
        return -1;

    }
}

int parse_var_bytes(buf_t **b_out, int argc, const char *argv[]) {
    int res;
    int i = 0;
    buf_t *b_res = 0;

    while (i < argc) {
        buf_t *b_tmp = 0;
        res = parse_var_bytes_(&b_tmp, argc - i, argv + i);

        if (res > 0) {
            i += res;
            if (b_res) {
                buf_t *b_new = balloc(b_res->size + b_tmp->size);
                if (!b_new) {
                    bfree(b_res);
                    bfree(b_tmp);
                    return -1;
                }

                memcpy(b_new->data, b_res->data, b_res->size);
                memcpy(b_new->data + b_res->size, b_tmp->data, b_tmp->size);
                bfree(b_res);
                bfree(b_tmp);
                b_tmp = 0;
                b_res = b_new;

            } else {
                b_res = b_tmp;
            }

        } else if (res == 0) {
            break;

        } else {
            bfree(b_res);
            bfree(b_tmp);
            return res;
        }
    }

    if (b_res && i)
        *b_out = b_res;

    return i;
}

int field_parse_multi_var_byte(struct hdr *hdr, int hdr_offset, struct field *f,
                               int argc, const char *argv[]) {
    int res;
    buf_t *b = 0;

    res = parse_var_bytes(&b, argc, argv);

    if (res > 1 && res <= argc) {
        f->val = b;
        f->bit_width = b->size * 8;
        hdr->size += b->size;

        return res;
    }

    if (b)
        bfree(b);

    return 0;
}

