#include "ef.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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
    {HAS_BASE_2,  "01" },
    {HAS_BASE_8,  "234567" },
    {HAS_BASE_10, "89" },
    {HAS_BASE_16, "aAbBcCdDeEfF" },
    {HAS_DOT,     "." },
    {HAS_COLON,   ":" },
};

buf_t *parse_bytes(const char *s, int bytes) {
    buf_t *b;
    int base, s_size = strlen(s);
    const char *s_begin = s, *data_begin = s;
    const char *data_end = data_begin + s_size;
    uint32_t has_mask = 0;
    int i, has_other = 0;
    uint32_t start_mask = 0;

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
            for (const char *set_i = has_chars[i].char_set; *set_i; ++set_i) {
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
    //printf("line: %d\n", __LINE__);
    //printf("%08x %08x %d %d\n", start_mask, has_mask, has_other, bytes);
    if (start_mask == START_WITH_0x && !has_other &&
        ((has_mask & ~(HAS_BASE_2 | HAS_BASE_8 | HAS_BASE_10 | HAS_BASE_16)) == 0)) {
        //printf("line: %d\n", __LINE__);
        base = 16;

    } else if (start_mask == 0 && !has_other &&
               ((has_mask & ~(HAS_BASE_2 | HAS_BASE_8 | HAS_BASE_10)) == 0)) {
        //printf("line: %d\n", __LINE__);
        base = 10;

    } else if (start_mask == START_WITH_0o && !has_other &&
               ((has_mask & ~(HAS_BASE_2 | HAS_BASE_8)) == 0)) {
        //printf("line: %d\n", __LINE__);
        base = 8;

    } else if (start_mask == START_WITH_0b && !has_other &&
               ((has_mask & ~(HAS_BASE_2)) == 0)) {
        //printf("line: %d\n", __LINE__);
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
    }

    //printf("line: %d %d %d\n", __LINE__, bytes, has_other);
    //printf("line: %d %d\n", __LINE__, has_mask & ~(HAS_HEX_COL));
    //printf("line: %d %d\n", __LINE__, has_mask & HAS_COLON);

    if (start_mask == 0 && !has_other &&
        ((has_mask & ~(HAS_BASE_2 | HAS_BASE_8)) ==
         (HAS_BASE_10 | HAS_DOT))) {

        //printf("line: %d\n", __LINE__);

    } else if (start_mask == 0 && bytes == 4 && !has_other &&
               ((has_mask & ~(HAS_HEX_DOT)) == 0) && (has_mask & HAS_DOT)) {
        // This will be treated as an IPv4
        unsigned char buf[sizeof(struct in6_addr)];
        //printf("line: %d\n", __LINE__);

        if (inet_pton(AF_INET, data_begin, buf) == 1) {
            b = balloc(4);
            if (!b)
                return b;
            memcpy(b->data, buf, 4);

            return b;

        } else {
            return 0;
        }

    } else if (start_mask == 0 && bytes == 6 && !has_other &&
               ((has_mask & ~(HAS_HEX_COL)) == 0) && (has_mask & HAS_COLON)) {
        // This will be treated as a mac-address
        uint8_t m[6] = {};

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

        //printf("line: %d\n", __LINE__);

        for (const char *x = data_begin; *x; ++x) {
            int colon = 0;
            int val = 0;

            if (*x >= '0' && *x <= '9') {
                val = *x - '0';

            } else if (*x >= 'a' && *x <= 'f') {
                val = *x - 'a';

            } else if (*x >= 'A' && *x <= 'F') {
                val = *x - 'A';

            } else if (*x == ':') {
                colon = 1;

            } else {
                return 0;

            }

            //printf("%d val:%x val_cnt:%d col_cnt:%d, idx:%d colon:%d\n",
            //       __LINE__, val, val_cnt, col_cnt, idx, colon);

            if (idx > 5)
                return 0;

            if (colon) {
                if (val_cnt != 0 && col_cnt == 0)
                    idx++;

                val_cnt = 0;
                col_cnt ++;

                if (col_cnt == 2) {
                    split_cnt ++;

                    if (split_cnt > 1)
                        return 0;

                    if (split) {
                        return 0;
                    } else {
                        split = idx;
                    }
                } else if (col_cnt > 2) {
                    return 0;
                }

            } else {
                val_cnt ++;
                col_cnt = 0;

                if (val_cnt > 2)
                    return 0;

                if (val_cnt == 1)
                    element_cnt ++;
                m[idx] <<= 4;
                m[idx] |= val;

                //printf("line: %d, idx: %d, %02x\n", __LINE__, idx, m[idx]);
            }
        }

        if (split_cnt > 1)
            return 0;

        if (element_cnt > 6)
            return 0;

        if (element_cnt >= 6 && split_cnt > 0)
            return 0;

        move_from = split;
        move_to = 6 - element_cnt + split;
        move_size = element_cnt - split;

        //printf("%d split:%d element_cnt:%d from:%d, to:%d, size:%d\n",
        //       __LINE__, split, element_cnt, move_from, move_to, move_size);

        //printf("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0],  m[1], m[2], m[3], m[4], m[5]);

        memmove(m + move_to, m + move_from, move_size);
        //printf("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0],  m[1], m[2], m[3], m[4], m[5]);
        memset(m + split, 0, move_to - move_from);

        //printf("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0],  m[1], m[2], m[3], m[4], m[5]);

        b = balloc(6);
        if (!b)
            return b;
        memcpy(b->data, m, 6);

        return b;


    } else if (start_mask == 0 && bytes == 16 && !has_other &&
               ((has_mask & ~(HAS_HEX_COL | HAS_DOT)) == 0) &&
               (has_mask & HAS_COLON)) {

        // This will be treated as an IPv6
        unsigned char buf[sizeof(struct in6_addr)];
        //printf("line: %d\n", __LINE__);

        if (inet_pton(AF_INET6, data_begin, buf) == 1) {
            b = balloc(16);
            if (!b)
                return b;
            memcpy(b->data, buf, 16);

            return b;

        } else {
            return 0;

        }
    }

    return 0;
}

