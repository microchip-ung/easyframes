#include "ef.h"

#include <vector>
#include "catch_single_include.hxx"

struct HexBuf {
    HexBuf(int _s, const char *_d) : s(_s), d(_d) { }

    int s;
    std::string d;
};

std::string hexstr(buf_t *b) {
    char bb[8];
    std::string s;

    if (!b)
        return "<NULL>";

    for (size_t i = 0; i < b->size; ++i) {
        snprintf(bb, 8, "%02x", b->data[i]);
        s.append(bb);
    }

    bfree(b);

    return s;
}

std::ostream& operator<<(std::ostream& o, const HexBuf &b) {
    o << b.d;
    return o;
}

//std::ostream& operator<<(std::ostream& o, const buf_t &b) {
//    o << hexstr(b);
//    return o;
//}

//std::ostream& operator<<(std::ostream& o, buf_t *b) {
//    if (!b) {
//        o << "<null>";
//        return o;
//    }
//
//    return operator<<(o, *b);
//}

TEST_CASE("parse_bytes", "[parse_bytes]" ) {
    CHECK(hexstr(parse_bytes("5", 4)) == "00000005");
    CHECK(hexstr(parse_bytes("5", 3)) == "000005");
    CHECK(hexstr(parse_bytes("5", 2)) == "0005");
    CHECK(hexstr(parse_bytes("5", 1)) == "05");
    CHECK(hexstr(parse_bytes("100", 4)) == "00000064");
    CHECK(hexstr(parse_bytes("77", 4)) == "0000004d");
    CHECK(hexstr(parse_bytes("1234", 4)) == "000004d2");
    CHECK(hexstr(parse_bytes("0x0800", 2)) == "0800");
    CHECK(hexstr(parse_bytes("0b1111", 2)) == "000f");
    CHECK(hexstr(parse_bytes("::1", 16)) ==
          "00000000000000000000000000000001");
    CHECK(hexstr(parse_bytes("2000::10.1.2.3", 16)) ==
          "2000000000000000000000000a010203");
    CHECK(hexstr(parse_bytes("10.1.2.3", 4)) == "0a010203");
    CHECK(hexstr(parse_bytes("10.1.2.8", 4)) == "0a010208");
    CHECK(hexstr(parse_bytes("10.0.99.2", 4)) == "0a006302");

    CHECK(!parse_bytes(":::", 6));
    CHECK(!parse_bytes("00::00::00", 6));
    CHECK(!parse_bytes("::00::00", 6));

    CHECK(hexstr(parse_bytes("::", 6)) == "000000000000");
    CHECK(hexstr(parse_bytes("::1", 6)) == "000000000001");
    CHECK(hexstr(parse_bytes("::1:2", 6)) == "000000000102");
    CHECK(hexstr(parse_bytes("::1:2:3", 6)) == "000000010203");
    CHECK(hexstr(parse_bytes("::1:2:3:4", 6)) == "000001020304");
    CHECK(hexstr(parse_bytes("::1:2:3:4:5", 6)) == "000102030405");
    CHECK(!parse_bytes("::1:2:3:4:5:6", 6));
    CHECK(!parse_bytes("::1:2:3:4:5:6:7", 6));

    CHECK(hexstr(parse_bytes("10::", 6)) == "100000000000");
    CHECK(hexstr(parse_bytes("10::1", 6)) == "100000000001");
    CHECK(hexstr(parse_bytes("10::1:2", 6)) == "100000000102");
    CHECK(hexstr(parse_bytes("10::1:2:3", 6)) == "100000010203");
    CHECK(hexstr(parse_bytes("10::1:2:3:4", 6)) == "100001020304");
    CHECK(!parse_bytes("10::1:2:3:4:5", 6));
    CHECK(!parse_bytes("10::1:2:3:4:5:6", 6));

    CHECK(hexstr(parse_bytes("10:20::", 6)) == "102000000000");
    CHECK(hexstr(parse_bytes("10:20::1", 6)) == "102000000001");
    CHECK(hexstr(parse_bytes("10:20::1:2", 6)) == "102000000102");
    CHECK(hexstr(parse_bytes("10:20::1:2:3", 6)) == "102000010203");
    CHECK(!parse_bytes("10:20::1:2:3:4", 6));
    CHECK(!parse_bytes("10:20::1:2:3:4:5", 6));

    CHECK(hexstr(parse_bytes("10:20:30::", 6)) == "102030000000");
    CHECK(hexstr(parse_bytes("10:20:30::1", 6)) == "102030000001");
    CHECK(hexstr(parse_bytes("10:20:30::1:2", 6)) == "102030000102");
    CHECK(!parse_bytes("10:20:30::1:2:3", 6));
    CHECK(!parse_bytes("10:20:30::1:2:3:4", 6));

    CHECK(hexstr(parse_bytes("10:20:30:40::", 6)) == "102030400000");
    CHECK(hexstr(parse_bytes("10:20:30:40::1", 6)) == "102030400001");
    CHECK(!parse_bytes("10:20:30:40::1:2", 6));
    CHECK(!parse_bytes("10:20:30:40::1:2:3", 6));

    CHECK(hexstr(parse_bytes("10:20:30:40:50::", 6)) == "102030405000");
    CHECK(!parse_bytes("10:20:30:40:50::1", 6));
    CHECK(!parse_bytes("10:20:30:40:50::1:2", 6));

    CHECK(hexstr(parse_bytes("a::4", 6)) == "0a0000000004");
    CHECK(hexstr(parse_bytes("0a::4", 6)) == "0a0000000004");
    CHECK(hexstr(parse_bytes("a0::4", 6)) == "a00000000004");

    CHECK(hexstr(parse_bytes("B::5", 6)) == "0b0000000005");
    CHECK(hexstr(parse_bytes("0B::5", 6)) == "0b0000000005");
    CHECK(hexstr(parse_bytes("B0::5", 6)) == "b00000000005");

        // ::      -> 00:00:00:00:00:00
        // ::1     -> 00:00:00:00:00:01
        // 1::     -> 01:00:00:00:00:00
        // 01::20  -> 01:00:00:00:00:20
        // 1::2    -> 01:00:00:00:00:02
        // 1:2::3  -> 01:02:00:00:00:03
}

TEST_CASE("hdr_write_field", "[hdr_write_field]" ) {
#define X(VAL_SIZE, VAL, WIDTH, OFFSET, OUT_SIZE, OUT)                                    \
    {                                                                                     \
        buf_t *b1 = balloc(OUT_SIZE);                                                     \
        buf_t *b2 = parse_bytes(VAL, VAL_SIZE);                                           \
        field_t f = { .name = "", .help = "", .bit_width = WIDTH, .bit_offset = OFFSET }; \
        hdr_write_field(b1, 0, &f, b2);                                                   \
                                                                                          \
        CHECK(hexstr(b1) == OUT);                                                         \
        bfree(b2);                                                                        \
    }

    /*
    X(3, "0x112233", 24,  0, 18, "112233000000000000000000000000000000");
    X(3, "0x112233", 24, 16, 18, "000011223300000000000000000000000000");
    */

    X(1, "0x1", 1,  0, 3, "800000");
    X(1, "0x1", 1,  1, 3, "400000");
    X(1, "0x1", 1,  2, 3, "200000");
    X(1, "0x1", 1,  3, 3, "100000");
    X(1, "0x1", 1,  4, 3, "080000");
    X(1, "0x1", 1,  5, 3, "040000");
    X(1, "0x1", 1,  6, 3, "020000");
    X(1, "0x1", 1,  7, 3, "010000");
    X(1, "0x1", 1,  8, 3, "008000");
    X(1, "0x1", 1,  9, 3, "004000");
    X(1, "0x1", 1, 10, 3, "002000");
    X(1, "0x1", 1, 11, 3, "001000");
    X(1, "0x1", 1, 12, 3, "000800");
    X(1, "0x1", 1, 13, 3, "000400");
    X(1, "0x1", 1, 14, 3, "000200");
    X(1, "0x1", 1, 15, 3, "000100");
    X(1, "0x1", 1, 16, 3, "000080");
    X(1, "0x1", 1, 17, 3, "000040");
    X(1, "0x1", 1, 18, 3, "000020");
    X(1, "0x1", 1, 19, 3, "000010");
    X(1, "0x1", 1, 20, 3, "000008");
    X(1, "0x1", 1, 21, 3, "000004");
    X(1, "0x1", 1, 22, 3, "000002");
    X(1, "0x1", 1, 23, 3, "000001");

    X(1, "0x3", 2,  0, 3, "c00000");
    X(1, "0x3", 2,  1, 3, "600000");
    X(1, "0x3", 2,  2, 3, "300000");
    X(1, "0x3", 2,  3, 3, "180000");
    X(1, "0x3", 2,  4, 3, "0c0000");
    X(1, "0x3", 2,  5, 3, "060000");
    X(1, "0x3", 2,  6, 3, "030000");

    X(1, "0x3", 2,  7, 3, "018000");
    X(1, "0x2", 2,  7, 3, "010000");
    X(1, "0x1", 2,  7, 3, "008000");

    X(1, "0x3", 2,  8, 3, "00c000");
    X(1, "0x3", 2,  9, 3, "006000");
    X(1, "0x3", 2, 10, 3, "003000");
    X(1, "0x3", 2, 11, 3, "001800");
    X(1, "0x3", 2, 12, 3, "000c00");
    X(1, "0x3", 2, 13, 3, "000600");
    X(1, "0x3", 2, 14, 3, "000300");
    X(1, "0x3", 2, 15, 3, "000180");
    X(1, "0x3", 2, 16, 3, "0000c0");
    X(1, "0x3", 2, 17, 3, "000060");
    X(1, "0x3", 2, 18, 3, "000030");
    X(1, "0x3", 2, 19, 3, "000018");
    X(1, "0x3", 2, 20, 3, "00000c");
    X(1, "0x3", 2, 21, 3, "000006");
    X(1, "0x3", 2, 22, 3, "000003");

    X(1, "0x7", 3,  0, 3, "e00000");
    X(1, "0x7", 3,  1, 3, "700000");
    X(1, "0x7", 3,  2, 3, "380000");
    X(1, "0x7", 3,  3, 3, "1c0000");
    X(1, "0x7", 3,  4, 3, "0e0000");
    X(1, "0x7", 3,  5, 3, "070000");
    X(1, "0x7", 3,  6, 3, "038000");
    X(1, "0x7", 3,  7, 3, "01c000");
    X(1, "0x7", 3,  8, 3, "00e000");
    X(1, "0x7", 3,  9, 3, "007000");
    X(1, "0x7", 3, 10, 3, "003800");
    X(1, "0x7", 3, 11, 3, "001c00");
    X(1, "0x7", 3, 12, 3, "000e00");
    X(1, "0x7", 3, 13, 3, "000700");
    X(1, "0x7", 3, 14, 3, "000380");
    X(1, "0x7", 3, 15, 3, "0001c0");
    X(1, "0x7", 3, 16, 3, "0000e0");
    X(1, "0x7", 3, 17, 3, "000070");
    X(1, "0x7", 3, 18, 3, "000038");
    X(1, "0x7", 3, 19, 3, "00001c");
    X(1, "0x7", 3, 20, 3, "00000e");
    X(1, "0x7", 3, 21, 3, "000007");

    // 0000 0
    // 0001 1
    // 0010 2
    // 0011 3
    // 0100 4
    // 0101 5
    // 0110 6
    // 0111 7
    // 1000 8
    // 1001 9
    // 1010 a
    // 1011 b
    // 1100 c
    // 1101 d
    // 1110 e
    // 1111 f

    X(1, "0xff", 8,  0, 3, "ff0000");
    X(1, "0xff", 8,  1, 3, "7f8000");
    X(1, "0xff", 8,  2, 3, "3fc000");
    X(1, "0xff", 8,  3, 3, "1fe000");
    X(1, "0xff", 8,  4, 3, "0ff000");
    X(1, "0xff", 8,  5, 3, "07f800");
    X(1, "0xff", 8,  6, 3, "03fc00");
    X(1, "0xff", 8,  7, 3, "01fe00");
    X(1, "0xff", 8,  8, 3, "00ff00");
    X(1, "0xff", 8,  9, 3, "007f80");
    X(1, "0xff", 8, 10, 3, "003fc0");
    X(1, "0xff", 8, 11, 3, "001fe0");
    X(1, "0xff", 8, 12, 3, "000ff0");
    X(1, "0xff", 8, 13, 3, "0007f8");
    X(1, "0xff", 8, 14, 3, "0003fc");
    X(1, "0xff", 8, 15, 3, "0001fe");
    X(1, "0xff", 8, 16, 3, "0000ff");

    X(2, "0xfff", 12,  0, 10, "fff00000000000000000");
    X(2, "0xfff", 12,  1, 10, "7ff80000000000000000");
    X(2, "0xfff", 12,  2, 10, "3ffc0000000000000000");
    X(2, "0xfff", 12,  3, 10, "1ffe0000000000000000");
    X(2, "0xfff", 12,  4, 10, "0fff0000000000000000");
    X(2, "0xfff", 12,  5, 10, "07ff8000000000000000");
    X(2, "0xfff", 12,  6, 10, "03ffc000000000000000");
    X(2, "0xfff", 12,  7, 10, "01ffe000000000000000");
    X(2, "0xfff", 12,  8, 10, "00fff000000000000000");
    X(2, "0xfff", 12,  9, 10, "007ff800000000000000");
    X(2, "0xfff", 12, 10, 10, "003ffc00000000000000");
    X(2, "0xfff", 12, 11, 10, "001ffe00000000000000");
    X(2, "0xfff", 12, 12, 10, "000fff00000000000000");
    X(2, "0xfff", 12, 13, 10, "0007ff80000000000000");
    X(2, "0xfff", 12, 14, 10, "0003ffc0000000000000");
    X(2, "0xfff", 12, 15, 10, "0001ffe0000000000000");
    X(2, "0xfff", 12, 16, 10, "0000fff0000000000000");
    X(2, "0xfff", 12, 17, 10, "00007ff8000000000000");
    X(2, "0xfff", 12, 18, 10, "00003ffc000000000000");
    X(2, "0xfff", 12, 19, 10, "00001ffe000000000000");
    X(2, "0xfff", 12, 20, 10, "00000fff000000000000");
    X(2, "0xfff", 12, 21, 10, "000007ff800000000000");
    X(2, "0xfff", 12, 22, 10, "000003ffc00000000000");
    X(2, "0xfff", 12, 23, 10, "000001ffe00000000000");

    X(6, "0xffffffffffff", 48,  0, 10, "ffffffffffff00000000");
    X(6, "0xffffffffffff", 48,  1, 10, "7fffffffffff80000000");
    X(6, "0xffffffffffff", 48,  2, 10, "3fffffffffffc0000000");
    X(6, "0xffffffffffff", 48,  3, 10, "1fffffffffffe0000000");
    X(6, "0xffffffffffff", 48,  4, 10, "0ffffffffffff0000000");
    X(6, "0xffffffffffff", 48,  5, 10, "07fffffffffff8000000");
    X(6, "0xffffffffffff", 48,  6, 10, "03fffffffffffc000000");
    X(6, "0xffffffffffff", 48,  7, 10, "01fffffffffffe000000");
    X(6, "0xffffffffffff", 48,  8, 10, "00ffffffffffff000000");
    X(6, "0xffffffffffff", 48,  9, 10, "007fffffffffff800000");
    X(6, "0xffffffffffff", 48, 10, 10, "003fffffffffffc00000");
    X(6, "0xffffffffffff", 48, 11, 10, "001fffffffffffe00000");
    X(6, "0xffffffffffff", 48, 12, 10, "000ffffffffffff00000");
    X(6, "0xffffffffffff", 48, 13, 10, "0007fffffffffff80000");
    X(6, "0xffffffffffff", 48, 14, 10, "0003fffffffffffc0000");
    X(6, "0xffffffffffff", 48, 15, 10, "0001fffffffffffe0000");
    X(6, "0xffffffffffff", 48, 16, 10, "0000ffffffffffff0000");
    X(6, "0xffffffffffff", 48, 17, 10, "00007fffffffffff8000");
    X(6, "0xffffffffffff", 48, 18, 10, "00003fffffffffffc000");
    X(6, "0xffffffffffff", 48, 19, 10, "00001fffffffffffe000");
    X(6, "0xffffffffffff", 48, 20, 10, "00000ffffffffffff000");
    X(6, "0xffffffffffff", 48, 21, 10, "000007fffffffffff800");
    X(6, "0xffffffffffff", 48, 22, 10, "000003fffffffffffc00");
    X(6, "0xffffffffffff", 48, 23, 10, "000001fffffffffffe00");
    X(6, "0xffffffffffff", 48, 24, 10, "000000ffffffffffff00");
    X(6, "0xffffffffffff", 48, 25, 10, "0000007fffffffffff80");
    X(6, "0xffffffffffff", 48, 26, 10, "0000003fffffffffffc0");
    X(6, "0xffffffffffff", 48, 27, 10, "0000001fffffffffffe0");
    X(6, "0xffffffffffff", 48, 28, 10, "0000000ffffffffffff0");
    X(6, "0xffffffffffff", 48, 29, 10, "00000007fffffffffff8");
    X(6, "0xffffffffffff", 48, 30, 10, "00000003fffffffffffc");
    X(6, "0xffffffffffff", 48, 31, 10, "00000001fffffffffffe");
    X(6, "0xffffffffffff", 48, 32, 10, "00000000ffffffffffff");

    //X(3, "0x0abcde", 20,  0, 10, "abcde000000000000000");
    //X(3, "0xfffff", 20,  1, 10, "fe0100");
    //X(3, "0xfffff", 20,  2, 10, "fc0300");
    //X(3, "0xfffff", 20,  3, 10, "f80700");
    //X(3, "0xfffff", 20,  4, 10, "f00f00");
    //X(3, "0xfffff", 20,  5, 10, "e01f00");
    //X(3, "0xfffff", 20,  6, 10, "c03f00");
    //X(3, "0xfffff", 20,  7, 10, "807f00");
    //X(3, "0xfffff", 20,  8, 10, "00ff00");
    //X(3, "0xfffff", 20,  9, 10, "00fe01");
    //X(3, "0xfffff", 20, 10, 10, "00fc03");
    //X(3, "0xfffff", 20, 11, 10, "00f807");
    //X(3, "0xfffff", 20, 12, 10, "00f00f");
    //X(3, "0xfffff", 20, 13, 10, "00e01f");
    //X(3, "0xfffff", 20, 14, 10, "00c03f");
    //X(3, "0xfffff", 20, 15, 10, "00807f");
    //X(3, "0xfffff", 20, 16, 10, "0000ff");

    buf_t *b1 = balloc(10);
    buf_t *b2 = parse_bytes("0x4", 1);
    buf_t *b3 = parse_bytes("0x5", 1);
    field_t f1 = { .name = "", .help = "", .bit_width = 4, .bit_offset = 0};
    field_t f2 = { .name = "", .help = "", .bit_width = 4, .bit_offset = 4};
    hdr_write_field(b1, 0, &f1, b2);
    hdr_write_field(b1, 0, &f2, b3);
    CHECK(hexstr(b1) == "45000000000000000000");
    bfree(b2);
    bfree(b3);
#undef X
}


buf_t *parse_var_bytes_wrap(std::vector<const char *> ptrs) {
    buf_t *b = 0;
    parse_var_bytes(&b, ptrs.size(), ptrs.data());
    //CHECK(res == ptrs.size());
    return b;
}

TEST_CASE("parse_var_bytes", "[parse_var_bytes]" ) {
#define X(EXPECT, ...)                                     \
    {                                                      \
        buf_t *b1 = parse_var_bytes_wrap({ __VA_ARGS__ }); \
        CHECK(hexstr(b1) == EXPECT);                       \
    }

    X("fedeabe0badebabe0011223344", "hex", "fedeabe0badebabe0011223344");
    X("fedeabe0badebabe0011223344", "hex", "fede.abe0:bade-babe-0011223344");
    X("48656c6c6f20776f726c64", "ascii", "Hello world");
    X("48656c6c6f20776f726c6400", "ascii0", "Hello world");

    X("ab",       "repeat", "1", "0xab");
    X("abab",     "repeat", "2", "0xab");
    X("ababab",   "repeat", "3", "0xab");
    X("abababab", "repeat", "4", "0xab");
    X("64646464", "repeat", "4", "100");

    {
        buf_t *b1 = parse_var_bytes_wrap({"repeat", "10000", "0xab"});
        CHECK(b1->size == 10000);
        char b2[10000];
        memset(b2, 0xab, 10000);
        CHECK(memcmp(b1->data, b2, 10000) == 0);
    }

    X("000102030405060708090a0b0c0d0e0f10111213", "pattern", "cnt", "20");
    X("0000000000000000000000000000000000000000", "pattern", "zero", "20");
    X("ffffffffffffffffffffffffffffffffffffffff", "pattern", "ones", "20");

    X("aaaaaaaaaaaaaaaaaaaaacef00010203040506070809",
      "repeat", "10", "0xaa", "hex", "acef", "pattern", "cnt", "10");

#undef X
}
