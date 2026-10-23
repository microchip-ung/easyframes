#include "ef.h"
#include "ef-test.h"
#include "catch_single_include.hxx"

// An 802.2 LLC header is preceded by a length, not an EtherType. The tests
// below pin the length llc computes into the header below it, and the cases
// where it must keep its hands off that field.

TEST_CASE("llc: 802.3 length counts llc plus everything above it", "[llc]") {
    struct {
        const char *what;
        std::vector<const char *> spec;
        uint8_t hi, lo;
    } cases[] = {
        // llc(3) on its own
        {"bare llc", {"eth", "llc"}, 0x00, 0x03},
        // llc(3) + 4 bytes of payload
        {"llc + payload", {"eth", "llc", "data", "hex", "deadbeef"},
         0x00, 0x07},
        // llc(3) + 46 bytes of payload, past the 60-byte pad boundary
        {"llc + long payload",
         {"eth", "llc", "data", "hex",
          "000102030405060708090a0b0c0d0e0f"
          "101112131415161718191a1b1c1d1e1f"
          "202122232425262728292a2b2c2d"},
         0x00, 0x31},
    };

    for (auto &c : cases) {
        SECTION(c.what) {
            frame_t *f = parse_frame_wrap(c.spec);
            REQUIRE(f != nullptr);

            buf_t *b = frame_to_buf(f);
            REQUIRE(b != nullptr);

            // The length replaces the EtherType in the eth header, bytes 12:13.
            CHECK(b->data[12] == c.hi);
            CHECK(b->data[13] == c.lo);

            bfree(b);
            frame_free(f);
        }
    }
}

TEST_CASE("llc: default dsap/ssap/ctrl are the STP SAPs", "[llc]") {
    frame_t *f = parse_frame_wrap({"eth", "llc"});
    REQUIRE(f != nullptr);

    buf_t *b = frame_to_buf(f);
    REQUIRE(b != nullptr);

    CHECK(b->data[14] == 0x42);
    CHECK(b->data[15] == 0x42);
    CHECK(b->data[16] == 0x03);

    bfree(b);
    frame_free(f);
}

TEST_CASE("llc: an explicit et on the eth header wins", "[llc]") {
    frame_t *f = parse_frame_wrap({"eth", "et", "0x1234", "llc"});
    REQUIRE(f != nullptr);

    buf_t *b = frame_to_buf(f);
    REQUIRE(b != nullptr);

    // llc_fill_defaults must not overwrite a value the user asked for.
    CHECK(b->data[12] == 0x12);
    CHECK(b->data[13] == 0x34);

    bfree(b);
    frame_free(f);
}

TEST_CASE("llc: the length lands in the outermost vlan tag", "[llc]") {
    frame_t *f = parse_frame_wrap({"eth", "ctag", "vid", "100", "llc",
                                   "data", "hex", "deadbeef"});
    REQUIRE(f != nullptr);

    buf_t *b = frame_to_buf(f);
    REQUIRE(b != nullptr);

    // eth.et becomes the ctag TPID, and the ctag's own "et" field at bytes
    // 16:17 carries the 802.3 length of llc(3) + payload(4).
    CHECK(b->data[12] == 0x81);
    CHECK(b->data[13] == 0x00);
    CHECK(b->data[16] == 0x00);
    CHECK(b->data[17] == 0x07);

    bfree(b);
    frame_free(f);
}

TEST_CASE("llc: a length past 1500 is refused, not misencoded", "[llc]") {
    // 1497 bytes of payload is the most an llc(3) frame can carry. One more
    // would put 1501 in the length field, and 1536 or more reads as an
    // EtherType; 65538 does not even fit in the field.
    frame_t *max = parse_frame_wrap({"eth", "llc", "data", "repeat", "1497",
                                     "0"});
    frame_t *over = parse_frame_wrap({"eth", "llc", "data", "repeat", "1498",
                                      "0"});
    frame_t *wrap = parse_frame_wrap({"eth", "llc", "data", "repeat",
                                      "65535", "0"});
    REQUIRE(max != nullptr);
    REQUIRE(over != nullptr);
    REQUIRE(wrap != nullptr);

    buf_t *b = frame_to_buf(max);
    REQUIRE(b != nullptr);
    CHECK(b->data[12] == 0x05);
    CHECK(b->data[13] == 0xdc);
    bfree(b);

    CHECK(frame_to_buf(over) == nullptr);
    CHECK(frame_to_buf(wrap) == nullptr);

    frame_free(max);
    frame_free(over);
    frame_free(wrap);
}

TEST_CASE("llc: an explicit et lifts the length limit", "[llc]") {
    // A test that wants the malformed frame on purpose can still have it.
    frame_t *f = parse_frame_wrap({"eth", "et", "0x0602", "llc",
                                   "data", "repeat", "1500", "0"});
    REQUIRE(f != nullptr);

    buf_t *b = frame_to_buf(f);
    REQUIRE(b != nullptr);
    CHECK(b->data[12] == 0x06);
    CHECK(b->data[13] == 0x02);

    bfree(b);
    frame_free(f);
}
