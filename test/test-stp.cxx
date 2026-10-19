#include "ef.h"
#include "ef-test.h"
#include "catch_single_include.hxx"

#include <string>

// IEEE 802.1D-1998 clause 9.3 BPDUs. A BPDU is not an Ethernet II frame: the
// type/length field carries a length, followed by an 802.2 LLC header and the
// BPDU body. These tests pin the byte layout of both BPDU types.

// ef pads short frames to 60 bytes. Append the zeros rather than spelling them
// out, so the expectation says "this body, then padding" and cannot drift.
static std::string padded(const std::string &body) {
    size_t bytes = body.size() / 2;
    REQUIRE(body.size() % 2 == 0);
    REQUIRE(bytes <= 60);
    return body + std::string((60 - bytes) * 2, '0');
}

// The frame a real bridge emits, byte for byte.
static const char *bpdu_config_body =
    "0180c20000000011223344550026"           // eth, 802.3 length 38
    "424203"                                 // llc dsap/ssap/ctrl
    "0000" "00" "00" "00"                    // proto, ver, type, flags
    "8000" "001122334400"                    // root id
    "00000000"                               // root path cost
    "8000" "001122334400"                    // bridge id
    "8001"                                   // port id
    "0000" "1400" "0200" "0f00";             // msg age, max age, hello, fwd

TEST_CASE("stp: config BPDU byte layout matches a real bridge", "[stp]") {
    frame_t *f = parse_frame_wrap({
        "eth", "dmac", "01:80:c2:00:00:00", "smac", "00:11:22:33:44:55",
        "llc",
        "stp", "root_mac", "00:11:22:33:44:00",
               "bridge_mac", "00:11:22:33:44:00",
    });
    REQUIRE(f != nullptr);

    // hexstr() frees the buf it is handed.
    CHECK(hexstr(frame_to_buf(f)) == padded(bpdu_config_body));

    frame_free(f);
}

TEST_CASE("stp: every config field can be set explicitly", "[stp]") {
    frame_t *f = parse_frame_wrap({
        "eth", "dmac", "01:80:c2:00:00:00", "smac", "00:11:22:33:44:55",
        "llc", "dsap", "0x42", "ssap", "0x42", "ctrl", "0x03",
        "stp", "proto", "0x0000", "ver", "0", "type", "0", "flags", "0",
               "root_prio", "0x8000", "root_mac", "00:11:22:33:44:00",
               "root_cost", "0",
               "bridge_prio", "0x8000", "bridge_mac", "00:11:22:33:44:00",
               "port", "0x8001",
               "msg_age", "0x0000", "max_age", "0x1400",
               "hello", "0x0200", "fwd_delay", "0x0f00",
    });
    REQUIRE(f != nullptr);

    // Spelling out every field must land on the same bytes as the defaults.
    CHECK(hexstr(frame_to_buf(f)) == padded(bpdu_config_body));

    frame_free(f);
}

TEST_CASE("stp: tc and tcack are bit 0 and bit 7 of flags", "[stp]") {
    frame_t *tc = parse_frame_wrap({"eth", "llc", "stp", "tc", "1"});
    frame_t *ack = parse_frame_wrap({"eth", "llc", "stp", "tcack", "1"});
    frame_t *both = parse_frame_wrap({"eth", "llc", "stp", "flags", "0x81"});
    REQUIRE(tc != nullptr);
    REQUIRE(ack != nullptr);
    REQUIRE(both != nullptr);

    buf_t *b_tc = frame_to_buf(tc);
    buf_t *b_ack = frame_to_buf(ack);
    buf_t *b_both = frame_to_buf(both);
    REQUIRE(b_tc != nullptr);
    REQUIRE(b_ack != nullptr);
    REQUIRE(b_both != nullptr);

    // flags sits at eth(14) + llc(3) + proto/ver/type(4) = offset 21.
    CHECK(b_tc->data[21] == 0x01);
    CHECK(b_ack->data[21] == 0x80);
    CHECK(b_both->data[21] == 0x81);

    bfree(b_tc);
    bfree(b_ack);
    bfree(b_both);
    frame_free(tc);
    frame_free(ack);
    frame_free(both);
}

// The six bits between tc and tcack, which only the rapid protocol sets.
// 802.1Q table 13-5, read against the flags octet at offset 21.
TEST_CASE("stp: every flag bit lands in its own bit of the flags octet",
          "[stp]") {
    struct { const char *field; const char *value; uint8_t expect; } cases[] = {
        { "tc",         "1", 0x01 },
        { "proposal",   "1", 0x02 },
        { "role",       "1", 0x04 },   // alternate or backup
        { "role",       "2", 0x08 },   // root
        { "role",       "3", 0x0c },   // designated
        { "learning",   "1", 0x10 },
        { "forwarding", "1", 0x20 },
        { "agreement",  "1", 0x40 },
        { "tcack",      "1", 0x80 },
    };

    for (auto &c : cases) {
        frame_t *f = parse_frame_wrap({"eth", "llc", "stp", c.field, c.value});
        REQUIRE(f != nullptr);

        buf_t *b = frame_to_buf(f);
        REQUIRE(b != nullptr);

        // Only the named bit may be set, so the whole octet is the expectation.
        INFO("stp " << c.field << " " << c.value);
        CHECK(b->data[21] == c.expect);

        bfree(b);
        frame_free(f);
    }
}

TEST_CASE("stp: a designated port proposing sets four flag bits", "[stp]") {
    // What a designated port offers at the start of the clause 13.35
    // handshake: proposal, role designated, learning and forwarding.
    frame_t *named = parse_frame_wrap({
        "eth", "llc",
        "stp", "proposal", "1", "role", "3",
               "learning", "1", "forwarding", "1",
    });
    frame_t *byte = parse_frame_wrap({"eth", "llc", "stp", "flags", "0x3e"});
    REQUIRE(named != nullptr);
    REQUIRE(byte != nullptr);

    buf_t *b_named = frame_to_buf(named);
    buf_t *b_byte = frame_to_buf(byte);
    REQUIRE(b_named != nullptr);
    REQUIRE(b_byte != nullptr);

    // Naming the bits and spelling out the byte must agree.
    CHECK(b_named->data[21] == 0x3e);
    CHECK(bequal(b_named, b_byte) == 1);

    bfree(b_named);
    bfree(b_byte);
    frame_free(named);
    frame_free(byte);
}

TEST_CASE("stp: an unnamed flag bit stays out of the rx mask", "[stp]") {
    // Each bit alias overlays a byte that is itself a field, so an alias
    // carries rx_match_skip and only enters the mask when it is named.
    // Without that, "flags ign" could not narrow the byte at all.
    frame_t *one = parse_frame_wrap({
        "eth", "llc", "stp", "flags", "ign", "agreement", "1",
    });
    frame_t *two = parse_frame_wrap({
        "eth", "llc", "stp", "flags", "ign", "agreement", "1", "role", "3",
    });
    REQUIRE(one != nullptr);
    REQUIRE(two != nullptr);

    buf_t *m_one = frame_mask_to_buf(one);
    buf_t *m_two = frame_mask_to_buf(two);
    REQUIRE(m_one != nullptr);
    REQUIRE(m_two != nullptr);

    CHECK(m_one->data[21] == 0x40);   // agreement alone
    CHECK(m_two->data[21] == 0x4c);   // agreement and the two role bits

    bfree(m_one);
    bfree(m_two);
    frame_free(one);
    frame_free(two);
}

TEST_CASE("stp: ignoring a flag bit takes it out of the rx mask", "[stp]") {
    // "flags" is itself in the mask unless ignored, so an ignored bit alias
    // has to clear its own bits from it rather than merely add nothing.
    struct { const char *field; uint8_t expect; } cases[] = {
        { "tc",         0xfe },
        { "proposal",   0xfd },
        { "role",       0xf3 },
        { "learning",   0xef },
        { "forwarding", 0xdf },
        { "agreement",  0xbf },
        { "tcack",      0x7f },
    };

    for (const char *hdr : {"stp"}) {
        for (auto &c : cases) {
            frame_t *f = parse_frame_wrap({"eth", "llc", hdr, c.field, "ign"});
            REQUIRE(f != nullptr);
            CHECK(f->has_mask == 1);

            buf_t *mask = frame_mask_to_buf(f);
            REQUIRE(mask != nullptr);

            INFO(hdr << " " << c.field << " ign");
            CHECK(mask->data[21] == c.expect);
            // The rest of the BPDU is still compared.
            CHECK(mask->data[20] == 0xff);
            CHECK(mask->data[22] == 0xff);

            bfree(mask);
            frame_free(f);
        }
    }
}

TEST_CASE("stp: a BPDU differing only in an ignored bit still matches",
          "[stp]") {
    // "tc ign" must accept a BPDU whatever its tc bit, which it cannot do if
    // the flags byte around it is still compared in full.
    frame_t *expect = parse_frame_wrap({"eth", "llc", "stp", "tc", "ign"});
    frame_t *rx_tc = parse_frame_wrap({"eth", "llc", "stp", "tc", "1"});
    frame_t *rx_ack = parse_frame_wrap({"eth", "llc", "stp", "tcack", "1"});
    REQUIRE(expect != nullptr);
    REQUIRE(rx_tc != nullptr);
    REQUIRE(rx_ack != nullptr);

    buf_t *b_expect = frame_to_buf(expect);
    buf_t *mask = frame_mask_to_buf(expect);
    buf_t *b_tc = frame_to_buf(rx_tc);
    buf_t *b_ack = frame_to_buf(rx_ack);
    REQUIRE(b_expect != nullptr);
    REQUIRE(mask != nullptr);
    REQUIRE(b_tc != nullptr);
    REQUIRE(b_ack != nullptr);

    CHECK(bequal_mask(b_tc, b_expect, mask, 0) == 1);
    // Ignoring tc must not loosen the other seven bits.
    CHECK(bequal_mask(b_ack, b_expect, mask, 0) == 0);

    bfree(b_expect);
    bfree(mask);
    bfree(b_tc);
    bfree(b_ack);
    frame_free(expect);
    frame_free(rx_tc);
    frame_free(rx_ack);
}

TEST_CASE("stp: an ignored bit clears the mask whatever the field order",
          "[stp]") {
    // flags comes before tc in the field list, but the bit must come out of
    // an explicitly-set flags byte however the command line orders them.
    frame_t *a = parse_frame_wrap({"eth", "llc", "stp", "flags", "0x81",
                                   "tc", "ign"});
    frame_t *b = parse_frame_wrap({"eth", "llc", "stp", "tc", "ign",
                                   "flags", "0x81"});
    REQUIRE(a != nullptr);
    REQUIRE(b != nullptr);

    buf_t *m_a = frame_mask_to_buf(a);
    buf_t *m_b = frame_mask_to_buf(b);
    REQUIRE(m_a != nullptr);
    REQUIRE(m_b != nullptr);

    CHECK(m_a->data[21] == 0xfe);
    CHECK(m_b->data[21] == 0xfe);

    bfree(m_a);
    bfree(m_b);
    frame_free(a);
    frame_free(b);
}

TEST_CASE("stp: ignoring an overlapping non-overlay field changes nothing",
          "[stp]") {
    // IFH fields overlap as alternative encodings of the same bits, not as
    // views of a wider field. Ignoring one there must not erase the mask of
    // another that is compared: b1-rew-op stays compared in full.
    frame_t *f = parse_frame_wrap({"ifh-oc1", "ign", "b1-rew-op", "0",
                                   "b0-masq-port", "ign", "eth"});
    REQUIRE(f != nullptr);

    buf_t *mask = frame_mask_to_buf(f);
    REQUIRE(mask != nullptr);

    CHECK(mask->data[0] == 0x3f);
    CHECK(mask->data[1] == 0xe0);

    bfree(mask);
    frame_free(f);
}

TEST_CASE("stp: TCN BPDU is a four-byte body", "[stp]") {
    frame_t *f = parse_frame_wrap({
        "eth", "dmac", "01:80:c2:00:00:00", "smac", "00:11:22:33:44:55",
        "llc", "stp_tcn",
    });
    REQUIRE(f != nullptr);

    CHECK(hexstr(frame_to_buf(f)) ==
          padded("0180c20000000011223344550007"   // eth, 802.3 length 7
                 "424203"                         // llc
                 "00000080"));                    // proto, ver, type=TCN

    frame_free(f);
}

TEST_CASE("stp: a config BPDU can be matched field by field", "[stp]") {
    // What an "rx" command builds: a value buf and a mask with every
    // specified field set to all-ones. Mirrors argc_cmd() in ef-args.c.
    frame_t *exact = parse_frame_wrap({
        "eth", "dmac", "01:80:c2:00:00:00", "smac", "00:11:22:33:44:55",
        "llc", "stp", "tc", "1",
    });
    frame_t *masked = parse_frame_wrap({
        "eth", "dmac", "01:80:c2:00:00:00", "smac", "00:11:22:33:44:55",
        "llc", "stp", "flags", "ign", "tc", "1",
    });
    REQUIRE(exact != nullptr);
    REQUIRE(masked != nullptr);
    CHECK(masked->has_mask == 1);

    buf_t *b_exact = frame_to_buf(exact);
    buf_t *b_masked = frame_to_buf(masked);
    buf_t *mask = frame_mask_to_buf(masked);
    REQUIRE(b_exact != nullptr);
    REQUIRE(b_masked != nullptr);
    REQUIRE(mask != nullptr);

    // "flags ign tc 1" must still pin tc, so only bit 0 of the flags byte
    // is compared and the received value must have it set. The other seven
    // bit aliases carry rx_match_skip, so an unnamed one adds nothing.
    CHECK(mask->data[21] == 0x01);
    CHECK(bequal_mask(b_exact, b_masked, mask, 0) == 1);

    bfree(b_exact);
    bfree(b_masked);
    bfree(mask);
    frame_free(exact);
    frame_free(masked);
}
