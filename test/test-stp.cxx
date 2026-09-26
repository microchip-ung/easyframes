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
    // is compared and the received value must have it set.
    CHECK(mask->data[21] == 0x81);
    CHECK(bequal_mask(b_exact, b_masked, mask, 0) == 1);

    bfree(b_exact);
    bfree(b_masked);
    bfree(mask);
    frame_free(exact);
    frame_free(masked);
}
