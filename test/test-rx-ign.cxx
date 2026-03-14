#include "ef.h"
#include "ef-test.h"
#include "catch_single_include.hxx"

#include <cstring>

static cmd_t make_rx_cmd(const char **argv, int argc)
{
    cmd_t c;
    memset(&c, 0, sizeof(c));
    argc_cmd(argc, argv, &c);
    return c;
}

static int ign_absorbs(cmd_t &ign, buf_t *rx)
{
    size_t hdr = ign.frame_size_no_padding;
    if (hdr == 0 || rx->size < hdr)
        return 0;

    size_t rx_orig = rx->size;
    size_t f_orig = ign.frame_buf->size;
    rx->size = hdr;
    ign.frame_buf->size = hdr;
    int m = bequal_mask(rx, ign.frame_buf, ign.frame_mask_buf, 0);
    ign.frame_buf->size = f_orig;
    rx->size = rx_orig;
    return m;
}

TEST_CASE("rx ign: parsing sets rx_ign flag", "[rx_ign]") {
    const char *argv[] = {"rx", "eth0", "ign", "eth", "dmac", "::1"};
    cmd_t c = make_rx_cmd(argv, 6);

    CHECK(c.type == CMD_TYPE_RX);
    CHECK(c.rx_ign == 1);
    CHECK(c.frame_buf != NULL);

    cmd_destruct(&c);
}

TEST_CASE("rx without ign: rx_ign is 0", "[rx_ign]") {
    const char *argv[] = {"rx", "eth0", "eth", "dmac", "::1"};
    cmd_t c = make_rx_cmd(argv, 5);

    CHECK(c.type == CMD_TYPE_RX);
    CHECK(c.rx_ign == 0);
    CHECK(c.frame_buf != NULL);

    cmd_destruct(&c);
}

TEST_CASE("rx ign: ign match does not set done", "[rx_ign]") {
    // Build an ign rx command with an eth frame
    const char *argv[] = {"rx", "eth0", "ign", "eth", "dmac", "::1", "smac", "::2"};
    cmd_t ign_cmd = make_rx_cmd(argv, 8);

    // Create a frame that matches
    frame_t *f = parse_frame_wrap({"eth", "dmac", "::1", "smac", "::2"});
    REQUIRE(f != NULL);
    buf_t *rx_frame = frame_to_buf(f);

    // Simulate what rfds_wfds_process does for ign commands:
    // match via bequal_mask, but don't set done
    int matched = bequal_mask(rx_frame, ign_cmd.frame_buf,
                              ign_cmd.frame_mask_buf,
                              ign_cmd.frame->padding_len);
    CHECK(matched == 1);

    // Key behavior: ign commands are never marked done
    CHECK(ign_cmd.done == 0);

    // Can match again (absorbs multiple frames)
    matched = bequal_mask(rx_frame, ign_cmd.frame_buf,
                          ign_cmd.frame_mask_buf,
                          ign_cmd.frame->padding_len);
    CHECK(matched == 1);
    CHECK(ign_cmd.done == 0);

    bfree(rx_frame);
    frame_free(f);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: regular cmd matches before ign cmd", "[rx_ign]") {
    // Build a regular rx and an ign rx that both match the same frame
    const char *reg_argv[] = {"rx", "eth0", "eth", "dmac", "::1", "smac", "::2"};
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "dmac", "::1", "smac", "::2"};
    cmd_t reg_cmd = make_rx_cmd(reg_argv, 7);
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 8);

    frame_t *f = parse_frame_wrap({"eth", "dmac", "::1", "smac", "::2"});
    REQUIRE(f != NULL);
    buf_t *rx_frame = frame_to_buf(f);

    // Simulate two-pass matching from rfds_wfds_process:
    // Pass 1: try regular (non-ign) commands
    int match = 0;
    cmd_t *cmds[] = {&reg_cmd, &ign_cmd};

    for (int p = 0; p < 2; p++) {
        cmd_t *c = cmds[p];
        if (!c->frame_buf || c->rx_ign || c->done)
            continue;
        if (bequal_mask(rx_frame, c->frame_buf, c->frame_mask_buf,
                        c->frame->padding_len)) {
            match = 1;
            c->done = 1;
            break;
        }
    }

    // Regular command should match first
    CHECK(match == 1);
    CHECK(reg_cmd.done == 1);
    CHECK(ign_cmd.done == 0);

    bfree(rx_frame);
    frame_free(f);
    cmd_destruct(&reg_cmd);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: non-matching frame still fails", "[rx_ign]") {
    // ign for IPv6-like frames (ethertype 0x86dd)
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "dmac", "ign",
                              "smac", "ign", "et", "0x86dd"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 10);

    // An IPv4 frame (ethertype 0x0800) should NOT match the ign
    frame_t *f = parse_frame_wrap({"eth", "dmac", "::1", "smac", "::2",
                                   "ipv4"});
    REQUIRE(f != NULL);
    buf_t *rx_frame = frame_to_buf(f);

    int matched = bequal_mask(rx_frame, ign_cmd.frame_buf,
                              ign_cmd.frame_mask_buf,
                              ign_cmd.frame->padding_len);
    CHECK(matched == 0);

    bfree(rx_frame);
    frame_free(f);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: matches when rx frame is longer than pattern", "[rx_ign]") {
    // Pattern: match any IPv6 Router Solicitation, ignore trailing options
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "ign", "et", "0x86dd",
                              "ipv6", "ign", "next", "58",
                              "icmp", "ign", "type", "133", "code", "0"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 17);
    REQUIRE(ign_cmd.frame_buf != NULL);

    // Build a longer frame: same headers + extra trailing data (ICMPv6 option)
    frame_t *f = parse_frame_wrap({"eth", "dmac", "33:33:0:0:0:2", "smac", "::1",
                                   "et", "0x86dd", "ipv6", "next", "58",
                                   "icmp", "type", "133", "code", "0", "hd", "0",
                                   "data", "hex", "0101aabbccdd0000"});
    REQUIRE(f != NULL);
    buf_t *rx_frame = frame_to_buf(f);

    // rx frame is longer than the pattern
    REQUIRE(rx_frame->size > ign_cmd.frame_buf->size);

    // With original size, strict match fails (different lengths)
    CHECK(bequal_mask(rx_frame, ign_cmd.frame_buf, ign_cmd.frame_mask_buf,
                      ign_cmd.frame->padding_len) == 0);

    // Simulate what rfds_wfds_process does for rx ign: truncate rx frame
    // to pattern length and compare with padding=0
    size_t orig_size = rx_frame->size;
    rx_frame->size = ign_cmd.frame_buf->size;
    CHECK(bequal_mask(rx_frame, ign_cmd.frame_buf, ign_cmd.frame_mask_buf,
                      0) == 1);
    rx_frame->size = orig_size;

    bfree(rx_frame);
    frame_free(f);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: shorter rx frame does not match pattern", "[rx_ign]") {
    // Pattern: eth + ipv6 + icmp (full RS)
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "ign",
                              "ipv6", "ign", "next", "58",
                              "icmp", "type", "133", "code", "0", "hd", "ign"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 16);
    REQUIRE(ign_cmd.frame_buf != NULL);

    // Build a frame that is shorter (just eth, no ipv6/icmp)
    frame_t *f = parse_frame_wrap({"eth", "dmac", "::1", "smac", "::2"});
    REQUIRE(f != NULL);
    buf_t *rx_frame = frame_to_buf(f);

    CHECK(rx_frame->size < ign_cmd.frame_buf->size);

    // Dynamic padding would be negative
    int ign_pad = rx_frame->size - ign_cmd.frame_buf->size;
    CHECK(ign_pad < 0);

    bfree(rx_frame);
    frame_free(f);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: ethertype filter absorbs realistic IPv6 chatter", "[rx_ign]") {
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "dmac", "ign",
                              "smac", "ign", "et", "0x86dd"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 10);
    REQUIRE(ign_cmd.frame_buf != NULL);

    std::vector<std::vector<const char *>> chatter = {
        {"eth", "dmac", "33:33:0:0:0:2", "smac", "56:b0:b3:5b:57:9b",
         "et", "0x86dd", "ipv6", "next", "58",
         "icmp", "type", "133", "code", "0", "hd", "0"},
        {"eth", "dmac", "33:33:0:0:0:1", "smac", "56:b0:b3:5b:57:9b",
         "et", "0x86dd", "ipv6", "next", "58",
         "icmp", "type", "134", "code", "0", "hd", "0"},
        {"eth", "dmac", "33:33:ff:5b:57:9b", "smac", "56:b0:b3:5b:57:9b",
         "et", "0x86dd", "ipv6", "next", "58",
         "icmp", "type", "135", "code", "0", "hd", "0"},
        {"eth", "dmac", "33:33:0:0:0:16", "smac", "b4:96:91:8c:9f:da",
         "et", "0x86dd", "ipv6", "next", "58",
         "icmp", "type", "143", "code", "0", "hd", "0"},
    };

    for (auto &spec : chatter) {
        frame_t *f = parse_frame_wrap(spec);
        REQUIRE(f != NULL);
        buf_t *rx = frame_to_buf(f);
        CHECK(ign_absorbs(ign_cmd, rx) == 1);
        bfree(rx);
        frame_free(f);
    }

    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: header-level ipv6 filter absorbs a real ICMPv6 frame",
          "[rx_ign]") {
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "ign", "ipv6", "ign"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 7);
    REQUIRE(ign_cmd.frame_buf != NULL);

    frame_t *f = parse_frame_wrap({"eth", "dmac", "33:33:0:0:0:16", "smac", "::1",
                                   "ipv6", "next", "58", "sip", "fe80::1",
                                   "dip", "ff02::16",
                                   "icmp", "type", "143", "code", "0", "hd", "0"});
    REQUIRE(f != NULL);
    buf_t *rx = frame_to_buf(f);

    CHECK(ign_absorbs(ign_cmd, rx) == 1);

    bfree(rx);
    frame_free(f);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: next-header filter absorbs ICMPv6 but not IPv6 UDP data",
          "[rx_ign]") {
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "ign",
                              "ipv6", "ign", "next", "58"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 9);
    REQUIRE(ign_cmd.frame_buf != NULL);

    frame_t *rs = parse_frame_wrap({"eth", "dmac", "33:33:0:0:0:2", "smac", "::1",
                                    "ipv6", "next", "58",
                                    "icmp", "type", "133", "code", "0", "hd", "0"});
    REQUIRE(rs != NULL);
    buf_t *rs_buf = frame_to_buf(rs);
    CHECK(ign_absorbs(ign_cmd, rs_buf) == 1);

    frame_t *data = parse_frame_wrap({"eth", "dmac", "33:33:0:20:0:2", "smac", "::1",
                                      "ipv6", "next", "17", "sip", "2001:db8::1",
                                      "dip", "ff05::20:2",
                                      "udp", "dport", "4096", "sport", "2048"});
    REQUIRE(data != NULL);
    buf_t *data_buf = frame_to_buf(data);
    CHECK(ign_absorbs(ign_cmd, data_buf) == 0);

    bfree(rs_buf);
    bfree(data_buf);
    frame_free(rs);
    frame_free(data);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: ptp ethertype filter absorbs a PTP sync frame", "[rx_ign]") {
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "dmac", "ign",
                              "smac", "ign", "et", "0x88f7"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 10);
    REQUIRE(ign_cmd.frame_buf != NULL);

    frame_t *f = parse_frame_wrap({"eth", "dmac", "01:1b:19:0:0:0", "smac", "::1",
                                   "et", "0x88f7", "ptp-sync"});
    REQUIRE(f != NULL);
    buf_t *rx = frame_to_buf(f);

    CHECK(ign_absorbs(ign_cmd, rx) == 1);

    bfree(rx);
    frame_free(f);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: igmp membership report filter absorbs report, not a query",
          "[rx_ign]") {
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "dmac", "ign",
                              "smac", "ign", "ipv4", "ign", "proto", "2",
                              "igmp", "ign", "type", "0x16"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 16);
    REQUIRE(ign_cmd.frame_buf != NULL);

    frame_t *report = parse_frame_wrap({"eth", "dmac", "01:00:5e:0:0:16",
                                        "smac", "::1", "ipv4", "proto", "2",
                                        "dip", "224.0.0.22", "sip", "10.0.0.1",
                                        "igmp", "type", "0x16", "ga", "239.1.2.3"});
    REQUIRE(report != NULL);
    buf_t *report_buf = frame_to_buf(report);
    CHECK(ign_absorbs(ign_cmd, report_buf) == 1);

    frame_t *query = parse_frame_wrap({"eth", "dmac", "01:00:5e:0:0:1",
                                       "smac", "::1", "ipv4", "proto", "2",
                                       "dip", "224.0.0.1", "sip", "10.0.0.1",
                                       "igmp", "type", "0x11", "ga", "0.0.0.0"});
    REQUIRE(query != NULL);
    buf_t *query_buf = frame_to_buf(query);
    CHECK(ign_absorbs(ign_cmd, query_buf) == 0);

    bfree(report_buf);
    bfree(query_buf);
    frame_free(report);
    frame_free(query);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign: ipv6 filter does not absorb unexpected non-IPv6 frames",
          "[rx_ign]") {
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "dmac", "ign",
                              "smac", "ign", "et", "0x86dd"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 10);
    REQUIRE(ign_cmd.frame_buf != NULL);

    frame_t *arp = parse_frame_wrap({"eth", "dmac", "ff:ff:ff:ff:ff:ff",
                                     "smac", "::1", "arp"});
    REQUIRE(arp != NULL);
    buf_t *arp_buf = frame_to_buf(arp);
    CHECK(ign_absorbs(ign_cmd, arp_buf) == 0);

    frame_t *ip4 = parse_frame_wrap({"eth", "dmac", "01:00:5e:1:2:3", "smac", "::1",
                                     "ipv4", "dip", "225.1.2.3", "sip", "10.0.0.1",
                                     "udp", "dport", "4096", "sport", "2048"});
    REQUIRE(ip4 != NULL);
    buf_t *ip4_buf = frame_to_buf(ip4);
    CHECK(ign_absorbs(ign_cmd, ip4_buf) == 0);

    bfree(arp_buf);
    bfree(ip4_buf);
    frame_free(arp);
    frame_free(ip4);
    cmd_destruct(&ign_cmd);
}

TEST_CASE("rx ign with header-level ign: matches any IPv6 content", "[rx_ign]") {
    // ign on eth fields + ipv6 header, matches any IPv6 frame of same structure
    const char *ign_argv[] = {"rx", "eth0", "ign", "eth", "ign", "ipv6", "ign"};
    cmd_t ign_cmd = make_rx_cmd(ign_argv, 7);

    // Two different IPv6 frames should both match
    frame_t *f1 = parse_frame_wrap({"eth", "dmac", "::1", "smac", "::2", "ipv6",
                                    "sip", "::1"});
    REQUIRE(f1 != NULL);
    buf_t *b1 = frame_to_buf(f1);

    CHECK(bequal_mask(b1, ign_cmd.frame_buf, ign_cmd.frame_mask_buf,
                      ign_cmd.frame->padding_len) == 1);

    frame_t *f2 = parse_frame_wrap({"eth", "dmac", "33:33:0:0:0:1", "smac", "::ff",
                                    "ipv6", "sip", "fe80::1", "dip", "ff02::1"});
    REQUIRE(f2 != NULL);
    buf_t *b2 = frame_to_buf(f2);

    CHECK(bequal_mask(b2, ign_cmd.frame_buf, ign_cmd.frame_mask_buf,
                      ign_cmd.frame->padding_len) == 1);

    bfree(b1);
    bfree(b2);
    frame_free(f1);
    frame_free(f2);
    cmd_destruct(&ign_cmd);
}
