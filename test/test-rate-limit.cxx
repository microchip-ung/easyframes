#include "ef.h"
#include "catch_single_include.hxx"

#include <cstring>

static cmd_t make_cmd(uint32_t rate_pps)
{
    cmd_t c;
    memset(&c, 0, sizeof(c));
    c.type = CMD_TYPE_TX;
    c.rate_pps = rate_pps;
    c.repeat = 1;
    return c;
}

TEST_CASE("rate_init sets correct fields", "[rate]") {
    cmd_t c = make_cmd(80);
    rate_init(&c);

    CHECK(c.rate_burst == 8);                 // clamp(80/10, 1, 64) = 8
    CHECK(c.tb_rate == 80 * 1000LL);          // 80 pps * 1000 millipkts
    CHECK(c.tb_max  == 8 * 1000LL);           // burst=8 * 1000
    CHECK(c.tb_tokens == c.tb_max);           // starts full
    CHECK(c.tb_last.tv_sec != 0);             // timestamp set
}

TEST_CASE("rate_can_send / rate_consume drain burst", "[rate]") {
    cmd_t c = make_cmd(100);
    rate_init(&c);

    // burst = clamp(100/10, 1, 64) = 10
    int sent = 0;
    while (rate_can_send(&c)) {
        rate_consume(&c);
        sent++;
        if (sent > 100)
            break; // safety
    }

    CHECK(sent == 10);
    CHECK(rate_can_send(&c) == 0);
}

TEST_CASE("rate_can_send unlimited always returns 1", "[rate]") {
    cmd_t c = make_cmd(0);
    // No init needed for unlimited

    CHECK(rate_can_send(&c) == 1);
    rate_consume(&c);  // should be no-op
    CHECK(rate_can_send(&c) == 1);
}

TEST_CASE("rate_refill adds correct tokens", "[rate]") {
    cmd_t c = make_cmd(1000);
    rate_init(&c);

    // Drain fully
    while (rate_can_send(&c))
        rate_consume(&c);

    CHECK(c.tb_tokens == 0);

    // Simulate 5ms elapsed (stays under burst cap)
    struct timespec now = c.tb_last;
    now.tv_nsec += 5000000; // 5ms
    if (now.tv_nsec >= 1000000000) {
        now.tv_sec += 1;
        now.tv_nsec -= 1000000000;
    }

    rate_refill(&c, &now);

    // 1000 pps * 5ms = 5 packets = 5000 millipkts
    CHECK(c.tb_tokens == 5000);
}

TEST_CASE("rate_refill partial token accumulation", "[rate]") {
    cmd_t c = make_cmd(100);
    rate_init(&c);

    while (rate_can_send(&c))
        rate_consume(&c);

    struct timespec now = c.tb_last;
    now.tv_nsec += 5000000; // 5ms

    rate_refill(&c, &now);

    // 100 pps * 5ms = 0.5 packets = 500 millipkts
    CHECK(c.tb_tokens == 500);
    CHECK(rate_can_send(&c) == 0); // not enough for a full packet
}

TEST_CASE("rate_refill second boundary crossing", "[rate]") {
    cmd_t c = make_cmd(50);
    rate_init(&c);

    // burst = clamp(50/10, 1, 64) = 5
    CHECK(c.rate_burst == 5);

    while (rate_can_send(&c))
        rate_consume(&c);

    struct timespec now = c.tb_last;
    // 1.5s elapsed
    now.tv_sec += 1;
    now.tv_nsec += 500000000;
    if (now.tv_nsec >= 1000000000) {
        now.tv_sec += 1;
        now.tv_nsec -= 1000000000;
    }

    rate_refill(&c, &now);

    // 50 pps * 1.5s = 75 pkts, but capped at burst (5 * 1000 = 5000)
    CHECK(c.tb_tokens == 5000);
}

TEST_CASE("rate_refill high rate no overflow", "[rate]") {
    cmd_t c = make_cmd(1000000); // 1 Mpps
    rate_init(&c);

    while (rate_can_send(&c))
        rate_consume(&c);

    struct timespec now = c.tb_last;
    now.tv_nsec += 10000000; // 10ms

    rate_refill(&c, &now);

    // 1e6 pps * 10ms = 10000 pkts = 10000000 millipkts, capped at burst
    CHECK(c.tb_tokens == c.tb_max);
}

TEST_CASE("rate_ns_until_token returns correct wait", "[rate]") {
    cmd_t c = make_cmd(1000);
    rate_init(&c);

    while (rate_can_send(&c))
        rate_consume(&c);

    int64_t ns = rate_ns_until_token(&c);

    // Need 1000 millipkts, rate is 1000000 millipkts/sec
    // 1000 / 1000000 * 1e9 = 1000000 ns = 1ms
    CHECK(ns == 1000000);
}

TEST_CASE("rate_ns_until_token unlimited returns 0", "[rate]") {
    cmd_t c = make_cmd(0);
    CHECK(rate_ns_until_token(&c) == 0);
}

TEST_CASE("rate_ns_until_token with tokens returns 0", "[rate]") {
    cmd_t c = make_cmd(1000);
    rate_init(&c);
    // Bucket is full
    CHECK(rate_ns_until_token(&c) == 0);
}

TEST_CASE("rate_bps_to_pps 1G minimum frame", "[rate]") {
    // 60-byte frame (min Ethernet without FCS) + 24 overhead = 84 bytes = 672 bits
    // 1e9 / 672 = 1488095
    CHECK(rate_bps_to_pps(1000000000ULL, 60) == 1488095);
}

TEST_CASE("rate_bps_to_pps 1G 1514-byte frame", "[rate]") {
    // 1514-byte frame + 24 overhead = 1538 bytes = 12304 bits
    // 1e9 / 12304 = 81274
    CHECK(rate_bps_to_pps(1000000000ULL, 1514) == 81274);
}

TEST_CASE("rate_bps_to_pps 100M minimum frame", "[rate]") {
    // 60 + 24 = 84 bytes = 672 bits
    // 1e8 / 672 = 148809
    CHECK(rate_bps_to_pps(100000000ULL, 60) == 148809);
}

TEST_CASE("rate_bps_to_pps floors to 1 pps", "[rate]") {
    // 100 bps with a 1514-byte frame: 100 / 12304 = 0, floored to 1
    CHECK(rate_bps_to_pps(100, 1514) == 1);
}

TEST_CASE("rate_bps_to_pps 10G", "[rate]") {
    // 60 + 24 = 84 = 672 bits
    // 10e9 / 672 = 14880952
    CHECK(rate_bps_to_pps(10000000000ULL, 60) == 14880952);
}
