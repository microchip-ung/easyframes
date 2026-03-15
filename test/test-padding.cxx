#include "ef.h"
#include "ef-test.h"
#include "catch_single_include.hxx"

#include <cstring>

// RAII guard to set NO_PAD for the duration of a scope
struct NoPadGuard {
    NoPadGuard()  { NO_PAD = 1; }
    ~NoPadGuard() { NO_PAD = 0; }
};

// Build a frame and its expected buf/mask from a frame spec
static void build_frame(std::vector<const char *> spec,
                        buf_t **out_buf, buf_t **out_mask,
                        frame_t **out_frame)
{
    frame_t *f = parse_frame_wrap(spec);
    REQUIRE(f != NULL);
    *out_buf = frame_to_buf(f);
    REQUIRE(*out_buf != NULL);
    *out_mask = f->has_mask ? frame_mask_to_buf(f) : NULL;
    *out_frame = f;
}

TEST_CASE("no-pad: eth-only frame is 14 bytes", "[nopad]") {
    NoPadGuard g;
    buf_t *buf, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &buf, &mask, &f);

    // eth header = 14 bytes, no padding to 60
    CHECK(buf->size == 14);

    bfree(buf);
    frame_free(f);
}

TEST_CASE("no-pad: default pads to 60 bytes", "[nopad]") {
    CHECK(NO_PAD == 0);
    buf_t *buf, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &buf, &mask, &f);

    CHECK(buf->size == 60);

    bfree(buf);
    frame_free(f);
}

TEST_CASE("no-pad: mask buf also skips padding", "[nopad]") {
    NoPadGuard g;

    // Use 'ign' on smac to force mask generation
    frame_t *f = parse_frame_wrap({"eth", "dmac", "::1", "smac", "ign"});
    REQUIRE(f != NULL);
    buf_t *buf = frame_to_buf(f);
    buf_t *mask = frame_mask_to_buf(f);
    REQUIRE(buf != NULL);
    REQUIRE(mask != NULL);

    CHECK(buf->size == 14);
    CHECK(mask->size == 14);

    bfree(buf);
    bfree(mask);
    frame_free(f);
}

TEST_CASE("no-pad: frame with payload stays exact size", "[nopad]") {
    NoPadGuard g;
    buf_t *buf, *mask;
    frame_t *f;

    // eth(14) + data pattern cnt 4 = 18 bytes, well under 60
    build_frame({"eth", "dmac", "::1", "smac", "::2",
                 "data", "pattern", "cnt", "4"}, &buf, &mask, &f);

    CHECK(buf->size == 18);

    bfree(buf);
    frame_free(f);
}

TEST_CASE("no-pad: large frame unaffected", "[nopad]") {
    NoPadGuard g;
    buf_t *buf, *mask;
    frame_t *f;

    // eth(14) + data pattern cnt 100 = 114 bytes, already > 60
    build_frame({"eth", "dmac", "::1", "smac", "::2",
                 "data", "pattern", "cnt", "100"}, &buf, &mask, &f);

    CHECK(buf->size == 114);

    bfree(buf);
    frame_free(f);
}

TEST_CASE("bequal_mask: zero padding accepted", "[bequal][padding]") {
    buf_t *exp = balloc(14);
    buf_t *rx  = balloc(60);
    for (size_t i = 0; i < 14; ++i) {
        exp->data[i] = (uint8_t)(i + 1);
        rx->data[i]  = (uint8_t)(i + 1);
    }
    // rx->data[14..59] left as 0 by balloc/calloc

    CHECK(bequal_mask(rx, exp, 0, 46) == 1);

    bfree(exp);
    bfree(rx);
}

TEST_CASE("bequal_mask: non-zero padding rejected", "[bequal][padding]") {
    buf_t *exp = balloc(14);
    buf_t *rx  = balloc(60);
    for (size_t i = 0; i < 14; ++i) {
        exp->data[i] = (uint8_t)(i + 1);
        rx->data[i]  = (uint8_t)(i + 1);
    }
    // Corrupt a single byte in the padding region
    rx->data[59] = 0xAA;

    CHECK(bequal_mask(rx, exp, 0, 46) == 0);

    bfree(exp);
    bfree(rx);
}

TEST_CASE("bequal_mask: non-zero padding rejected (all 0xAA)",
          "[bequal][padding]") {
    buf_t *exp = balloc(14);
    buf_t *rx  = balloc(60);
    for (size_t i = 0; i < 14; ++i) {
        exp->data[i] = (uint8_t)(i + 1);
        rx->data[i]  = (uint8_t)(i + 1);
    }
    for (size_t i = 14; i < 60; ++i)
        rx->data[i] = 0xAA;

    CHECK(bequal_mask(rx, exp, 0, 46) == 0);

    bfree(exp);
    bfree(rx);
}

TEST_CASE("bequal_mask: masked path, zero padding accepted",
          "[bequal][padding]") {
    buf_t *exp  = balloc(14);
    buf_t *mask = balloc(14);
    buf_t *rx   = balloc(60);
    for (size_t i = 0; i < 14; ++i) {
        exp->data[i]  = (uint8_t)(i + 1);
        mask->data[i] = 0xff;
        rx->data[i]   = (uint8_t)(i + 1);
    }

    CHECK(bequal_mask(rx, exp, mask, 46) == 1);

    bfree(exp);
    bfree(mask);
    bfree(rx);
}

TEST_CASE("bequal_mask: masked path, non-zero padding rejected",
          "[bequal][padding]") {
    buf_t *exp  = balloc(14);
    buf_t *mask = balloc(14);
    buf_t *rx   = balloc(60);
    for (size_t i = 0; i < 14; ++i) {
        exp->data[i]  = (uint8_t)(i + 1);
        mask->data[i] = 0xff;
        rx->data[i]   = (uint8_t)(i + 1);
    }
    rx->data[30] = 0x01;

    CHECK(bequal_mask(rx, exp, mask, 46) == 0);

    bfree(exp);
    bfree(mask);
    bfree(rx);
}
