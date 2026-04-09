#include "ef.h"
#include "ef-test.h"
#include "catch_single_include.hxx"

#include <cstring>

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

// Create a padded copy of a buffer: original data + pad_len zero bytes
static buf_t *make_padded_rx(const buf_t *expected, int pad_len)
{
    buf_t *rx = balloc(expected->size + pad_len);
    REQUIRE(rx != NULL);
    memcpy(rx->data, expected->data, expected->size);
    memset(rx->data + expected->size, 0, pad_len);
    return rx;
}

TEST_CASE("padding: padded frame matches with correct padding", "[padding]") {
    buf_t *expected, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &expected, &mask, &f);

    // Simulate a 4-byte padded RX frame
    buf_t *rx = make_padded_rx(expected, 4);

    CHECK(bequal_mask(rx, expected, mask, 4) == 1);

    bfree(rx);
    bfree(expected);
    frame_free(f);
}

TEST_CASE("padding: padded frame fails with wrong padding value", "[padding]") {
    buf_t *expected, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &expected, &mask, &f);

    buf_t *rx = make_padded_rx(expected, 4);

    // Wrong padding value, size check fails
    CHECK(bequal_mask(rx, expected, mask, 3) == 0);
    CHECK(bequal_mask(rx, expected, mask, 5) == 0);
    CHECK(bequal_mask(rx, expected, mask, 0) == 0);

    bfree(rx);
    bfree(expected);
    frame_free(f);
}

TEST_CASE("padding: zero padding self-matches", "[padding]") {
    buf_t *expected, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &expected, &mask, &f);

    CHECK(bequal_mask(expected, expected, mask, 0) == 1);

    bfree(expected);
    frame_free(f);
}

TEST_CASE("padding: padded frame with mask matches", "[padding]") {
    buf_t *expected, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "ign"}, &expected, &mask, &f);

    REQUIRE(mask != NULL);

    // Build RX with different smac but 8 bytes of padding
    frame_t *f2 = parse_frame_wrap({"eth", "dmac", "::1", "smac", "::ff"});
    buf_t *rx_base = frame_to_buf(f2);
    buf_t *rx = make_padded_rx(rx_base, 8);

    CHECK(bequal_mask(rx, expected, mask, 8) == 1);

    bfree(rx);
    bfree(rx_base);
    frame_free(f2);
    bfree(mask);
    bfree(expected);
    frame_free(f);
}

TEST_CASE("padding: data mismatch in non-padding region fails", "[padding]") {
    buf_t *expected, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &expected, &mask, &f);

    buf_t *rx = make_padded_rx(expected, 4);

    // Corrupt a byte in the frame data (not the padding)
    rx->data[0] ^= 0xff;

    CHECK(bequal_mask(rx, expected, mask, 4) == 0);

    bfree(rx);
    bfree(expected);
    frame_free(f);
}

TEST_CASE("padding: zero-filled padding bytes match", "[padding]") {
    buf_t *expected, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &expected, &mask, &f);

    // make_padded_rx fills padding with zeros
    buf_t *rx = make_padded_rx(expected, 8);

    CHECK(bequal_mask(rx, expected, mask, 8) == 1);

    bfree(rx);
    bfree(expected);
    frame_free(f);
}

TEST_CASE("padding: non-zero padding bytes rejected", "[padding]") {
    buf_t *expected, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &expected, &mask, &f);

    buf_t *rx = make_padded_rx(expected, 8);

    // Non-zero padding bytes must cause match failure
    memset(rx->data + expected->size, 0xde, 8);

    CHECK(bequal_mask(rx, expected, mask, 8) == 0);

    bfree(rx);
    bfree(expected);
    frame_free(f);
}

TEST_CASE("padding: negative padding rejected", "[padding]") {
    buf_t *expected, *mask;
    frame_t *f;
    build_frame({"eth", "dmac", "::1", "smac", "::2"}, &expected, &mask, &f);

    CHECK(bequal_mask(expected, expected, mask, -1) == 0);
    CHECK(bequal_mask(expected, expected, mask, -100) == 0);

    bfree(expected);
    frame_free(f);
}
