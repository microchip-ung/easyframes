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
