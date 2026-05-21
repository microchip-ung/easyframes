#include "ef.h"
#include "ef-test.h"
#include "catch_single_include.hxx"

// Regression for the v2-query shrink path in mld_fill_defaults: when
// rresv/ng widths are zeroed but their bit_offsets (224, 240) are left
// pointing past the shrunk 28-byte MLD header, frame_mask_to_buf used
// to assert in hdr_write_field because the mask path force-allocates
// a maskb and writes it for every field regardless of width.
//
// hdr_copy_to_buf_ now skips bit_width==0 fields, so building a mask
// for an MLDv2 query no longer trips the assert. frame_to_buf was
// always fine (val/def NULL paths skip the write), but we cover both.

static const std::vector<const char *> mldv2_query = {
    "eth", "dmac", "33:33:00:00:00:01",
           "smac", "00:00:00:00:00:01",
    "ipv6", "hlim", "1", "sip", "::", "dip", "ff02::1",
    "data", "hex", "3a00050200000100",
    "mld", "type", "130", "max_resp", "10000",
           "qrv", "2", "qqic", "125", "ns", "0",
};

TEST_CASE("frame_mask_to_buf does not assert on MLDv2 query (zero-width rresv/ng)",
          "[mld][zero-width]") {
    frame_t *f = parse_frame_wrap(mldv2_query);
    REQUIRE(f != nullptr);

    // Mirror what ef-args.c:261-265 does for rx patterns: frame_to_buf
    // runs first and mld_fill_defaults shrinks the MLD header (size 32
    // -> 28) and zeroes rresv/ng bit_widths. frame_mask_to_buf then
    // observes that mutated state — and used to assert in hdr_write_field
    // because the mask path force-allocates a maskb and writes it for
    // every field regardless of width, with bit_offsets still pointing
    // past the shrunk header end.
    buf_t *val = frame_to_buf(f);
    REQUIRE(val != nullptr);

    buf_t *mask = frame_mask_to_buf(f);
    REQUIRE(mask != nullptr);
    CHECK(mask->size >= 14 + 40 + 8 + 28);  // eth+ipv6+data+shrunk-mld

    bfree(val);
    bfree(mask);
    frame_free(f);
}

TEST_CASE("frame_to_buf builds an MLDv2 query without padding the shrunk fields",
          "[mld][zero-width]") {
    frame_t *f = parse_frame_wrap(mldv2_query);
    REQUIRE(f != nullptr);

    buf_t *buf = frame_to_buf(f);
    REQUIRE(buf != nullptr);
    // Frame is padded to 60 bytes by default; raw size before padding
    // is eth(14) + ipv6(40) + data(8) + mld(28) = 90, > 60, so no pad.
    CHECK(buf->size == 90);

    bfree(buf);
    frame_free(f);
}
