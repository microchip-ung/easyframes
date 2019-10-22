#include "ef.h"
#include "ef-test.h"

#include <vector>
#include <iostream>
#include "catch_single_include.hxx"


TEST_CASE("ifh-ignore", "[ifh]" ) {
    auto f1 = parse_frame_wrap({"ifh-oc1", "rew-val", "0xabcdef", "eth", "dmac", "1::2", "smac", "3::4"});
    auto f2 = parse_frame_wrap({"ifh-oc1", "rew-val", "0x123456", "eth", "dmac", "1::2", "smac", "3::4"});
    auto f3 = parse_frame_wrap({"ifh-oc1", "rew-val", "ign",      "eth", "dmac", "1::2", "smac", "3::4"});

    auto b1 = frame_to_buf(f1);
    auto b2 = frame_to_buf(f2);
    auto b3 = frame_to_buf(f3);
    auto m3 = frame_mask_to_buf(f3);

    CHECK(bequal_mask(b1, b1, 0, 0) == 1);
    CHECK(bequal_mask(b2, b2, 0, 0) == 1);
    CHECK(bequal_mask(b3, b3, 0, 0) == 1);

    CHECK(bequal_mask(b1, b2, 0, 0) == 0);
    CHECK(bequal_mask(b1, b3, 0, 0) == 0);
    CHECK(bequal_mask(b2, b3, 0, 0) == 0);

    CHECK(bequal_mask(b1, b2, m3, 0) == 1);

#if 0
    // hexstr free memmory!!!
    std::cout << "b1: " << hexstr(b1) << std::endl;
    std::cout << "b2: " << hexstr(b2) << std::endl;
    std::cout << "b3: " << hexstr(b3) << std::endl;
    std::cout << "m3: " << hexstr(m3) << std::endl;
#else
    bfree(b1);
    bfree(b2);
    bfree(b3);
    bfree(m3);
#endif
    frame_free(f1);
    frame_free(f2);
    frame_free(f3);
}

