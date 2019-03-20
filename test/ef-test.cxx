#include "ef-test.h"

// hexstr free memmory (TODO, fix this hack)
std::string hexstr(buf_t *b) {
    char bb[8];
    std::string s;

    if (!b)
        return "<NULL>";

    for (size_t i = 0; i < b->size; ++i) {
        snprintf(bb, 8, "%02x", b->data[i]);
        s.append(bb);
    }

    bfree(b);

    return s;
}

std::ostream& operator<<(std::ostream& o, const HexBuf &b) {
    o << b.d;
    return o;
}

frame_t *parse_frame_wrap(std::vector<const char *> ptrs) {
    size_t cnt;
    frame_t *f = frame_alloc();

    cnt = argc_frame(ptrs.size(), ptrs.data(), f);
    if (cnt != ptrs.size()) {
        frame_free(f);
        return 0;
    }

    return f;
}


