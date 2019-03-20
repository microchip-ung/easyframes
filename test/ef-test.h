#ifndef EF_TEST_H
#define EF_TEST_H

#include "ef.h"

#include <string>
#include <vector>

struct HexBuf {
    HexBuf(int _s, const char *_d) : s(_s), d(_d) { }

    int s;
    std::string d;
};

// hexstr free memmory (TODO, fix this hack)
std::string hexstr(buf_t *b);

std::ostream& operator<<(std::ostream& o, const HexBuf &b);

frame_t *parse_frame_wrap(std::vector<const char *> ptrs);

#endif   // EF_TEST_H
