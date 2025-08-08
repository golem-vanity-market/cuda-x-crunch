#pragma once
#include "create3.h"

#define SCORE_ACCEPTED 1
#define SCORE_REJECTED 0


inline uint32_t bswap32(uint32_t x) {
    return ((x & 0x000000FFU) << 24) |
           ((x & 0x0000FF00U) << 8)  |
           ((x & 0x00FF0000U) >> 8)  |
           ((x & 0xFF000000U) >> 24);
}

#define MATCH0_32(a, MASK) \
    ((a & bswap32(MASK)) == 0x0)

inline uint32_t cpu_scorer(ethaddress& addr, pattern_descriptor descr)
{
    int group_score = 0;
    int letter_score = 0;
    int number_score = 0;


    int number_of_zeroes = 0;
    int pattern_repeats = 0;
    if (descr.use_common) {
        uint8_t let_full[40];
        for (int i = 0; i < 20; i++) {
            let_full[2 * i] = (addr.b[i] >> 4) & 0x0f;
            let_full[2 * i + 1] = addr.b[i] & 0x0f;
        }
        for (int i = 0; i < 40; i++) {
            uint8_t letter = let_full[i];

            if (i > 0 && letter == let_full[i - 1]) {
                group_score += 1;
            }
            if (letter >= 10) {
                letter_score += 1;
            }
            if (letter < 10) {
                number_score += 1;
            }
            if (letter == 0) {
                number_of_zeroes += 1;
            }
        }

        if (addr.d[0] == addr.d[1] && addr.d[1] == addr.d[2] && addr.d[2] == addr.d[3]) {
            pattern_repeats = 1;
        }
    }

    int pattern = 0;
    uint32_t number = addr.d[0];
    uint32_t number_suffix = addr.d[4];

    uint32_t prefix_short = bswap32(number) & 0xFFFFFF00;
    uint32_t suffix_short = bswap32(number_suffix) & 0x00FFFFFF;

    if ((descr.use_common && (number == bswap32(0xbadbabe0)
        || prefix_short == 0x01234500
        || prefix_short == 0x12345600
        || number == bswap32(0xb00bbabe)
        || number == bswap32(0xc0ffee00)
        || number == bswap32(0xdaedbeef)
        || number == bswap32(0xdaedf00d)
        || prefix_short == 0x31415900
        || prefix_short == 0x00000000
        || prefix_short == 0x11111100
        || prefix_short == 0x22222200
        || prefix_short == 0x33333300
        || prefix_short == 0x44444400
        || prefix_short == 0x55555500
        || prefix_short == 0x66666600
        || prefix_short == 0x77777700
        || prefix_short == 0x88888800
        || prefix_short == 0x99999900
        || prefix_short == 0xaaaaaa00
        || prefix_short == 0xbbbbbb00
        || prefix_short == 0xcccccc00
        || prefix_short == 0xdddddd00
        || prefix_short == 0xeeeeee00
        || prefix_short == 0xffffff00))
        || (number & 0x00FFFFFF) == (descr.search_prefix & 0x00FFFFFF)
        ) {
        pattern = 1;
    }
    if ((descr.use_common && (
           suffix_short == 0x00000000
        || suffix_short == 0x00111111
        || suffix_short == 0x00222222
        || suffix_short == 0x00333333
        || suffix_short == 0x00444444
        || suffix_short == 0x00555555
        || suffix_short == 0x00666666
        || suffix_short == 0x00777777
        || suffix_short == 0x00888888
        || suffix_short == 0x00999999
        || suffix_short == 0x00aaaaaa
        || suffix_short == 0x00bbbbbb
        || suffix_short == 0x00cccccc
        || suffix_short == 0x00dddddd
        || suffix_short == 0x00eeeeee
        || suffix_short == 0x00ffffff))
        || (number & 0xFFFFFF00) == (descr.search_suffix & 0xFFFFFF00)
        ) {
        pattern = 1;
    }

    int pattern_zeroes = 0;


    if (
        pattern_zeroes >= 1 ||
        pattern >= 1 ||
        pattern_repeats >= 1 ||
        group_score >= 15 ||
        letter_score > 32 ||
        number_score >= 40 ||
        number_of_zeroes >= 17 ||
        0
        ) {
        return SCORE_ACCEPTED;
    }
    return SCORE_REJECTED;
}
