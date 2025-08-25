#pragma once
#include "create3.h"

#define SCORE_ACCEPTED 1
#define SCORE_REJECTED 0


__device__ __forceinline__ uint32_t bswap32(uint32_t x) {
    return __byte_perm(x, 0, 0x0123);  // Reverse byte order
}

#define MATCH0_32(a, MASK) \
    ((a & bswap32(MASK)) == 0x0)

__device__ inline uint32_t scorer(ethaddress& addr, pattern_descriptor descr)
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

    if ((descr.use_common && (number == bswap32(0xbadbabe0)
        || number == bswap32(0x01234567)
        || number == bswap32(0x12345678)
        || number == bswap32(0xb00bbabe)
        || number == bswap32(0xc0ffee00)
        || number == bswap32(0xdaedbeef)
        || number == bswap32(0xdaedf00d)
        || number == bswap32(0x31415926)
        || number == bswap32(0x00000000)
        || number == bswap32(0x11111111)
        || number == bswap32(0x22222222)
        || number == bswap32(0x33333333)
        || number == bswap32(0x44444444)
        || number == bswap32(0x55555555)
        || number == bswap32(0x66666666)
        || number == bswap32(0x77777777)
        || number == bswap32(0x88888888)
        || number == bswap32(0x99999999)
        || number == bswap32(0xaaaaaaaa)
        || number == bswap32(0xbbbbbbbb)
        || number == bswap32(0xcccccccc)
        || number == bswap32(0xdddddddd)
        || number == bswap32(0xeeeeeeee)
        || number == bswap32(0xffffffff)))
        || number == descr.search_prefix
        ) {
        pattern = 1;
    }
    if ((descr.use_common && (
        number_suffix == bswap32(0x00000000)
        || number_suffix == bswap32(0x11111111)
        || number_suffix == bswap32(0x22222222)
        || number_suffix == bswap32(0x33333333)
        || number_suffix == bswap32(0x44444444)
        || number_suffix == bswap32(0x55555555)
        || number_suffix == bswap32(0x66666666)
        || number_suffix == bswap32(0x77777777)
        || number_suffix == bswap32(0x88888888)
        || number_suffix == bswap32(0x99999999)
        || number_suffix == bswap32(0xaaaaaaaa)
        || number_suffix == bswap32(0xbbbbbbbb)
        || number_suffix == bswap32(0xcccccccc)
        || number_suffix == bswap32(0xdddddddd)
        || number_suffix == bswap32(0xeeeeeeee)
        || number_suffix == bswap32(0xffffffff)))
        || number_suffix == descr.search_suffix
        ) {
        pattern = 1;
    }

    if (descr.use_mask) {
        if (
                (addr.d[0] & descr.mask_bits.d[0]) == descr.mask_value.d[0] &&
                (addr.d[1] & descr.mask_bits.d[1]) == descr.mask_value.d[1] &&
                (addr.d[2] & descr.mask_bits.d[2]) == descr.mask_value.d[2] &&
                (addr.d[3] & descr.mask_bits.d[3]) == descr.mask_value.d[3] &&
                (addr.d[4] & descr.mask_bits.d[4]) == descr.mask_value.d[4]
            )
            {
                pattern = 1;
            } 
        }

    int pattern_zeroes = 0;

    if (descr.use_triples && number_of_zeroes >= 8) {
        if (
            (MATCH0_32(addr.d[0], 0xffff000f) && MATCH0_32(addr.d[1], 0xfff00000)) ||
            (MATCH0_32(addr.d[0], 0x0ffff000) && MATCH0_32(addr.d[1], 0xffff0000)) ||
            (MATCH0_32(addr.d[0], 0x00ffff00) && MATCH0_32(addr.d[1], 0x0ffff000)) ||
            (MATCH0_32(addr.d[0], 0x000ffff0) && MATCH0_32(addr.d[1], 0x00ffff00)) ||
            (MATCH0_32(addr.d[0], 0x0000ffff) && MATCH0_32(addr.d[1], 0x000ffff0)) ||
            (MATCH0_32(addr.d[0], 0x00000fff) && MATCH0_32(addr.d[1], 0xf000ffff)) ||
            (MATCH0_32(addr.d[0], 0x000000ff) && MATCH0_32(addr.d[1], 0xff000fff) && MATCH0_32(addr.d[2], 0xf0000000)) ||
            (MATCH0_32(addr.d[0], 0x0000000f) && MATCH0_32(addr.d[1], 0xfff000ff) && MATCH0_32(addr.d[2], 0xff000000)) ||
            (MATCH0_32(addr.d[1], 0xffff000f) && MATCH0_32(addr.d[2], 0xfff00000)) ||
            (MATCH0_32(addr.d[1], 0x0ffff000) && MATCH0_32(addr.d[2], 0xffff0000)) ||
            (MATCH0_32(addr.d[1], 0x00ffff00) && MATCH0_32(addr.d[2], 0x0ffff000)) ||
            (MATCH0_32(addr.d[1], 0x000ffff0) && MATCH0_32(addr.d[2], 0x00ffff00)) ||
            (MATCH0_32(addr.d[1], 0x0000ffff) && MATCH0_32(addr.d[2], 0x000ffff0)) ||
            (MATCH0_32(addr.d[1], 0x00000fff) && MATCH0_32(addr.d[2], 0xf000ffff)) ||
            (MATCH0_32(addr.d[1], 0x000000ff) && MATCH0_32(addr.d[2], 0xff000fff) && MATCH0_32(addr.d[3], 0xf0000000)) ||
            (MATCH0_32(addr.d[1], 0x0000000f) && MATCH0_32(addr.d[2], 0xfff000ff) && MATCH0_32(addr.d[3], 0xff000000)) ||
            (MATCH0_32(addr.d[2], 0xffff000f) && MATCH0_32(addr.d[3], 0xfff00000)) ||
            (MATCH0_32(addr.d[2], 0x0ffff000) && MATCH0_32(addr.d[3], 0xffff0000)) ||
            (MATCH0_32(addr.d[2], 0x00ffff00) && MATCH0_32(addr.d[3], 0x0ffff000)) ||
            (MATCH0_32(addr.d[2], 0x000ffff0) && MATCH0_32(addr.d[3], 0x00ffff00)) ||
            (MATCH0_32(addr.d[2], 0x0000ffff) && MATCH0_32(addr.d[3], 0x000ffff0)) ||
            (MATCH0_32(addr.d[2], 0x00000fff) && MATCH0_32(addr.d[3], 0xf000ffff)) ||
            (MATCH0_32(addr.d[2], 0x000000ff) && MATCH0_32(addr.d[3], 0xff000fff) && MATCH0_32(addr.d[4], 0xf0000000)) ||
            (MATCH0_32(addr.d[2], 0x0000000f) && MATCH0_32(addr.d[3], 0xfff000ff) && MATCH0_32(addr.d[4], 0xff000000)) ||
            (MATCH0_32(addr.d[3], 0xffff000f) && MATCH0_32(addr.d[4], 0xfff00000)) ||
            (MATCH0_32(addr.d[3], 0x0ffff000) && MATCH0_32(addr.d[4], 0xffff0000)) ||
            (MATCH0_32(addr.d[3], 0x00ffff00) && MATCH0_32(addr.d[4], 0x0ffff000)) ||
            (MATCH0_32(addr.d[3], 0x000ffff0) && MATCH0_32(addr.d[4], 0x00ffff00)) ||
            (MATCH0_32(addr.d[3], 0x0000ffff) && MATCH0_32(addr.d[4], 0x000ffff0)) ||
            (MATCH0_32(addr.d[3], 0x00000fff) && MATCH0_32(addr.d[4], 0xf000ffff)) ||
            0
            ) {
            pattern_zeroes = 1;
        }
    }

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
