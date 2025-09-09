#include "version.h"
#include "bip32.h"
#include "utils.hpp"
#include "Logger.hpp"
#include <iostream>
#include <cuda_runtime_api.h>
#include <string>
#include <filesystem>
#include <cstring>
#include "precomp.hpp"
#include <secp256k1.h>
#include "cpu_scorer.h"


#define rotate64(x, s) ((x << s) | (x >> (64U - s)))

const mp_number tripleNegativeGx = { {0xbb17b196, 0xf2287bec, 0x76958573, 0xf82c096e, 0x946adeea, 0xff1ed83e, 0x1269ccfa, 0x92c4cc83 } };
const mp_number negativeGy = { {0x04ef2777, 0x63b82f6f, 0x597aabe6, 0x02e84bb7, 0xf1eef757, 0xa25b0403, 0xd95c3b9a, 0xb7c52588 } };

//6481385041966929816
//188021827762530521
//6170039885052185351
//8772561819708210092

//11261198710074299576
//18237243440184513561
//6747795201694173352
//5204712524664259685
const unsigned long long int GxCoord[4] = {6481385041966929816ULL, 188021827762530521ULL, 6170039885052185351ULL, 8772561819708210092ULL};
const unsigned long long int GyCoord[4] = {11261198710074299576ULL, 18237243440184513561ULL, 6747795201694173352ULL, 5204712524664259685ULL};

inline uint32_t mul_hi(uint32_t a, uint32_t b) {
	uint64_t result = static_cast<uint64_t>(a) * static_cast<uint64_t>(b);
	return static_cast<uint32_t>(result >> 32);
}

// mod              = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
const mp_number mod = { {0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff} };


// tripleNegativeGx = 0x92c4cc831269ccfaff1ed83e946adeeaf82c096e76958573f2287becbb17b196

// doubleNegativeGy = 0x6f8a4b11b2b8773544b60807e3ddeeae05d0976eb2f557ccc7705edf09de52bf
//const mp_number doubleNegativeGy = { {0x09de52bf, 0xc7705edf, 0xb2f557cc, 0x05d0976e, 0xe3ddeeae, 0x44b60807, 0xb2b87735, 0x6f8a4b11} };

// negativeGy       = 0xb7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777

// Multiprecision subtraction. Underflow signalled via return value.
static mp_word mp_sub(mp_number& r, const mp_number& a, const mp_number& b) {
	mp_word t, c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		t = a.d[i] - b.d[i] - c;
		c = t > a.d[i] ? 1 : (t == a.d[i] ? c : 0);

		r.d[i] = t;
	}

	return c;
}



// Multiprecision subtraction of the modulus saved in mod. Underflow signalled via return value.
static mp_word mp_sub_mod(mp_number& r) {
	mp_number mod = { {0xfffffc2fU, 0xfffffffeU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU} };

	mp_word t, c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		t = r.d[i] - mod.d[i] - c;
		c = t > r.d[i] ? 1 : (t == r.d[i] ? c : 0);

		r.d[i] = t;
	}

	return c;
}


static void mp_mod_sub(mp_number& r, const mp_number& a, const mp_number& b) {
	mp_word i, t, c = 0;

	for (i = 0; i < MP_WORDS; ++i) {
		t = a.d[i] - b.d[i] - c;
		c = t < a.d[i] ? 0 : (t == a.d[i] ? c : 1);

		r.d[i] = t;
	}

	if (c) {
		c = 0;
		for (i = 0; i < MP_WORDS; ++i) {
			r.d[i] += mod.d[i] + c;
			c = r.d[i] < mod.d[i] ? 1 : (r.d[i] == mod.d[i] ? c : 0);
		}
	}
}



static void mp_mod_sub_const(mp_number& r, const mp_number& a, const mp_number& b) {
	mp_word i, t, c = 0;

	for (i = 0; i < MP_WORDS; ++i) {
		t = a.d[i] - b.d[i] - c;
		c = t < a.d[i] ? 0 : (t == a.d[i] ? c : 1);

		r.d[i] = t;
	}

	if (c) {
		c = 0;
		for (i = 0; i < MP_WORDS; ++i) {
			r.d[i] += mod.d[i] + c;
			c = r.d[i] < mod.d[i] ? 1 : (r.d[i] == mod.d[i] ? c : 0);
		}
	}
}


static void mp_mod_sub_gx(mp_number& r, const mp_number& a) {
	mp_word i, t, c = 0;

	t = a.d[0] - 0x16f81798U; c = t < a.d[0] ? 0 : (t == a.d[0] ? c : 1); r.d[0] = t;
	t = a.d[1] - 0x59f2815bU - c; c = t < a.d[1] ? 0 : (t == a.d[1] ? c : 1); r.d[1] = t;
	t = a.d[2] - 0x2dce28d9U - c; c = t < a.d[2] ? 0 : (t == a.d[2] ? c : 1); r.d[2] = t;
	t = a.d[3] - 0x029bfcdbU - c; c = t < a.d[3] ? 0 : (t == a.d[3] ? c : 1); r.d[3] = t;
	t = a.d[4] - 0xce870b07U - c; c = t < a.d[4] ? 0 : (t == a.d[4] ? c : 1); r.d[4] = t;
	t = a.d[5] - 0x55a06295U - c; c = t < a.d[5] ? 0 : (t == a.d[5] ? c : 1); r.d[5] = t;
	t = a.d[6] - 0xf9dcbbacU - c; c = t < a.d[6] ? 0 : (t == a.d[6] ? c : 1); r.d[6] = t;
	t = a.d[7] - 0x79be667eU - c; c = t < a.d[7] ? 0 : (t == a.d[7] ? c : 1); r.d[7] = t;

	if (c) {
		c = 0;
		for (i = 0; i < MP_WORDS; ++i) {
			r.d[i] += mod.d[i] + c;
			c = r.d[i] < mod.d[i] ? 1 : (r.d[i] == mod.d[i] ? c : 0);
		}
	}
}

// Multiprecision subtraction modulo M of G_y from a number.
// Specialization of mp_mod_sub in hope of performance gain.
static void mp_mod_sub_gy(mp_number& r, const mp_number& a) {
	mp_word i, t, c = 0;

	t = a.d[0] - 0xfb10d4b8U; c = t < a.d[0] ? 0 : (t == a.d[0] ? c : 1); r.d[0] = t;
	t = a.d[1] - 0x9c47d08fU - c; c = t < a.d[1] ? 0 : (t == a.d[1] ? c : 1); r.d[1] = t;
	t = a.d[2] - 0xa6855419U - c; c = t < a.d[2] ? 0 : (t == a.d[2] ? c : 1); r.d[2] = t;
	t = a.d[3] - 0xfd17b448U - c; c = t < a.d[3] ? 0 : (t == a.d[3] ? c : 1); r.d[3] = t;
	t = a.d[4] - 0x0e1108a8U - c; c = t < a.d[4] ? 0 : (t == a.d[4] ? c : 1); r.d[4] = t;
	t = a.d[5] - 0x5da4fbfcU - c; c = t < a.d[5] ? 0 : (t == a.d[5] ? c : 1); r.d[5] = t;
	t = a.d[6] - 0x26a3c465U - c; c = t < a.d[6] ? 0 : (t == a.d[6] ? c : 1); r.d[6] = t;
	t = a.d[7] - 0x483ada77U - c; c = t < a.d[7] ? 0 : (t == a.d[7] ? c : 1); r.d[7] = t;

	if (c) {
		c = 0;
		for (i = 0; i < MP_WORDS; ++i) {
			r.d[i] += mod.d[i] + c;
			c = r.d[i] < mod.d[i] ? 1 : (r.d[i] == mod.d[i] ? c : 0);
		}
	}
}

// Multiprecision addition. Overflow signalled via return value.
static mp_word mp_add(mp_number& r, const mp_number& a) {
	mp_word c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		r.d[i] += a.d[i] + c;
		c = r.d[i] < a.d[i] ? 1 : (r.d[i] == a.d[i] ? c : 0);
	}

	return c;
}

// Multiprecision addition of the modulus saved in mod. Overflow signalled via return value.
static mp_word mp_add_mod(mp_number& r) {
	mp_word c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		r.d[i] += mod.d[i] + c;
		c = r.d[i] < mod.d[i] ? 1 : (r.d[i] == mod.d[i] ? c : 0);
	}

	return c;
}

// Multiprecision addition of two numbers with one extra word each. Overflow signalled via return value.
static mp_word mp_add_more(mp_number& r, mp_word& extraR, const mp_number& a, const mp_word& extraA) {
	const mp_word c = mp_add(r, a);
	extraR += extraA + c;
	return extraR < extraA ? 1 : (extraR == extraA ? c : 0);
}

// Multiprecision greater than or equal (>=) operator
static mp_word mp_gte(mp_number& a, const mp_number& b) {
	mp_word l = 0, g = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		if (a.d[i] < b.d[i]) l |= (1 << i);
		if (a.d[i] > b.d[i]) g |= (1 << i);
	}

	return g >= l;
}

// Bit shifts a number with an extra word to the right one step
static void mp_shr_extra(mp_number& r, mp_word& e) {
	r.d[0] = (r.d[1] << 31) | (r.d[0] >> 1);
	r.d[1] = (r.d[2] << 31) | (r.d[1] >> 1);
	r.d[2] = (r.d[3] << 31) | (r.d[2] >> 1);
	r.d[3] = (r.d[4] << 31) | (r.d[3] >> 1);
	r.d[4] = (r.d[5] << 31) | (r.d[4] >> 1);
	r.d[5] = (r.d[6] << 31) | (r.d[5] >> 1);
	r.d[6] = (r.d[7] << 31) | (r.d[6] >> 1);
	r.d[7] = (e << 31) | (r.d[7] >> 1);
	e >>= 1;
}

// Bit shifts a number to the right one step
static void mp_shr(mp_number& r) {
	r.d[0] = (r.d[1] << 31) | (r.d[0] >> 1);
	r.d[1] = (r.d[2] << 31) | (r.d[1] >> 1);
	r.d[2] = (r.d[3] << 31) | (r.d[2] >> 1);
	r.d[3] = (r.d[4] << 31) | (r.d[3] >> 1);
	r.d[4] = (r.d[5] << 31) | (r.d[4] >> 1);
	r.d[5] = (r.d[6] << 31) | (r.d[5] >> 1);
	r.d[6] = (r.d[7] << 31) | (r.d[6] >> 1);
	r.d[7] >>= 1;
}

// Multiplies a number with a word and adds it to an existing number with an extra word, overflow of the extra word is signalled in return value
// This is a special function only used for modular multiplication
static mp_word mp_mul_word_add_extra(mp_number& r, const mp_number& a, const mp_word w, mp_word& extra) {
	mp_word cM = 0; // Carry for multiplication
	mp_word cA = 0; // Carry for addition
	mp_word tM = 0; // Temporary storage for multiplication

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		tM = (a.d[i] * w + cM);
		cM = mul_hi(a.d[i], w) + (tM < cM);

		r.d[i] += tM + cA;
		cA = r.d[i] < tM ? 1 : (r.d[i] == tM ? cA : 0);
	}

	extra += cM + cA;
	return extra < cM ? 1 : (extra == cM ? cA : 0);
}

// Multiplies a number with a word, potentially adds modhigher to it, and then subtracts it from en existing number, no extra words, no overflow
// This is a special function only used for modular multiplication
static void mp_mul_mod_word_sub(mp_number& r, const mp_word w, const bool withModHigher) {
	// Having these numbers declared here instead of using the global values in __constant address space seems to lead
	// to better optimizations by the compiler on my GTX 1070.
	mp_number mod = { { 0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff} };
	mp_number modhigher = { {0x00000000, 0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff} };

	mp_word cM = 0; // Carry for multiplication
	mp_word cS = 0; // Carry for subtraction
	mp_word tS = 0; // Temporary storage for subtraction
	mp_word tM = 0; // Temporary storage for multiplication
	mp_word cA = 0; // Carry for addition of modhigher

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		tM = (mod.d[i] * w + cM);
		cM = mul_hi(mod.d[i], w) + (tM < cM);

		tM += (withModHigher ? modhigher.d[i] : 0) + cA;
		cA = tM < (withModHigher ? modhigher.d[i] : 0) ? 1 : (tM == (withModHigher ? modhigher.d[i] : 0) ? cA : 0);

		tS = r.d[i] - tM - cS;
		cS = tS > r.d[i] ? 1 : (tS == r.d[i] ? cS : 0);

		r.d[i] = tS;
	}
}

// Modular multiplication. Based on Algorithm 3 (and a series of hunches) from this article:
// https://www.esat.kuleuven.be/cosic/publications/article-1191.pdf
// When I first implemented it I never encountered a situation where the additional end steps
// of adding or subtracting the modulo was necessary. Maybe it's not for the particular modulo
// used in secp256k1, maybe the overflow bit can be skipped in to avoid 8 subtractions and
// trade it for the final steps? Maybe the final steps are necessary but seldom needed?
// I have no idea, for the time being I'll leave it like this, also see the comments at the
// beginning of this document under the title "Cutting corners".
static void mp_mod_mul(mp_number& r, const mp_number& X, const mp_number& Y) {
	mp_number Z = { {0} };
	mp_word extraWord;

	for (int i = MP_WORDS - 1; i >= 0; --i) {
		// Z = Z * 2^32
		extraWord = Z.d[7]; Z.d[7] = Z.d[6]; Z.d[6] = Z.d[5]; Z.d[5] = Z.d[4]; Z.d[4] = Z.d[3]; Z.d[3] = Z.d[2]; Z.d[2] = Z.d[1]; Z.d[1] = Z.d[0]; Z.d[0] = 0;

		// Z = Z + X * Y_i
		bool overflow = mp_mul_word_add_extra(Z, X, Y.d[i], extraWord);

		// Z = Z - qM
		mp_mul_mod_word_sub(Z, extraWord, overflow);
	}

	r = Z;
}

// Modular inversion of a number.
static void mp_mod_inverse(mp_number& r) {
	mp_number A = { { 1 } };
	mp_number C = { { 0 } };
	mp_number v = mod;

	mp_word extraA = 0;
	mp_word extraC = 0;

	while (r.d[0] || r.d[1] || r.d[2] || r.d[3] || r.d[4] || r.d[5] || r.d[6] || r.d[7]) {
		while (!(r.d[0] & 1)) {
			mp_shr(r);
			if (A.d[0] & 1) {
				extraA += mp_add_mod(A);
			}

			mp_shr_extra(A, extraA);
		}

		while (!(v.d[0] & 1)) {
			mp_shr(v);
			if (C.d[0] & 1) {
				extraC += mp_add_mod(C);
			}

			mp_shr_extra(C, extraC);
		}

		if (mp_gte(r, v)) {
			mp_sub(r, r, v);
			mp_add_more(A, extraA, C, extraC);
		}
		else {
			mp_sub(v, v, r);
			mp_add_more(C, extraC, A, extraA);
		}
	}

	while (extraC) {
		extraC -= mp_sub_mod(C);
	}

	v = mod;
	mp_sub(r, v, C);
}


#define TH_ELT(t, c0, c1, c2, c3, c4, d0, d1, d2, d3, d4) \
{ \
    t = rotate64((uint64_t)(d0 ^ d1 ^ d2 ^ d3 ^ d4), (uint64_t)1) ^ (c0 ^ c1 ^ c2 ^ c3 ^ c4); \
}

#define THETA(s00, s01, s02, s03, s04, \
              s10, s11, s12, s13, s14, \
              s20, s21, s22, s23, s24, \
              s30, s31, s32, s33, s34, \
              s40, s41, s42, s43, s44) \
{ \
    TH_ELT(t0, s40, s41, s42, s43, s44, s10, s11, s12, s13, s14); \
    TH_ELT(t1, s00, s01, s02, s03, s04, s20, s21, s22, s23, s24); \
    TH_ELT(t2, s10, s11, s12, s13, s14, s30, s31, s32, s33, s34); \
    TH_ELT(t3, s20, s21, s22, s23, s24, s40, s41, s42, s43, s44); \
    TH_ELT(t4, s30, s31, s32, s33, s34, s00, s01, s02, s03, s04); \
    s00 ^= t0; s01 ^= t0; s02 ^= t0; s03 ^= t0; s04 ^= t0; \
    s10 ^= t1; s11 ^= t1; s12 ^= t1; s13 ^= t1; s14 ^= t1; \
    s20 ^= t2; s21 ^= t2; s22 ^= t2; s23 ^= t2; s24 ^= t2; \
    s30 ^= t3; s31 ^= t3; s32 ^= t3; s33 ^= t3; s34 ^= t3; \
    s40 ^= t4; s41 ^= t4; s42 ^= t4; s43 ^= t4; s44 ^= t4; \
}

#define RHOPI(s00, s01, s02, s03, s04, \
              s10, s11, s12, s13, s14, \
              s20, s21, s22, s23, s24, \
              s30, s31, s32, s33, s34, \
              s40, s41, s42, s43, s44) \
{ \
	t0  = rotate64(s10, (uint64_t) 1);  \
	s10 = rotate64(s11, (uint64_t)44); \
	s11 = rotate64(s41, (uint64_t)20); \
	s41 = rotate64(s24, (uint64_t)61); \
	s24 = rotate64(s42, (uint64_t)39); \
	s42 = rotate64(s04, (uint64_t)18); \
	s04 = rotate64(s20, (uint64_t)62); \
	s20 = rotate64(s22, (uint64_t)43); \
	s22 = rotate64(s32, (uint64_t)25); \
	s32 = rotate64(s43, (uint64_t) 8); \
	s43 = rotate64(s34, (uint64_t)56); \
	s34 = rotate64(s03, (uint64_t)41); \
	s03 = rotate64(s40, (uint64_t)27); \
	s40 = rotate64(s44, (uint64_t)14); \
	s44 = rotate64(s14, (uint64_t) 2); \
	s14 = rotate64(s31, (uint64_t)55); \
	s31 = rotate64(s13, (uint64_t)45); \
	s13 = rotate64(s01, (uint64_t)36); \
	s01 = rotate64(s30, (uint64_t)28); \
	s30 = rotate64(s33, (uint64_t)21); \
	s33 = rotate64(s23, (uint64_t)15); \
	s23 = rotate64(s12, (uint64_t)10); \
	s12 = rotate64(s21, (uint64_t) 6); \
	s21 = rotate64(s02, (uint64_t) 3); \
	s02 = t0; \
}

#define KHI(s00, s01, s02, s03, s04, \
            s10, s11, s12, s13, s14, \
            s20, s21, s22, s23, s24, \
            s30, s31, s32, s33, s34, \
            s40, s41, s42, s43, s44) \
{ \
    t0 = s00 ^ (~s10 &  s20); \
    t1 = s10 ^ (~s20 &  s30); \
    t2 = s20 ^ (~s30 &  s40); \
    t3 = s30 ^ (~s40 &  s00); \
    t4 = s40 ^ (~s00 &  s10); \
    s00 = t0; s10 = t1; s20 = t2; s30 = t3; s40 = t4; \
    \
    t0 = s01 ^ (~s11 &  s21); \
    t1 = s11 ^ (~s21 &  s31); \
    t2 = s21 ^ (~s31 &  s41); \
    t3 = s31 ^ (~s41 &  s01); \
    t4 = s41 ^ (~s01 &  s11); \
    s01 = t0; s11 = t1; s21 = t2; s31 = t3; s41 = t4; \
    \
    t0 = s02 ^ (~s12 &  s22); \
    t1 = s12 ^ (~s22 &  s32); \
    t2 = s22 ^ (~s32 &  s42); \
    t3 = s32 ^ (~s42 &  s02); \
    t4 = s42 ^ (~s02 &  s12); \
    s02 = t0; s12 = t1; s22 = t2; s32 = t3; s42 = t4; \
    \
    t0 = s03 ^ (~s13 &  s23); \
    t1 = s13 ^ (~s23 &  s33); \
    t2 = s23 ^ (~s33 &  s43); \
    t3 = s33 ^ (~s43 &  s03); \
    t4 = s43 ^ (~s03 &  s13); \
    s03 = t0; s13 = t1; s23 = t2; s33 = t3; s43 = t4; \
    \
    t0 = s04 ^ (~s14 &  s24); \
    t1 = s14 ^ (~s24 &  s34); \
    t2 = s24 ^ (~s34 &  s44); \
    t3 = s34 ^ (~s44 &  s04); \
    t4 = s44 ^ (~s04 &  s14); \
    s04 = t0; s14 = t1; s24 = t2; s34 = t3; s44 = t4; \
}

#define IOTA(s00, r) { s00 ^= r; }

static uint64_t keccakf_rndc[24] = {
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

// Barely a bottleneck. No need to tinker more.
static void cpu_sha3_keccakf(ethhash& h)
{
	uint64_t* const st = (uint64_t*)&h;
	h.d[33] ^= 0x80000000;
	uint64_t t0, t1, t2, t3, t4;

	// Unrolling and removing PI stage gave negligible performance on GTX 1070.
	for (int i = 0; i < 24; ++i) {
		THETA(st[0], st[5], st[10], st[15], st[20], st[1], st[6], st[11], st[16], st[21], st[2], st[7], st[12], st[17], st[22], st[3], st[8], st[13], st[18], st[23], st[4], st[9], st[14], st[19], st[24]);
		RHOPI(st[0], st[5], st[10], st[15], st[20], st[1], st[6], st[11], st[16], st[21], st[2], st[7], st[12], st[17], st[22], st[3], st[8], st[13], st[18], st[23], st[4], st[9], st[14], st[19], st[24]);
		KHI(st[0], st[5], st[10], st[15], st[20], st[1], st[6], st[11], st[16], st[21], st[2], st[7], st[12], st[17], st[22], st[3], st[8], st[13], st[18], st[23], st[4], st[9], st[14], st[19], st[24]);
		IOTA(st[0], keccakf_rndc[i]);
	}
}

// Elliptical point addition
// Does not handle points sharing X coordinate, this is a deliberate design choice.
// For more information on this choice see the beginning of this file.
static void point_add(point& r, const point& p, const point& o) {
	mp_number tmp;
	mp_number newX;
	mp_number newY;

	mp_mod_sub(tmp, o.x, p.x);

	mp_mod_inverse(tmp);

	mp_mod_sub(newX, o.y, p.y);
	mp_mod_mul(tmp, tmp, newX);

	mp_mod_mul(newX, tmp, tmp);
	mp_mod_sub(newX, newX, p.x);
	mp_mod_sub(newX, newX, o.x);

	mp_mod_sub(newY, p.x, newX);
	mp_mod_mul(newY, newY, tmp);
	mp_mod_sub(newY, newY, p.y);

	r.x = newX;
	r.y = newY;
}

// n = multi-precision number
// bit = bit index (0 = least significant)
// result = output bool
bool mp_getbit(const mp_number& n, int bit) {
    const int quad = bit / 64;
    const int bit_in_word = 63 - bit % 64;

	return (n.q[quad] >> bit_in_word) & 1ULL;
}




/****************************************************************************

                         SHA512


            Original copyright (sha256):
            OpenCL Optimized kernel
            (c) B. Kerler 2018
            MIT License

            Adapted for SHA512 by C.B .. apparently quite a while ago
            The moral of the story is always use UL on uint64_ts!

*****************************************************************************/


#define rotl64(X, S) (((X) << S) | ((X) >> (64 - S)))
#define rotr64(X, S) (((X) >> (S)) | ((X) << (64 - (S))))
 
static inline uint64_t bitselect(uint64_t a, uint64_t b, uint64_t c) {
	return (a & ~c) | (b & c);
}
static inline uint64_t swap64(const uint64_t val)
{
	// ab cd ef gh -> gh ef cd ab using the 32 bit trick
	uint64_t tmp = (rotr64(val & 0x0000FFFF0000FFFFUL, 16UL) | rotl64(val & 0xFFFF0000FFFF0000UL, 16UL));

	// Then see this as g- e- c- a- and -h -f -d -b to swap within the pairs,
	// gh ef cd ab -> hg fe dc ba
	return (rotr64(tmp & 0xFF00FF00FF00FF00UL, 8UL) | rotl64(tmp & 0x00FF00FF00FF00FFUL, 8UL));
}

// Elliptical point doubling
// p = point to double
// r = result (2p)

static void point_double(point& r, const point& p) {
	mp_number tmp1, tmp2, slope, newX, newY;

	// tmp1 = 3 * p.x^2
	mp_mod_mul(tmp1, p.x, p.x);       // tmp1 = x^2

	mp_number three = { 0 };

	three.q[3] = swap64(3);

	mp_mod_mul(tmp1, tmp1, (mp_number&)three); // tmp1 = 3x^2

	three.q[3] = swap64(2);
	// slope = (3x^2) / (2y)
	tmp2 = p.y;
	mp_mod_mul(tmp2, tmp2, (mp_number&)three); // tmp1 = 3x^2
	mp_mod_inverse(tmp2);             // tmp2 = (2y)^-1
	mp_mod_mul(slope, tmp1, tmp2);

	// newX = slope^2 - 2x
	mp_mod_mul(newX, slope, slope);
	mp_mod_sub(newX, newX, p.x);
	mp_mod_sub(newX, newX, p.x);

	// newY = slope * (x - newX) - y
	mp_mod_sub(newY, p.x, newX);
	mp_mod_mul(newY, slope, newY);
	mp_mod_sub(newY, newY, p.y);

	r.x = newX;
	r.y = newY;
}








// bitselect is "if c then b else a" for each bit
// so equivalent to (c & b) | ((~c) & a)
#define choose64(x,y,z)   (bitselect(z,y,x))
// Cleverly determines majority vote, conditioning on x=z
#define bit_maj(x,y,z)   (bitselect (x, y, ((x) ^ (z))))


// ==============================================================================
// =========  S0,S1,s0,s1  ======================================================


#define S0(x) (rotr64(x,28ull) ^ rotr64(x,34ull) ^ rotr64(x,39ull))
#define S1(x) (rotr64(x,14ull) ^ rotr64(x,18ull) ^ rotr64(x,41ull))

#define little_s0(x) (rotr64(x,1ull) ^ rotr64(x,8ull) ^ ((x) >> 7ull))
#define little_s1(x) (rotr64(x,19ull) ^ rotr64(x,61ull) ^ ((x) >> 6ull))


// ==============================================================================
// =========  MD-pads the input, taken from md5.cl  =============================
// Adapted for uint64_ts
// Note that the padding is still in a distinct uint64_t to the appended length.


// 'highBit' macro is (i+1) bytes, all 0 but the last which is 0x80
//  where we are thinking Little-endian thoughts.
// Don't forget to call constants longs!!
#define highBit(i) (0x1ULL << (8*i + 7))
#define fBytes(i) (0xFFFFFFFFFFFFFFFFULL >> (8 * (8-i)))
 uint64_t padLong[8] = {
	highBit(0), highBit(1), highBit(2), highBit(3),
	highBit(4), highBit(5), highBit(6), highBit(7)
}; 
uint64_t maskLong[8] = {
	0, fBytes(1), fBytes(2), fBytes(3),     // strange behaviour for fBytes(0)
	fBytes(4), fBytes(5), fBytes(6), fBytes(7)
};


/* The standard padding, INPLACE,
	add a 1 bit, then little-endian original length mod 2^128 (not 64) at the end of a block
	RETURN number of blocks */                  
static int sha512_inplace_padding(uint64_t* msg, const uint64_t msgLen_bytes)
{                                                                      
	/* Appends the 1 bit to the end, and 0s to the end of the byte */ 
	const uint32_t padLongIndex = (msgLen_bytes) / 8;              
	const uint32_t overhang = ((msgLen_bytes) - padLongIndex * 8);   
	/* Don't assume that there are zeros here! */                   
	msg[padLongIndex] &= maskLong[overhang];                          
	msg[padLongIndex] |= padLong[overhang];                              
	
	/* Previous code was horrible
		Now we zero until we reach a multiple of the block size,
		Skipping TWO longs to ensure there is room for the length */     
	msg[padLongIndex + 1] = 0;                                          
	msg[padLongIndex + 2] = 0;                                          
	uint32_t i = 0;                                                 
	for (i = padLongIndex + 3; i % 16 != 0; i++)
	{                                                                  
		msg[i] = 0;                                                     
	}                                                                   
	
	/* Determine the total number of blocks */                          
	int nBlocks = i / 16;
	/* Add the bit length to the end, 128-bit, big endian? (source wikipedia)
		Seemingly this does require SWAPing, so perhaps it's little-endian? */           
	msg[i - 2] = 0;   /* For clarity */                                   
	msg[i - 1] = swap64(msgLen_bytes * 8);                                    
	return nBlocks;                                                     
}

#undef bs_long
#undef def_md_pad_128
#undef highBit
#undef fBytes

// ==============================================================================

uint64_t k_sha256[80] =
{
	0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL,
	0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL, 0x12835b0145706fbeUL,
	0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL, 0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
	0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
	0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL, 0x983e5152ee66dfabUL,
	0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
	0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL,
	0x53380d139d95b3dfUL, 0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
	0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL,
	0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL, 0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL,
	0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL,
	0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
	0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL, 0xca273eceea26619cUL,
	0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL,
	0x113f9804bef90daeUL, 0x1b710b35131c471bUL, 0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
	0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};


#define SHA512_STEP(a,b,c,d,e,f,g,h,x,K)  \
/**/                \
{                   \
  h += K + S1(e) + choose64(e,f,g) + x; /* h = temp1 */   \
  d += h;           \
  h += S0(a) + bit_maj(a,b,c);  \
}


/* The main hashing function */     
static void sha512_hash_function(uint64_t *input, const uint32_t length, uint64_t* hash)
{                                   
    /* Do the padding - we weren't previously for some reason */            
	const uint32_t nBlocks = sha512_inplace_padding(input, (const unsigned long)length);
    /*if (length == 8){   
        printf("Padded input: ");   \
        printFromLongFunc(input, hashBlockSize_bytes, true)
    }*/   
                                    
    uint64_t W[0x50];      
    /* state which is repeatedly processed & added to */    
    uint64_t State[8]={0};   
    State[0] = 0x6a09e667f3bcc908UL;
    State[1] = 0xbb67ae8584caa73bUL;	
    State[2] = 0x3c6ef372fe94f82bUL;	
    State[3] = 0xa54ff53a5f1d36f1UL;	
    State[4] = 0x510e527fade682d1UL;	
    State[5] = 0x9b05688c2b3e6c1fUL;	
    State[6] = 0x1f83d9abfb41bd6bUL;	
    State[7] = 0x5be0cd19137e2179UL;
                                  
    uint64_t a,b,c,d,e,f,g,h;  
                                
    /* loop for each block */   
    for (int block_i = 0; block_i < nBlocks; block_i++)     
    {                                           
        /* No need to (re-)initialise W.
			Note that the input pointer is updated */    
		W[0] = swap64(input[0]);
		W[1] = swap64(input[1]);	
		W[2] = swap64(input[2]);	
		W[3] = swap64(input[3]);	
		W[4] = swap64(input[4]);	
		W[5] = swap64(input[5]);	
		W[6] = swap64(input[6]);	
		W[7] = swap64(input[7]);	
		W[8] = swap64(input[8]);	
		W[9] = swap64(input[9]);	
		W[10] = swap64(input[10]);	
		W[11] = swap64(input[11]);	
		W[12] = swap64(input[12]);	
		W[13] = swap64(input[13]);	
		W[14] = swap64(input[14]);	
		W[15] = swap64(input[15]);	
	
		for (int i = 16; i < 80; i++)   
		{                   
			W[i] = W[i - 16] + little_s0(W[i - 15]) + W[i - 7] + little_s1(W[i - 2]);   
		}               
		
		a = State[0];   
		b = State[1];   
		c = State[2];   
		d = State[3];   
		e = State[4];   
		f = State[5];   
		g = State[6];  
		h = State[7];   
		
		/* Note loop is only 5 */  
		for (int i = 0; i < 80; i += 16)    
		{                   
            SHA512_STEP(a, b, c, d, e, f, g, h, W[i + 0], k_sha256[i +  0]);
            SHA512_STEP(h, a, b, c, d, e, f, g, W[i + 1], k_sha256[i +  1]);
            SHA512_STEP(g, h, a, b, c, d, e, f, W[i + 2], k_sha256[i +  2]);
            SHA512_STEP(f, g, h, a, b, c, d, e, W[i + 3], k_sha256[i +  3]);
            SHA512_STEP(e, f, g, h, a, b, c, d, W[i + 4], k_sha256[i +  4]);
            SHA512_STEP(d, e, f, g, h, a, b, c, W[i + 5], k_sha256[i +  5]);
            SHA512_STEP(c, d, e, f, g, h, a, b, W[i + 6], k_sha256[i +  6]);
            SHA512_STEP(b, c, d, e, f, g, h, a, W[i + 7], k_sha256[i +  7]);
            SHA512_STEP(a, b, c, d, e, f, g, h, W[i + 8], k_sha256[i +  8]);
            SHA512_STEP(h, a, b, c, d, e, f, g, W[i + 9], k_sha256[i +  9]);
            SHA512_STEP(g, h, a, b, c, d, e, f, W[i + 10], k_sha256[i + 10]);
            SHA512_STEP(f, g, h, a, b, c, d, e, W[i + 11], k_sha256[i + 11]);
            SHA512_STEP(e, f, g, h, a, b, c, d, W[i + 12], k_sha256[i + 12]);
            SHA512_STEP(d, e, f, g, h, a, b, c, W[i + 13], k_sha256[i + 13]);
            SHA512_STEP(c, d, e, f, g, h, a, b, W[i + 14], k_sha256[i + 14]);
            SHA512_STEP(b, c, d, e, f, g, h, a, W[i + 15], k_sha256[i + 15]);
		}                   
			
		State[0] += a;  
		State[1] += b;  
		State[2] += c;  
		State[3] += d;  
		State[4] += e;  
		State[5] += f;  
		State[6] += g;  
		State[7] += h;  
		input += 16;   
	}                   
		
	hash[0] = swap64(State[0]);   
	hash[1] = swap64(State[1]);   
	hash[2] = swap64(State[2]);   
	hash[3] = swap64(State[3]);   
	hash[4] = swap64(State[4]);   
	hash[5] = swap64(State[5]);   
	hash[6] = swap64(State[6]);   
	hash[7] = swap64(State[7]);   
	return;             
}

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64
void hmac_sha512(
	const uint8_t key[128],
	const uint8_t message[37],
	uint8_t out_digest[64])
{
	const size_t key_len = 32;
	const size_t msg_len = 37;
	uint8_t key_block[SHA512_BLOCK_SIZE];
	uint8_t inner_digest[SHA512_DIGEST_SIZE];
	uint8_t input_buf[256]; //two blocks each 128 bytes
	uint64_t hash_buf[8];    
	for (int i = 0; i < SHA512_BLOCK_SIZE; i++) {
		input_buf[i] = key[i] ^ 0x36;
	}
	memcpy(input_buf + SHA512_BLOCK_SIZE, message, msg_len);
	sha512_hash_function((uint64_t*)input_buf, SHA512_BLOCK_SIZE + msg_len, hash_buf);
	memcpy(inner_digest, hash_buf, SHA512_DIGEST_SIZE);

	// Step 4: Outer hash = sha512(k_opad || inner_digest)

	//reuse input_buf
	for (int i = 0; i < SHA512_BLOCK_SIZE; i++) {
		input_buf[i] = key[i] ^ 0x5c;
	}
	memcpy(input_buf + SHA512_BLOCK_SIZE, inner_digest, SHA512_DIGEST_SIZE);
	sha512_hash_function((uint64_t*)input_buf, SHA512_BLOCK_SIZE + SHA512_DIGEST_SIZE, hash_buf);

	memcpy(out_digest, hash_buf, SHA512_DIGEST_SIZE);
}

cl_ulong4 bip32_cpu_createRandomSeed() {
	// We do not need really safe crypto random here, since we inherit safety
	// of the key from the user-provided seed public key.
	// We only need this random to not repeat same job among different devices


	cl_ulong4 diff;
	diff.s[0] = get_next_random();
	diff.s[1] = get_next_random();
	diff.s[2] = get_next_random();
	diff.s[3] = 0x0;
	return diff;
}
void cpu_bip32_data_init(bip32_search_data *init_data)
{
    init_data->total_compute = 0;
    init_data->time_started = get_app_time_sec();

    int data_count = init_data->kernel_group_size * init_data->kernel_groups;
    cudaMalloc((void **)&init_data->device_result, sizeof(search_result) * RESULTS_ARRAY_SIZE);
    cudaMalloc((void **)&init_data->device_precomp, sizeof(point) * 8160);
    cudaMemcpy(init_data->device_precomp, g_precomp, sizeof(point) * 8160, cudaMemcpyHostToDevice);

    init_data->host_result = new search_result[RESULTS_ARRAY_SIZE]();

    memset(init_data->host_result, 0, sizeof(search_result) * RESULTS_ARRAY_SIZE);
}

void cpu_bip32_data_destroy(bip32_search_data *init_data)
{
    delete[] init_data->host_result;
    cudaFree(init_data->device_result);
    cudaFree(init_data->device_precomp);
}
static std::string toHex(const uint8_t * const s, const size_t len) {
	std::string b("0123456789abcdef");
	std::string r;

	for (size_t i = 0; i < len; ++i) {
		const unsigned char h = s[i] / 16;
		const unsigned char l = s[i] % 16;

		r = r + b.substr(h, 1) + b.substr(l, 1);
	}

	return r;
}
static uint8_t fromHexChar(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
	throw std::invalid_argument("Invalid hex character");
}

static void fromHex(const std::string& hex, uint8_t* out, size_t outLen) {
	if (hex.size() % 2 != 0) {
		throw std::invalid_argument("Hex string must have even length");
	}
	if (outLen < hex.size() / 2) {
		throw std::length_error("Output buffer too small");
	}

	for (size_t i = 0; i < hex.size(); i += 2) {
		uint8_t high = fromHexChar(hex[i]);
		uint8_t low = fromHexChar(hex[i + 1]);
		out[i / 2] = (high << 4) | low;
	}
}

void random_encoding_test() {
	uint8_t raw[82];
	for (int i = 0; i < 82; i++) {
		raw[i] = get_next_random() % 256;
	}
	//printf("Random : %s\n", toHex(raw, 82).c_str());
	bip32_pub_key_compr enc;
	b58enc(enc.data, &enc.size, raw);

	if (enc.size != 110 && enc.size != 111 && enc.size != 112) {
		printf("WARN: different compr size %d\n", enc.size);
	}
	if (enc.size > 112) {
		printf("Random encoding test failed too big encoding size\n");
		return;
	}
	//printf("Encoded: %.*s\n", enc.size, enc.data);

	uint8_t raw2[82];
	b58tobin(raw2, (const char*)enc.data, enc.size);
	//printf("Reenco : %s\n", toHex(raw2, 82).c_str());
	if (memcmp(raw, raw2, 82) != 0) {
		printf("Random encoding test failed\n");
		return;
	}
}


struct sha_512_result {
	uint8_t bytes[64];
};

sha_512_result easy_hash_sha512(std::string input) {
	uint64_t hashIn[16] = { 0 };
	sha_512_result r = { 0 };

	memcpy(hashIn, input.c_str(), input.size());

	sha512_hash_function(hashIn, input.size(), (uint64_t*) r.bytes);

	return r;
}



bool test_sha_512() {

	if (toHex(easy_hash_sha512("56781234_44444").bytes, 64) != "c9e1ae246d000875522cd7d3b12d72595bebffbc07aa396a38c6fc6e183410e0dfde0dfcda367b10dc630b8fb73642fe6443163114e6f465da02cd24574d1c88" )
	{
		printf("SHA512 test failed\n");
		return false;
	}


	printf("SHA512 test passed\n");
	return true;
}

bool test_sha_512_hmac() {

	std::string key = "fb22a56b14dba5284857e76261a4bec31f5d0e7c62a53ced8ca0416aabc9f275";
	std::string pubkey = "027c430b31625c583ed5cd8bb759e7d0b66c359f2ca25b886602dcbd5ec7151fd0";
	std::string index = "00000000";
	std::string expected_result = "2f159ffec13ccb97cca28de88382b93e9a2739fe7db09adbc9dfc87c27eb155f897ad2ce04df9761e3c21e303e0ad60047c4cb86e64f2f3940f25258fa8b39c3";
	std::string data = pubkey + index;

	uint8_t keyBin[128] = {0};
	fromHex(key, keyBin, 32);
	uint8_t dataBin[37];
	fromHex(data, dataBin, 37);

	uint8_t out[64];
	hmac_sha512(keyBin, dataBin, out);
	std::string outHex = toHex(out, 64);

	if (outHex != expected_result) {
		printf("HMAC-SHA512 test failed\n");
		return false;
	}
	//printf("HMAC-SHA512 test passed\n");

	return true;
}


bool test_sha_512_hmac_loop() {

	std::string key = "fb22a56b14dba5284857e76261a4bec31f5d0e7c62a53ced8ca0416aabc9f275";
	std::string pubkey = "027c430b31625c583ed5cd8bb759e7d0b66c359f2ca25b886602dcbd5ec7151fd0";
	std::string index = "00000000";
	std::string expected_result = "2f159ffec13ccb97cca28de88382b93e9a2739fe7db09adbc9dfc87c27eb155f897ad2ce04df9761e3c21e303e0ad60047c4cb86e64f2f3940f25258fa8b39c3";
	std::string data = pubkey + index;

	uint8_t keyBin[128] = { 0 };
	fromHex(key, keyBin, 32);
	uint8_t dataBin[37];
	fromHex(data, dataBin, 37);

	uint8_t expected_out[64];
	fromHex(expected_result, expected_out, 64);

	for (int64_t i = 1; i <= 1000; i++) {
		if (i % 1000000 == 0) {
			printf("Computed: %lldM\n", (long long int) (i / 1000000));
			fflush(stdout);
		}
		uint8_t out[64];
		hmac_sha512(keyBin, dataBin, out);
		if (memcmp(expected_out, out, 64)) {
			printf("HMAC-SHA512 test failed\n");
			return false;
		}

	}
	//printf("HMAC-SHA512 test passed\n");

	return true;
}

secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

pattern_descriptor g_bip32_search_descr;
bool derive_child2(point pub, point &P, uint8_t * outchainCode, uint8_t chain_code[32], std::string path, uint32_t index) {
	//bip32_pub_key pub;


	uint8_t compressed_pub_key[33];
	compress_pubkey(compressed_pub_key, pub);
	secp256k1_pubkey pubkey;

	memcpy(pubkey.data, &pub, sizeof(point));

	uint8_t keyBin[128] = { 0 };
	uint8_t dataBin[37];

	memcpy(keyBin, chain_code, 32);
	memcpy(dataBin, compressed_pub_key, 33);

	dataBin[33] = (index >> 24) & 0xFF;
	dataBin[34] = (index >> 16) & 0xFF;
	dataBin[35] = (index >> 8) & 0xFF;
	dataBin[36] = index & 0xFF;

	uint8_t out[64];
	hmac_sha512(keyBin, dataBin, out);
	memcpy(outchainCode, &out[32], 32);

	//printf("SHA 512: %s\n", toHex(out, 64).c_str());


	const int success = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, (const unsigned char*)&out[0]);
	if (!success) {
		// invalid key
		fprintf(stderr, "Tweak add failed\n");
		return false;
	}

	mp_number gx;
	mp_number gy;

	memcpy(&gx, GxCoord, sizeof(mp_number));
	memcpy(&gy, GyCoord, sizeof(mp_number));

	//printf("Gx: %016llx%016llx%016llx%016llx\n", gx.q[3], gx.q[2], gx.q[1], gx.q[0]);
	//printf("Gy: %016llx%016llx%016llx%016llx\n", gy.q[3], gy.q[2], gy.q[1], gy.q[0]);


	memcpy(&P, &pubkey, sizeof(point));


	ethhash h = { { 0 } };


	// Initialize Keccak structure with point coordinates in big endian
	h.d[0] = bswap32(P.x.d[MP_WORDS - 1]);
	h.d[1] = bswap32(P.x.d[MP_WORDS - 2]);
	h.d[2] = bswap32(P.x.d[MP_WORDS - 3]);
	h.d[3] = bswap32(P.x.d[MP_WORDS - 4]);
	h.d[4] = bswap32(P.x.d[MP_WORDS - 5]);
	h.d[5] = bswap32(P.x.d[MP_WORDS - 6]);
	h.d[6] = bswap32(P.x.d[MP_WORDS - 7]);
	h.d[7] = bswap32(P.x.d[MP_WORDS - 8]);
	h.d[8] = bswap32(P.y.d[MP_WORDS - 1]);
	h.d[9] = bswap32(P.y.d[MP_WORDS - 2]);
	h.d[10] = bswap32(P.y.d[MP_WORDS - 3]);
	h.d[11] = bswap32(P.y.d[MP_WORDS - 4]);
	h.d[12] = bswap32(P.y.d[MP_WORDS - 5]);
	h.d[13] = bswap32(P.y.d[MP_WORDS - 6]);
	h.d[14] = bswap32(P.y.d[MP_WORDS - 7]);
	h.d[15] = bswap32(P.y.d[MP_WORDS - 8]);
	h.d[16] ^= 0x01; // length 64

	cpu_sha3_keccakf(h);

	// Save public address hash in pInverse, only used as interim storage until next cycle
	ethaddress& addr = *(ethaddress*)&h.d[3];
	if (cpu_scorer(addr, g_bip32_search_descr)) {
		printf("Matched address: 0x%s, path: %s/%d\n", toHex(&addr.b[0], 20).c_str(), path.c_str(), index);

		return true;
	}
	return false;
}



bool showInfoFirstLoop = true;
double startSecs = get_app_time_sec();
int64_t addresses_found = 0;
int64_t g_total_compute = 0;

void cpu_bip32_data_search(std::string public_key, pattern_descriptor descr, bip32_search_data *init_data)
{
	g_bip32_search_descr = descr;

	bip32_pub_key_compr compr;
	for (int i = 0; i < public_key.size(); i++) {
        compr.data[i] = public_key[i];
	}
    compr.data[public_key.size()] = 0;
	compr.size = public_key.size();

	bip32_pub_key_compr comprNew = compr;
	uint8_t raw[82];
	b58tobin(raw, (const char*)compr.data, compr.size);
	
	bip32_pub_key pub;
	pub.version = *(uint32_t*)&raw[0];
	pub.depth = raw[4];
	pub.parent_fpr = *(uint32_t*)&raw[5];
	pub.child_num = *(uint32_t*)&raw[9];
	memcpy(&pub.chain_code[0], &raw[13], 32);

	secp256k1_pubkey pubkey;
	if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, &raw[45], 33)) {
		// invalid key
		fprintf(stderr, "Invalid compressed pubkey\n");
		return;
	}

	point rootPublicPoint;
	memcpy(&rootPublicPoint.x, &pubkey.data[0], sizeof(mp_number));
	memcpy(&rootPublicPoint.y, &pubkey.data[32], sizeof(mp_number));

	memcpy(&pub.verification, &raw[78], 4);

	
	if (showInfoFirstLoop) {
		printf("BIP32 root xpub key details:\n");
		printf(" Version       : 0x%08x\n", bswap32(pub.version));
		printf(" Depth         : %d\n", pub.depth);
		printf(" Parent fpr    : 0x%08x\n", bswap32(pub.parent_fpr));
		printf(" Child num     : %u\n", bswap32(pub.child_num));
		printf(" Chain code    : %s\n", toHex(pub.chain_code, 32).c_str());
		printf(" Compressed key: %s\n", toHex(&raw[45], 33).c_str());
		printf(" Verification  : %s\n", toHex(pub.verification, 4).c_str());
		showInfoFirstLoop = false;
	}

	int32_t maxJ = init_data->rounds;
	int32_t maxK = init_data->kernel_group_size;

	std::string root_path = "%ROOT_PATH%/";
	for (int64_t i = 0; i <= init_data->kernel_groups; i++) {
		
		point pDerived;
		uint8_t outchainCode[32];
		uint32_t num = 100000 + get_next_random() % 2000000000;
		if (derive_child2(rootPublicPoint, pDerived, outchainCode, pub.chain_code, root_path, num)) {
			// printf("Matched address: 0x%s\n", toHex(&addr.b[0], 20).c_str());
		}
        std::string path = root_path + std::to_string(num);
		point pDerived2;
		uint8_t outchainCode2[32];
		for (int64_t j = 0; j < maxJ; j++) {
			uint32_t num2 = 100000 + get_next_random() % 2000000000;
			derive_child2(pDerived, pDerived2, outchainCode2, outchainCode, path, num2);
			uint8_t outchainCode3[32];
			point pDerived3;

			for (int32_t k = 0; k < maxK; k++) {
				if (derive_child2(pDerived2, pDerived3, outchainCode3, outchainCode2, path + "/" + std::to_string(num2), k)) {
					addresses_found += 1;
					printf("Number of addresses found: %lld\n", (long long int)addresses_found);
				}
			}
		}
		g_total_compute += (i * maxJ * maxK);
		double curSecs = get_app_time_sec();
		printf("Computed: %.02f MH, speed %.01f kH/s\n", g_total_compute / 1000000.0, g_total_compute / (curSecs - startSecs) / 1000);
		fflush(stdout);

	}
}