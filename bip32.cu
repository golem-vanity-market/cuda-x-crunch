#include "private_key.h"
#include "scorer.cuh"

#define rotate64(x, s) ((x << s) | (x >> (64U - s)))

__device__ const mp_number tripleNegativeGx = { {0xbb17b196, 0xf2287bec, 0x76958573, 0xf82c096e, 0x946adeea, 0xff1ed83e, 0x1269ccfa, 0x92c4cc83 } };
__device__ const mp_number negativeGy       = { {0x04ef2777, 0x63b82f6f, 0x597aabe6, 0x02e84bb7, 0xf1eef757, 0xa25b0403, 0xd95c3b9a, 0xb7c52588 } };


#define mul_hi(a, b) __umulhi(a, b)

// mod              = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
__device__ const mp_number mod              = { {0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff} };


// tripleNegativeGx = 0x92c4cc831269ccfaff1ed83e946adeeaf82c096e76958573f2287becbb17b196

// doubleNegativeGy = 0x6f8a4b11b2b8773544b60807e3ddeeae05d0976eb2f557ccc7705edf09de52bf
//__device__ const mp_number doubleNegativeGy = { {0x09de52bf, 0xc7705edf, 0xb2f557cc, 0x05d0976e, 0xe3ddeeae, 0x44b60807, 0xb2b87735, 0x6f8a4b11} };

// negativeGy       = 0xb7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777

// Multiprecision subtraction. Underflow signalled via return value.
__device__ mp_word mp_sub(mp_number& r, const mp_number& a, const mp_number& b) {
	mp_word t, c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		t = a.d[i] - b.d[i] - c;
		c = t > a.d[i] ? 1 : (t == a.d[i] ? c : 0);

		r.d[i] = t;
	}

	return c;
}



// Multiprecision subtraction of the modulus saved in mod. Underflow signalled via return value.
__device__ mp_word mp_sub_mod(mp_number& r) {
	mp_number mod = { {0xfffffc2fU, 0xfffffffeU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU} };

	mp_word t, c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		t = r.d[i] - mod.d[i] - c;
		c = t > r.d[i] ? 1 : (t == r.d[i] ? c : 0);

		r.d[i] = t;
	}

	return c;
}


__device__ void mp_mod_sub(mp_number& r, const mp_number& a, const mp_number& b) {
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

__device__ void mp_mod_sub_const(mp_number& r, const mp_number& a, const mp_number& b) {
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


__device__ void mp_mod_sub_gx(mp_number& r, const mp_number& a) {
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
__device__ void mp_mod_sub_gy(mp_number& r, const mp_number& a) {
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
__device__ mp_word mp_add(mp_number& r, const mp_number& a) {
	mp_word c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		r.d[i] += a.d[i] + c;
		c = r.d[i] < a.d[i] ? 1 : (r.d[i] == a.d[i] ? c : 0);
	}

	return c;
}

// Multiprecision addition of the modulus saved in mod. Overflow signalled via return value.
__device__ mp_word mp_add_mod(mp_number& r) {
	mp_word c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		r.d[i] += mod.d[i] + c;
		c = r.d[i] < mod.d[i] ? 1 : (r.d[i] == mod.d[i] ? c : 0);
	}

	return c;
}

// Multiprecision addition of two numbers with one extra word each. Overflow signalled via return value.
__device__ mp_word mp_add_more(mp_number& r, mp_word& extraR, const mp_number& a, const mp_word& extraA) {
	const mp_word c = mp_add(r, a);
	extraR += extraA + c;
	return extraR < extraA ? 1 : (extraR == extraA ? c : 0);
}

// Multiprecision greater than or equal (>=) operator
__device__ mp_word mp_gte(mp_number& a, const mp_number& b) {
	mp_word l = 0, g = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		if (a.d[i] < b.d[i]) l |= (1 << i);
		if (a.d[i] > b.d[i]) g |= (1 << i);
	}

	return g >= l;
}

// Bit shifts a number with an extra word to the right one step
__device__ void mp_shr_extra(mp_number& r, mp_word& e) {
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
__device__ void mp_shr(mp_number& r) {
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
__device__ mp_word mp_mul_word_add_extra(mp_number& r, const mp_number& a, const mp_word w, mp_word& extra) {
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
__device__ void mp_mul_mod_word_sub(mp_number& r, const mp_word w, const bool withModHigher) {
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
__device__ void mp_mod_mul(mp_number& r, const mp_number& X, const mp_number& Y) {
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
__device__ void mp_mod_inverse(mp_number& r) {
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

__device__ uint64_t keccakf_rndc[24] = {
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
__device__ void sha3_keccakf(ethhash& h)
{
    uint64_t * const st = (uint64_t *) &h;
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
__device__ void point_add(point& r, point& p, point& o) {
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


__constant__ mp_number g_publicKeyX = {0};
__constant__ mp_number g_publicKeyY = {0};
__constant__ pattern_descriptor g_search_descr = {0};

void update_public_key(const mp_number &x, const mp_number &y)
{
    cudaMemcpyToSymbol(g_publicKeyX, &x, sizeof(mp_number));
    cudaMemcpyToSymbol(g_publicKeyY, &y, sizeof(mp_number));
}

void update_search_prefix(const pattern_descriptor pref)
{
    cudaMemcpyToSymbol(g_search_descr, &pref, sizeof(pattern_descriptor));
}


__device__ void profanity_init_seed_first(const point * const precomp, point& p, const uint32_t precompOffset, const uint64_t seed) {
	point o;
    bool bIsFirst = true;
	for (uint32_t i = 0; i < 8; ++i) {
		const uint32_t byte = (seed >> (i * 8)) & 0xFF;

		if (byte) {
			o = precomp[precompOffset + i * 255 + byte - 1];
            if (bIsFirst) {
                p = o;
                bIsFirst = false;
            } else {
                point_add(p, p, o);
            }
		}
	}
}

__device__ void profanity_init_seed(const point * const precomp, point& p, const uint32_t precompOffset, const uint64_t seed) {
	point o;

	for (uint32_t i = 0; i < 8; ++i) {
		const uint32_t byte = (seed >> (i * 8)) & 0xFF;

		if (byte) {
			o = precomp[precompOffset + i * 255 + byte - 1];
            point_add(p, p, o);
		}
	}
}

typedef struct {
	uint32_t found;
	uint32_t foundId;
	uint8_t foundHash[20];
} result;
#define PROFANITY_MAX_SCORE 40



__global__ void profanity_init_inverse_and_iterate(
    const point * const precomp,
    search_result* const results,
    uint32_t rounds,
    uint32_t kernelGroupSize,
    const cl_ulong4 seed,
    const cl_ulong4 seedX,
    const cl_ulong4 seedY)
{
    mp_number pInverse[PROFANITY_INVERSE_SIZE];
    mp_number pDeltaX[PROFANITY_INVERSE_SIZE];
    mp_number pPrevLambda[PROFANITY_INVERSE_SIZE];
    size_t global_id = (threadIdx.x + blockIdx.x * blockDim.x);

    for (int i = 0; i < PROFANITY_INVERSE_SIZE; i += 1) {
        size_t logical_id = global_id * PROFANITY_INVERSE_SIZE + i;

        point p = {
            .x = {.d = {
                (mp_word)(seedX.x & 0xFFFFFFFF), (mp_word)(seedX.x >> 32),
                (mp_word)(seedX.y & 0xFFFFFFFF), (mp_word)(seedX.y >> 32),
                (mp_word)(seedX.z & 0xFFFFFFFF), (mp_word)(seedX.z >> 32),
                (mp_word)(seedX.w & 0xFFFFFFFF), (mp_word)(seedX.w >> 32),
            }},
            .y = {.d = {
                (mp_word)(seedY.x & 0xFFFFFFFF), (mp_word)(seedY.x >> 32),
                (mp_word)(seedY.y & 0xFFFFFFFF), (mp_word)(seedY.y >> 32),
                (mp_word)(seedY.z & 0xFFFFFFFF), (mp_word)(seedY.z >> 32),
                (mp_word)(seedY.w & 0xFFFFFFFF), (mp_word)(seedY.w >> 32),
            }},
        };
        point p_random;

        mp_number tmp1, tmp2;
        point tmp3;

        // Calculate k*G where k = seed.wzyx (in other words, find the point indicated by the private key represented in seed)
        profanity_init_seed_first(precomp, p_random, 8 * 255 * 0, seed.x);
        profanity_init_seed(precomp, p_random, 8 * 255 * 1, seed.y);
        profanity_init_seed(precomp, p_random, 8 * 255 * 2, seed.z);
        profanity_init_seed(precomp, p_random, 8 * 255 * 3, seed.w + logical_id);
        point_add(p, p, p_random);

        // Calculate current lambda in this point
        mp_mod_sub_gx(tmp1, p.x);
        mp_mod_inverse(tmp1);

        mp_mod_sub_gy(tmp2, p.y);
        mp_mod_mul(tmp1, tmp1, tmp2);

        // Jump to next point (precomp[0] is the generator point G)
        tmp3 = precomp[0];
        point_add(p, tmp3, p);

        // pDeltaX should contain the delta (x - G_x)
        mp_mod_sub_gx(p.x, p.x);

        pDeltaX[i] = p.x;
        pPrevLambda[i] = tmp1;
    }

    //algorithm is tuned so first round is 2
    for (int round = 2; round < rounds + 2; round++) {
        // negativeDoubleGy = 0x6f8a4b11b2b8773544b60807e3ddeeae05d0976eb2f557ccc7705edf09de52bf
        mp_number negativeDoubleGy = { {0x09de52bf, 0xc7705edf, 0xb2f557cc, 0x05d0976e, 0xe3ddeeae, 0x44b60807, 0xb2b87735, 0x6f8a4b11 } };

        mp_number copy1, copy2;
        mp_number buffer[PROFANITY_INVERSE_SIZE];
        mp_number buffer2[PROFANITY_INVERSE_SIZE];

        // We initialize buffer and buffer2 such that:
        // buffer[i] = pDeltaX[id] * pDeltaX[id + 1] * pDeltaX[id + 2] * ... * pDeltaX[id + i]
        // buffer2[i] = pDeltaX[id + i]

        buffer[0] = pDeltaX[0];

        for (int32_t i = 1; i < PROFANITY_INVERSE_SIZE; ++i) {

            buffer2[i] = pDeltaX[i];

            mp_mod_mul(buffer[i], buffer2[i], buffer[i - 1]);
        }

        // Take the inverse of all x-values combined
        copy1 = buffer[PROFANITY_INVERSE_SIZE - 1];
        mp_mod_inverse(copy1);
        __syncthreads();

        // We multiply in -2G_y together with the inverse so that we have:
        //            - 2 * G_y
        //  ----------------------------
        //  x_0 * x_1 * x_2 * x_3 * ...
        mp_mod_mul(copy1, copy1, negativeDoubleGy);

        // Multiply out each individual inverse using the buffers
        for (int32_t i = PROFANITY_INVERSE_SIZE - 1; i > 0; --i) {
            mp_mod_mul(copy2, copy1, buffer[i - 1]);
            mp_mod_mul(copy1, copy1, buffer2[i]);
            pInverse[i] = copy2;
        }
        pInverse[0] = copy1;

        for (int i = 0; i < PROFANITY_INVERSE_SIZE; i += 1) {
            size_t logical_id = global_id * PROFANITY_INVERSE_SIZE + i;
            // negativeGx = 0x8641998106234453aa5f9d6a3178f4f8fd640324d231d726a60d7ea3e907e497
            mp_number negativeGx = { {0xe907e497, 0xa60d7ea3, 0xd231d726, 0xfd640324, 0x3178f4f8, 0xaa5f9d6a, 0x06234453, 0x86419981 } };

            ethhash h = { { 0 } };
            mp_number dX = pDeltaX[i];

            mp_number lambda = pPrevLambda[i];

            mp_number tmp = pInverse[i];

            // λ' = - (2G_y) / d' - λ <=> lambda := pInversedNegativeDoubleGy[id] - pPrevLambda[id]
            mp_mod_sub(lambda, tmp, lambda);

            // λ² = λ * λ <=> tmp := lambda * lambda = λ²
            mp_mod_mul(tmp, lambda, lambda);

            // d' = λ² - d - 3g = (-3g) - (d - λ²) <=> x := tripleNegativeGx - (x - tmp)
            mp_mod_sub(dX, dX, tmp);
            mp_mod_sub_const(dX, tripleNegativeGx, dX);

            pDeltaX[i] = dX;
            pPrevLambda[i] = lambda;

            // Calculate y from dX and lambda
            // y' = (-G_Y) - λ * d' <=> p.y := negativeGy - (p.y * p.x)
            mp_mod_mul(tmp, lambda, dX);
            mp_mod_sub_const(tmp, negativeGy, tmp);

            // Restore X coordinate from delta value
            mp_mod_sub(dX, dX, negativeGx);

            // Initialize Keccak structure with point coordinates in big endian
            h.d[0] = bswap32(dX.d[MP_WORDS - 1]);
            h.d[1] = bswap32(dX.d[MP_WORDS - 2]);
            h.d[2] = bswap32(dX.d[MP_WORDS - 3]);
            h.d[3] = bswap32(dX.d[MP_WORDS - 4]);
            h.d[4] = bswap32(dX.d[MP_WORDS - 5]);
            h.d[5] = bswap32(dX.d[MP_WORDS - 6]);
            h.d[6] = bswap32(dX.d[MP_WORDS - 7]);
            h.d[7] = bswap32(dX.d[MP_WORDS - 8]);
            h.d[8] = bswap32(tmp.d[MP_WORDS - 1]);
            h.d[9] = bswap32(tmp.d[MP_WORDS - 2]);
            h.d[10] = bswap32(tmp.d[MP_WORDS - 3]);
            h.d[11] = bswap32(tmp.d[MP_WORDS - 4]);
            h.d[12] = bswap32(tmp.d[MP_WORDS - 5]);
            h.d[13] = bswap32(tmp.d[MP_WORDS - 6]);
            h.d[14] = bswap32(tmp.d[MP_WORDS - 7]);
            h.d[15] = bswap32(tmp.d[MP_WORDS - 8]);
            h.d[16] ^= 0x01; // length 64

            sha3_keccakf(h);

            // Save public address hash in pInverse, only used as interim storage until next cycle
            ethaddress& addr = *(ethaddress*)&h.d[3];

            if (scorer(addr, g_search_descr)) {
                results[logical_id % RESULTS_ARRAY_SIZE].id = logical_id;
                results[logical_id % RESULTS_ARRAY_SIZE].round = round;

                for (int i = 0; i < 20; i++) {
                    results[logical_id % RESULTS_ARRAY_SIZE].addr[i] = addr.b[i];
                }
            }
        }
    }
}

__global__ void profanity_dump_all_results(mp_number * const pInverse, search_result* const results, const size_t rounds) {
    const size_t id = (threadIdx.x + blockIdx.x * blockDim.x);

    mp_number inv = pInverse[id];
    //int score = 0;

    results[id].id = id;
    results[id].round = rounds + 1;

    for (int i = 0; i < 20; i++) {
        results[id].addr[i] = inv.b[i];
    }
}


void run_kernel_private_search(private_search_data * data) {
    int number_of_rounds = data->rounds;
    profanity_init_inverse_and_iterate<<<(int)(data->kernel_groups), data->kernel_group_size>>>(
        data->device_precomp,
        data->device_result,
        number_of_rounds,
        data->kernel_groups * data->kernel_group_size,
        data->seed,
        data->public_key_x,
        data->public_key_y
    );

}

