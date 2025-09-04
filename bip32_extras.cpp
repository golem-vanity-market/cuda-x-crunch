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




static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

typedef uint64_t b58_maxint_t;
typedef uint32_t b58_almostmaxint_t;
#define b58_almostmaxint_bits (sizeof(b58_almostmaxint_t) * 8)
static const b58_almostmaxint_t b58_almostmaxint_mask = ((((b58_maxint_t)1) << b58_almostmaxint_bits) - 1);

// probably no need to be optimized for CPU
bool b58tobin(uint8_t *bin, const char *b58, size_t b58sz)
{
	size_t binsz = 82;
	const uint8_t *b58u = (uint8_t*)b58;
	uint8_t *binu = bin;
	size_t outisz = (82 + 3) / 4;
	b58_almostmaxint_t outi[21];
	b58_maxint_t t;
	b58_almostmaxint_t c;
	size_t i, j;
	uint8_t bytesleft = binsz % sizeof(b58_almostmaxint_t);
	b58_almostmaxint_t zeromask = bytesleft ? (b58_almostmaxint_mask << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;
	
	if (!b58sz)
		b58sz = strlen(b58);
	
	for (i = 0; i < outisz; ++i) {
		outi[i] = 0;
	}
	
	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
		++zerocount;
	
	for ( ; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return false;
		if (b58digits_map[b58u[i]] == -1)
			// Invalid base58 digit
			return false;
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--; )
		{
			t = ((b58_maxint_t)outi[j]) * 58 + c;
			c = t >> b58_almostmaxint_bits;
			outi[j] = t & b58_almostmaxint_mask;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return false;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return false;
	}
	
	j = 0;
	if (bytesleft) {
		for (i = bytesleft; i > 0; --i) {
			*(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
		}
		++j;
	}
	
	for (; j < outisz; ++j)
	{
		for (i = sizeof(*outi); i > 0; --i) {
			*(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
		}
	}
	return true;
}
static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// this has to be optimized (it is used in new key derivation)
void b58enc(uint8_t* b58, uint8_t* b58sz, const uint8_t* data)
{
	int binsz = 82;
	const uint8_t* bin = data;
	int carry;
	size_t i, j, high, zcount = 0;
	size_t size;

	while (zcount < binsz && !bin[zcount])
		++zcount;

	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[114];
	memset(buf, 0, size);

	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
			if (!j) {
				// Otherwise j wraps to maxint which is > high
				break;
			}
		}
	}

	for (j = 0; j < size && !buf[j]; ++j);


	if (zcount)
		memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j)
		b58[i] = b58digits_ordered[buf[j]];
	b58[i] = '\0';
	*b58sz = i;
}

bip32_pub_key_compr cpu_decode_bip32_compressed(bip32_pub_key_compr compr) {
	bip32_pub_key r;

	bip32_pub_key_compr compr2;
	uint8_t out[82];
	b58tobin(out, (const char*)compr.data, compr.size);

	b58enc(compr2.data, &compr2.size, out);

	//printf("Start  : %.*s\n", compr.size, compr.data);
    //uint8_t out[82];
    //base58_decode((const char*) compr.data, out, 82);
    //display hex
	//printf("Decoded: %s\n", toHex(out, 78).c_str());

	printf("End    : %.*s\n", compr2.size, compr2.data);

    return compr2;
}


inline uint32_t bswap32(uint32_t x) {
	return ((x & 0x000000FFU) << 24) |
		((x & 0x0000FF00U) << 8) |
		((x & 0x00FF0000U) >> 8) |
		((x & 0xFF000000U) >> 24);
}

// Compress 65-byte uncompressed pubkey (0x04 || X || Y) into 33-byte compressed
// Returns 0 on success, -1 if invalid
int compress_pubkey(uint8_t out33[33], bip32_pub_key pub) {
	// Copy X coordinate (bytes 1..32)
	//memcpy(&out33[1], &pub.public_key_x, 32);

	cl_ulong4 x = pub.public_key_x;

	*(uint32_t*)&out33[29] = bswap32(x.d[0]);
	*(uint32_t*)&out33[25] = bswap32(x.d[1]);
	*(uint32_t*)&out33[21] = bswap32(x.d[2]);
	*(uint32_t*)&out33[17] = bswap32(x.d[3]);
	*(uint32_t*)&out33[13] = bswap32(x.d[4]);
	*(uint32_t*)&out33[9] = bswap32(x.d[5]);
	*(uint32_t*)&out33[5] = bswap32(x.d[6]);
	*(uint32_t*)&out33[1] = bswap32(x.d[7]);

	cl_ulong4 y = pub.public_key_y;
	// Check parity

	out33[0] = (y.d[0] & 0x1) ? 0x03 : 0x02;

	// Check parity of Y coordinate (last byte of pubkey = least significant byte of Y)
	//uint8_t y_parity = in65[64] & 1;
	//out33[0] = y_parity ? 0x03 : 0x02;

	return 0;
}

