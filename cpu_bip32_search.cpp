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
static void printResult(std::string public_key, cl_ulong4 seed, uint64_t round, search_result r, bip32_search_data *init_data) {

	// Format private key
	uint64_t carry = 0;
	cl_ulong4 seedRes;

	seedRes.s[0] = seed.s[0] + round; carry = seedRes.s[0] < round;
	seedRes.s[1] = seed.s[1] + carry; carry = !seedRes.s[1];
	seedRes.s[2] = seed.s[2] + carry; carry = !seedRes.s[2];
	seedRes.s[3] = seed.s[3] + carry + r.id;

	std::ostringstream ss;
	ss << std::hex << std::setfill('0');
	ss << std::setw(16) << seedRes.s[3] << std::setw(16) << seedRes.s[2] << std::setw(16) << seedRes.s[1] << std::setw(16) << seedRes.s[0];
	const std::string strPrivate = ss.str();

	// Format public key
	const std::string strPublic = toHex(r.addr, 20);

	// Print
    printf("0x%s,0x%s,0x%s,%s_%lu\n", strPrivate.c_str(), strPublic.c_str(), public_key.c_str(), g_strVersion.c_str(), (unsigned long)(init_data->total_compute / 1000 / 1000 / 1000));
}


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
static int compress_pubkey(uint8_t out33[33], bip32_pub_key pub) {
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

void cpu_bip32_data_search(std::string public_key, pattern_descriptor descr, bip32_search_data *init_data)
{
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
	pub.public_key_x = init_data->public_key_x;
	pub.public_key_y = init_data->public_key_y;
	pub.version = *(uint32_t*)&raw[0];
	pub.depth = raw[4];
	pub.parent_fpr = *(uint32_t*)&raw[5];
	pub.child_num = *(uint32_t*)&raw[9];
	memcpy(&pub.chain_code[0], &raw[13], 32);

	uint8_t compressed_pub_key[33];
	compress_pubkey(compressed_pub_key, pub);
	if (memcmp(&raw[45], compressed_pub_key, 33) != 0) {
		printf("Public key compression mismatch!\n");
		printf("Compressed public key from raw  : %s\n", toHex(&raw[45], 33).c_str());
		printf("Compressed public key from input: %s\n", toHex(compressed_pub_key, 33).c_str());
		return;
	}
	memcpy(&pub.verification, &raw[78], 4);

	printf("BIP32 public key details:\n");
	printf(" Version       : 0x%08x\n", bswap32(pub.version));
	printf(" Depth         : %d\n", pub.depth);
	printf(" Parent fpr    : 0x%08x\n", bswap32(pub.parent_fpr));
	printf(" Child num     : %u\n", bswap32(pub.child_num));
	printf(" Chain code    : %s\n", toHex(pub.chain_code, 32).c_str());
	printf(" Compressed key: %s\n", toHex(compressed_pub_key, 33).c_str());
	printf(" Verification  : %s\n", toHex(pub.verification, 4).c_str());

	printf("Public key accepted: %s\n", toHex(compressed_pub_key, 33).c_str());


	printf("Started random compression testing ..\n");
	for (int64_t i = 1; i <= 10000; i++) {
		if (i % 1000000 == 0) {
			printf("Computed: %lldM\n", i / 1000000);
			fflush(stdout);
		}
		random_encoding_test();
	}




}