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
	const uint8_t* key,
	const uint8_t* message,
	uint8_t* out_digest)
{
	const size_t key_len = 32;
	const size_t msg_len = 37;
	uint8_t key_block[SHA512_BLOCK_SIZE];
	uint8_t inner_digest[SHA512_DIGEST_SIZE];
	uint8_t temp_buf[SHA512_BLOCK_SIZE + msg_len + 1000];  // careful on stack for large msg
	uint64_t hash_buf[8];      // 8 x 64-bit = 64 bytes

	// Step 1: Normalize key
	if (key_len > SHA512_BLOCK_SIZE) {
		sha512_hash_function((uint64_t*)key, key_len, hash_buf);
		memcpy(key_block, hash_buf, SHA512_DIGEST_SIZE);
		memset(key_block + SHA512_DIGEST_SIZE, 0, SHA512_BLOCK_SIZE - SHA512_DIGEST_SIZE);
	}
	else {
		memcpy(key_block, key, key_len);
		memset(key_block + key_len, 0, SHA512_BLOCK_SIZE - key_len);
	}

	// Step 2: Create inner/outer pads
	uint8_t k_ipad[SHA512_BLOCK_SIZE];
	uint8_t k_opad[SHA512_BLOCK_SIZE];
	for (int i = 0; i < SHA512_BLOCK_SIZE; i++) {
		k_ipad[i] = key_block[i] ^ 0x36;
		k_opad[i] = key_block[i] ^ 0x5c;
	}

	// Step 3: Inner hash = sha512(k_ipad || message)
	memcpy(temp_buf, k_ipad, SHA512_BLOCK_SIZE);
	memcpy(temp_buf + SHA512_BLOCK_SIZE, message, msg_len);
	sha512_hash_function((uint64_t*)temp_buf, SHA512_BLOCK_SIZE + msg_len, hash_buf);
	memcpy(inner_digest, hash_buf, SHA512_DIGEST_SIZE);

	// Step 4: Outer hash = sha512(k_opad || inner_digest)
	uint8_t outer_buf[SHA512_BLOCK_SIZE + SHA512_DIGEST_SIZE + 100];
	memcpy(outer_buf, k_opad, SHA512_BLOCK_SIZE);
	memcpy(outer_buf + SHA512_BLOCK_SIZE, inner_digest, SHA512_DIGEST_SIZE);
	sha512_hash_function((uint64_t*)outer_buf, SHA512_BLOCK_SIZE + SHA512_DIGEST_SIZE, hash_buf);

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
    printf("0x%s,0x%s,0x%s,%s_%llu\n", strPrivate.c_str(), strPublic.c_str(), public_key.c_str(), g_strVersion.c_str(), (uint64_t)(init_data->total_compute / 1000 / 1000 / 1000));
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

inline uint32_t bswap32(uint32_t x) {
	return ((x & 0x000000FFU) << 24) |
		((x & 0x0000FF00U) << 8) |
		((x & 0x00FF0000U) >> 8) |
		((x & 0xFF000000U) >> 24);
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

	uint8_t keyBin[32];
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
	printf("HMAC-SHA512 test passed\n");

	return true;
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

	
	printf("Public key accepted: %s\n", toHex(compressed_pub_key, 33).c_str());
	printf("BIP32 root xpub key details:\n");
	printf(" Version       : 0x%08x\n", bswap32(pub.version));
	printf(" Depth         : %d\n", pub.depth);
	printf(" Parent fpr    : 0x%08x\n", bswap32(pub.parent_fpr));
	printf(" Child num     : %u\n", bswap32(pub.child_num));
	printf(" Chain code    : %s\n", toHex(pub.chain_code, 32).c_str());
	printf(" Compressed key: %s\n", toHex(compressed_pub_key, 33).c_str());
	printf(" Verification  : %s\n", toHex(pub.verification, 4).c_str());

	
	auto res = easy_hash_sha512("56781234_44444");
	printf(" Hex: %s\n", toHex(res.bytes, sizeof(res.bytes)).c_str());

	if (!test_sha_512()) {
		return;
	}
	if (!test_sha_512_hmac()) {
		return;
	}

	printf("Started random compression testing ..\n");
	for (int64_t i = 1; i <= 10000; i++) {
		if (i % 1000000 == 0) {
			printf("Computed: %lldM\n", i / 1000000);
			fflush(stdout);
		}
		random_encoding_test();
	}




}