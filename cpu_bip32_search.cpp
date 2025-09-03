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


/*
	Original copyright (sha256):
	OpenCL Optimized kernel
	(c) B. Kerler 2018
	MIT License

	Adapted for SHA512 by C.B .. apparently quite a while ago
	The moral of the story is always use UL on uint64_ts!
*/


#define rotl64(X, S) (((X) << S) | ((X) >> (64 - S)))
#define rotr64(X, S) (((X) >> (S)) | ((X) << (64 - (S))))
 
static inline uint64_t bitselect(uint64_t a, uint64_t b, uint64_t c) {
	return (a & ~c) | (b & c);
}
uint64_t swap64(const uint64_t val)
{
	// ab cd ef gh -> gh ef cd ab using the 32 bit trick
	uint64_t tmp = (rotr64(val & 0x0000FFFF0000FFFFUL, 16UL) | rotl64(val & 0xFFFF0000FFFF0000UL, 16UL));

	// Then see this as g- e- c- a- and -h -f -d -b to swap within the pairs,
	// gh ef cd ab -> hg fe dc ba
	return (rotr64(tmp & 0xFF00FF00FF00FF00UL, 8UL) | rotl64(tmp & 0x00FF00FF00FF00FFUL, 8UL));
}


// bitselect is "if c then b else a" for each bit
// so equivalent to (c & b) | ((~c) & a)
#define choose(x,y,z)   (bitselect(z,y,x))
// Cleverly determines majority vote, conditioning on x=z
#define bit_maj(x,y,z)   (bitselect (x, y, ((x) ^ (z))))

// Hopefully rotate works for long too?



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
static int mdPadFunc(uint64_t* msg, const uint64_t msgLen_bytes)
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
  h += K + S1(e) + choose(e,f,g) + x; /* h = temp1 */   \
  d += h;           \
  h += S0(a) + bit_maj(a,b,c);  \
}




#define ROUND_STEP(i) \
/**/                  \
{                     \
    SHA512_STEP(a, b, c, d, e, f, g, h, W[i + 0], k_sha256[i +  0]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W[i + 1], k_sha256[i +  1]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W[i + 2], k_sha256[i +  2]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W[i + 3], k_sha256[i +  3]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W[i + 4], k_sha256[i +  4]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W[i + 5], k_sha256[i +  5]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W[i + 6], k_sha256[i +  6]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i + 7], k_sha256[i +  7]); \
    SHA512_STEP(a, b, c, d, e, f, g, h, W[i + 8], k_sha256[i +  8]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W[i + 9], k_sha256[i +  9]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W[i + 10], k_sha256[i + 10]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W[i + 11], k_sha256[i + 11]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W[i + 12], k_sha256[i + 12]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W[i + 13], k_sha256[i + 13]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W[i + 14], k_sha256[i + 14]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i + 15], k_sha256[i + 15]); \
}


/* The main hashing function */     
static void hash_global(uint64_t *input, const uint32_t length, uint64_t* hash)    
{                                   
    /* Do the padding - we weren't previously for some reason */            
	const uint32_t nBlocks = mdPadFunc(input, (const unsigned long)length);
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
			ROUND_STEP(i)   
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

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/

typedef struct {
	uint8_t data[64];
	uint32_t datalen;
	uint64_t bitlen;
	uint32_t state[8];
} CUDA_SHA256_CTX;

/****************************** MACROS ******************************/
#ifndef ROTLEFT
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#endif

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
__constant__ uint32_t k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
__device__  __forceinline__ void cuda_sha256_transform(CUDA_SHA256_CTX* ctx, const uint8_t data[])
{
	uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

__device__ void cuda_sha256_init(CUDA_SHA256_CTX* ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

__device__ void cuda_sha256_update(CUDA_SHA256_CTX* ctx, const uint8_t data[], size_t len)
{
	uint32_t i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			cuda_sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

__device__ void cuda_sha256_final(CUDA_SHA256_CTX* ctx, uint8_t hash[])
{
	uint32_t i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		cuda_sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	cuda_sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

void compute_sha256_hash(uint8_t* indata, uint32_t inlen, uint8_t* outdata)
{
	uint8_t in = 0;
	uint8_t out[32];
	CUDA_SHA256_CTX ctx;
	
	cuda_sha256_init(&ctx);
	cuda_sha256_update(&ctx, indata, inlen);
	cuda_sha256_final(&ctx, outdata);

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


	uint8_t hash[32];
	compute_sha256_hash(&raw[0], 78, hash);

	uint8_t hash2[32];
	compute_sha256_hash(hash, 32, hash2);

	if (memcmp(pub.verification, &hash2[0], 4) != 0) {
		printf("Public key verification mismatch!\n");
		printf("Computed verification: %s\n", toHex(&hash2[0], 4).c_str());
		printf("Provided verification: %s\n", toHex(pub.verification, 4).c_str());
		return;
	}
	
	printf("Public key accepted: %s\n", toHex(compressed_pub_key, 33).c_str());
	printf("BIP32 root xpub key details:\n");
	printf(" Version       : 0x%08x\n", bswap32(pub.version));
	printf(" Depth         : %d\n", pub.depth);
	printf(" Parent fpr    : 0x%08x\n", bswap32(pub.parent_fpr));
	printf(" Child num     : %u\n", bswap32(pub.child_num));
	printf(" Chain code    : %s\n", toHex(pub.chain_code, 32).c_str());
	printf(" Compressed key: %s\n", toHex(compressed_pub_key, 33).c_str());
	printf(" Verification  : %s\n", toHex(pub.verification, 4).c_str());

	uint64_t hashIn[16] = { 0 };
	uint64_t hashOut[8] = { 0 };


	const std::string message = "Wiadomosc testowa 3333 AAAA fffffffff";

	memcpy(hashIn, message.c_str(), message.size());


	hash_global(hashIn, message.size(), hashOut);
	printf("SHA512(0) = %016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx\n",
		swap64(hashOut[0]), swap64(hashOut[1]), swap64(hashOut[2]), swap64(hashOut[3]),
			swap64(hashOut[4]), swap64(hashOut[5]), swap64(hashOut[6]), swap64(hashOut[7]));
	
	printf("Started random compression testing ..\n");
	for (int64_t i = 1; i <= 10000; i++) {
		if (i % 1000000 == 0) {
			printf("Computed: %lldM\n", i / 1000000);
			fflush(stdout);
		}
		random_encoding_test();
	}




}