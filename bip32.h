#pragma once

#include "create3.h"
#include <string>
// bip32 key search

#define PROFANITY_INVERSE_SIZE 200
#define RESULTS_ARRAY_SIZE 250000

struct bip32_search_data {
    cl_ulong4 seed;
    int rounds;
    int kernel_group_size;
    int kernel_groups;
    search_result* device_result;
    search_result* host_result;
    point* device_precomp;
    uint64_t total_compute;
    double time_started;
};

#define MAX_COMPRESSED_KEY_SIZE 114

struct bip32_pub_key_compr {
    uint8_t data[MAX_COMPRESSED_KEY_SIZE];
	uint8_t size;
};

struct bip32_pub_key {
    uint32_t version;
    uint8_t depth;
    uint32_t parent_fpr;
    uint32_t child_num;
    uint8_t chain_code[32];
    uint8_t compressed_key[33];
	uint8_t verification[4];
};


/*
void update_bip32_key(mp_number const& x, mp_number const& y);
void bip32_update_search_prefix(pattern_descriptor pref);
void bip32_data_init(bip32_search_data* init_data);
void bip32_data_search(std::string public_key, pattern_descriptor descr, bip32_search_data* init_data);
void bip32_data_destroy(bip32_search_data* init_data);
void run_kernel_bip32_search(bip32_search_data* data);

salt bip32_generate_random_salt();
*/

void cpu_update_bip32_key(mp_number const& x, mp_number const& y);
void cpu_bip32_update_search_prefix(pattern_descriptor pref);
void cpu_bip32_data_init(bip32_search_data* init_data);
void cpu_bip32_data_search(std::string public_key, pattern_descriptor descr, bip32_search_data* init_data);
void cpu_bip32_data_destroy(bip32_search_data* init_data);
void run_cpu_bip32_search(bip32_search_data* data);

salt cpu_bip32_generate_random_salt();

void b58enc(uint8_t* b58, uint8_t* b58sz, const uint8_t* data);
bip32_pub_key_compr cpu_decode_bip32_compressed(bip32_pub_key_compr compr);
bool b58tobin(uint8_t* bin, const char* b58, size_t b58sz);
int compress_pubkey(uint8_t out33[33], point pub);
