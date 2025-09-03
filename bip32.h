#pragma once

#include "create3.h"
#include <string>
// bip32 key search

#define PROFANITY_INVERSE_SIZE 200
#define RESULTS_ARRAY_SIZE 250000

struct bip32_search_data {
    cl_ulong4 public_key_x;
    cl_ulong4 public_key_y;
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
    int version;
    int depth;
    int parent_fpr;
    int child_num;
    int chain_code;
    cl_ulong4 public_key_x;
    cl_ulong4 public_key_y;
};



void update_bip32_key(mp_number const& x, mp_number const& y);
void bip32_update_search_prefix(pattern_descriptor pref);
void bip32_data_init(bip32_search_data* init_data);
void bip32_data_search(std::string public_key, pattern_descriptor descr, bip32_search_data* init_data);
void bip32_data_destroy(bip32_search_data* init_data);
void run_kernel_bip32_search(bip32_search_data* data);

salt bip32_generate_random_salt();


void cpu_update_bip32_key(mp_number const& x, mp_number const& y);
void cpu_bip32_update_search_prefix(pattern_descriptor pref);
void cpu_bip32_data_init(bip32_search_data* init_data);
void cpu_bip32_data_search(std::string public_key, pattern_descriptor descr, bip32_search_data* init_data);
void cpu_bip32_data_destroy(bip32_search_data* init_data);
void run_cpu_bip32_search(bip32_search_data* data);

salt cpu_bip32_generate_random_salt();