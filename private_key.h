#pragma once

#include "create3.h"
#include <string>
// private key search

#define PROFANITY_INVERSE_SIZE 200
#define RESULTS_ARRAY_SIZE 250000

struct private_search_data {
    cl_ulong4 public_key_x;
    cl_ulong4 public_key_y;
    cl_ulong4 seed;
    int rounds;
    int kernel_group_size;
    int kernel_groups;
    search_result * device_result;
    search_result * host_result;
    point * device_precomp;
    uint64_t total_compute;
    double time_started;
};

void update_public_key(mp_number const& x, mp_number const& y);
void update_search_prefix(const uint64_t &pref);
void private_data_init(private_search_data *init_data);
void private_data_search(std::string public_key, pattern_descriptor descr, private_search_data *init_data);
void private_data_destroy(private_search_data *init_data);
void run_kernel_private_search(private_search_data * data);

salt generate_random_salt();


void cpu_update_public_key(mp_number const& x, mp_number const& y);
void cpu_update_search_prefix(const uint64_t &pref);
void cpu_private_data_init(private_search_data *init_data);
void cpu_private_data_search(std::string public_key, pattern_descriptor descr, private_search_data *init_data);
void cpu_private_data_destroy(private_search_data *init_data);
void run_cpu_private_search(private_search_data * data);

salt cpu_generate_random_salt();

