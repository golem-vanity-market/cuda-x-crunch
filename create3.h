#pragma once

#include "types.hpp"

#include <cstdint>

struct factory {
    uint8_t b[20];
};

struct search_result {
    uint8_t addr[20];
    uint32_t id;
    uint32_t round;
};

struct create3_search_data {
    char factory[41];
    char outputDir[1024];
    int rounds;
    int kernel_group_size;
    int kernel_groups;
    search_result * device_result;
    search_result * host_result;
    uint64_t total_compute;
    double time_started;
};

union salt {
    uint8_t b[32];
    uint32_t d[8];
    uint64_t q[4];
};

union ethhash {
    uint8_t b[200];
    uint32_t d[50];
    uint64_t q[25];
};

union ethaddress {
    uint8_t b[20];
    uint16_t w[10];
    uint32_t d[5];
};

struct pattern_descriptor {
    uint64_t search_prefix;
    uint64_t search_suffix;
    bool use_common;
    bool use_triples;
    bool use_letters;
};

void load_seed_to_device(salt *seed_data);
void load_factory_to_device(const char* factory);
void create3_data_init(create3_search_data* data);
void create3_data_destroy(create3_search_data* data);
void create3_search(create3_search_data* factory, pattern_descriptor descr);

void cpu_load_seed_to_device(salt *seed_data);
void cpu_load_factory_to_device(const char* factory);
void cpu_create3_data_init(create3_search_data* data);
void cpu_create3_data_destroy(create3_search_data* data);
void cpu_create3_search(create3_search_data* factory, pattern_descriptor descr);

#ifdef UNUSED_OLD_TESTS
void test_create3();
#endif

//cuda
void update_device_factory(const uint8_t* factory);
void update_device_salt(const salt* salt);
void run_kernel_create3_search(create3_search_data * data);
void update_search_prefix_contract(const uint64_t &pref);

//cpu
void cpu_update_device_factory(const uint8_t* factory);
void cpu_update_device_salt(const salt* salt);
void run_cpu_create3_search(create3_search_data * data);
void cpu_update_search_prefix_contract(const uint64_t &pref);