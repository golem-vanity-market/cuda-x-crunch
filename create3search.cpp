#include "version.h"
#include "create3.h"
#include "utils.hpp"
#include "Logger.hpp"
#include <iostream>
#include <cuda_runtime_api.h>
#include <string>
#include <filesystem>
#include <cstring>

void create3_data_init(create3_search_data *init_data)
{
    init_data->total_compute = 0;
    init_data->time_started = get_app_time_sec();

    int data_count = init_data->kernel_group_size * init_data->kernel_groups;
    cudaMalloc((void **)&init_data->device_result, sizeof(search_result) * data_count);
    init_data->host_result = new search_result[data_count]();
    memset(init_data->host_result, 0, sizeof(search_result) * data_count);
    CHECK_CUDA_ERROR("Allocate memory on CUDA");
}

void create3_data_destroy(create3_search_data *init_data)
{
    delete[] init_data->host_result;
    cudaFree(init_data->device_result);
}

salt generate_random_salt() {
    salt randomSalt;
    randomSalt.q[0] = get_next_random();
    randomSalt.q[1] = get_next_random();
    randomSalt.q[2] = get_next_random();
    randomSalt.q[3] = get_next_random();
    return randomSalt;
}

void create3_search(create3_search_data *init_data, pattern_descriptor descr)
{
    double start = get_app_time_sec();

    const int kernel_group_size = init_data->kernel_group_size;
    const uint64_t data_count = init_data->kernel_groups * kernel_group_size;

    load_factory_to_device(init_data->factory);
    update_search_prefix_contract(descr);
    CHECK_CUDA_ERROR("Failed to load factory data");

    salt randomSalt = generate_random_salt();
    update_device_salt(&randomSalt);
    CHECK_CUDA_ERROR("Failed to load salt data");

    cudaMemset(init_data->device_result, 0, sizeof(search_result) * data_count);

    LOG_DEBUG("Copying data to device %d MB...", (uint32_t)(sizeof(search_result) * data_count / 1024 / 1024));

    LOG_DEBUG("Running keccak kernel...");
    run_kernel_create3_search(init_data);
    CHECK_CUDA_ERROR("Failed to run kernel");

    LOG_DEBUG("Copying data back...");
    search_result* f = init_data->host_result;
    cudaMemcpy(f, init_data->device_result, data_count * sizeof(search_result), cudaMemcpyDeviceToHost);
    cudaDeviceSynchronize();
    CHECK_CUDA_ERROR("Failed to run kernel or copy memory");

    char hexAddr[43] = { 0 };
    for (int n = 0; n < data_count; n++) {
        if (f[n].round != 0) {
            salt newSalt;
            newSalt.q[0] = randomSalt.q[0];
            newSalt.q[1] = randomSalt.q[1];
            newSalt.q[2] = randomSalt.q[2];
            newSalt.q[3] = randomSalt.q[3];
            newSalt.d[0] = f[n].id;
            newSalt.d[1] = f[n].round;
            std::string hexAddr = bytes_to_ethereum_address(f[n].addr);

            char salt[65] = {0};
            for (int i = 0; i < 32; i++) {
                sprintf(&salt[(i) * 2], "%02x", newSalt.b[i]);
            }
            salt[64] = 0;
            printf("0x%s,%s,0x%s,%s_%lu\n", salt, hexAddr.c_str(), init_data->factory, g_strVersion.c_str(), (unsigned long)(init_data->total_compute / 1000 / 1000 / 1000));

            std::string outputDir = init_data->outputDir;
            if (outputDir == "") {
                continue;
            }
            // Ensure output directory exists

            std::filesystem::path outDirPath(outputDir);
            if (!std::filesystem::exists(outDirPath)) {
                std::filesystem::create_directories(outDirPath);
            }

            std::string fileName = init_data->outputDir + std::string("/addr_") + hexAddr + ".csv";

            FILE *out_file = fopen(fileName.c_str(), "w");
            if (out_file == NULL) {
				LOG_ERROR("Error opening file %s!\n", fileName.c_str());
				exit(1);
			}

            fprintf(out_file, "0x%s,%s,0x%s,%s_%lu", salt, hexAddr.c_str(), init_data->factory, "cuda_miner_v0.1.0", (unsigned long)(init_data->total_compute / 1000 / 1000 / 1000));

            fclose(out_file);

        }
    }

    double end = get_app_time_sec();

    init_data->total_compute += init_data->rounds * data_count;
    LOG_DEBUG("Addresses computed: %lld", init_data->rounds * data_count);
    LOG_DEBUG("Compute MH: %f MH/s", (double)init_data->rounds * data_count / (end - start) / 1000 / 1000);
    LOG_INFO("Total compute %.2f GH - %.2f MH/s", (double)init_data->total_compute / 1000. / 1000. / 1000., (double)init_data->total_compute / (end - init_data->time_started) / 1000 / 1000);
}

void load_factory_to_device(const char* factory) {
    uint8_t factory_bytes[20];
    for (int i = 0; i < 20; i++) {
        unsigned int byte;
        sscanf(factory + i * 2, "%2x", &byte); // Parse 2-character hex string
        factory_bytes[i] = (uint8_t)(byte);
    }
    update_device_factory(factory_bytes);
}

