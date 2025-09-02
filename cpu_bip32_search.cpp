#include "version.h"
#include "cpu_bip32.h"
#include "utils.hpp"
#include "Logger.hpp"
#include <iostream>
#include <cuda_runtime_api.h>
#include <string>
#include <filesystem>
#include <cstring>
#include "precomp.hpp"

cl_ulong4 createRandomSeed() {
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
void bip32_data_init(bip32_search_data *init_data)
{
    init_data->total_compute = 0;
    init_data->time_started = get_app_time_sec();

    int data_count = init_data->kernel_group_size * init_data->kernel_groups;
    cudaMalloc((void **)&init_data->device_result, sizeof(search_result) * RESULTS_ARRAY_SIZE);
    cudaMalloc((void **)&init_data->device_precomp, sizeof(point) * 8160);
    cudaMemcpy(init_data->device_precomp, g_precomp, sizeof(point) * 8160, cudaMemcpyHostToDevice);

    init_data->host_result = new search_result[RESULTS_ARRAY_SIZE]();

    memset(init_data->host_result, 0, sizeof(search_result) * RESULTS_ARRAY_SIZE);
    CHECK_CUDA_ERROR("Allocate memory on CUDA");
}

void bip32_data_destroy(bip32_search_data *init_data)
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
void bip32_data_search(std::string public_key, pattern_descriptor descr, bip32_search_data *init_data)
{
    double start = get_app_time_sec();

    const int kernel_group_size = init_data->kernel_group_size;
    const uint64_t data_count = init_data->kernel_groups * kernel_group_size;

    cl_ulong4 randomSalt = createRandomSeed();
    CHECK_CUDA_ERROR("Failed to load salt data");

    init_data->seed = randomSalt;
    cudaMemset(init_data->device_result, 0, sizeof(search_result) * RESULTS_ARRAY_SIZE);

    LOG_DEBUG("Copying data to device %d MB...", (uint32_t)(sizeof(search_result) * data_count / 1024 / 1024));
    update_public_key(init_data->public_key_x.mpn, init_data->public_key_y.mpn);
    update_search_prefix(descr);

    LOG_DEBUG("Running keccak kernel...");
    run_kernel_bip32_search(init_data);
    CHECK_CUDA_ERROR("Failed to run kernel");

    LOG_DEBUG("Copying data back...");
    search_result* f = init_data->host_result;
    cudaMemcpy(f, init_data->device_result, RESULTS_ARRAY_SIZE * sizeof(search_result), cudaMemcpyDeviceToHost);
    cudaDeviceSynchronize();
    CHECK_CUDA_ERROR("Failed to run kernel or copy memory");

    double end = get_app_time_sec();

    char hexAddr[43] = { 0 };
    for (int n = 0; n < RESULTS_ARRAY_SIZE; n++) {
        if (f[n].round != 0) {
            printResult(public_key, init_data->seed, f[n].round, f[n], init_data);
            //salt newSalt;
            //newSalt.q[0] = randomSalt.q[0];
            /*newSalt.q[1] = randomSalt.q[1];
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
            printf("0x%s,%s,%s_%lld\n", salt, hexAddr.c_str(), "cuda_miner_v0.1.0", init_data->total_compute / 1000 / 1000 / 1000);
*/
//printResult(init_data->seed, 1, *f)
//            std::string outputDir = init_data->outputDir;
  //          if (outputDir == "") {
                continue;
    //        }
            // Ensure output directory exists
/*
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

            fprintf(out_file, "0x%s,%s,0x%s,%s_%lld", salt, hexAddr.c_str(), init_data->factory, "cuda_miner_v0.1.0", init_data->total_compute / 1000 / 1000 / 1000);

            fclose(out_file);*/

        }
    }


    init_data->total_compute += init_data->rounds * data_count * PROFANITY_INVERSE_SIZE;
    LOG_DEBUG("Addresses computed: %lld", init_data->total_compute);
    LOG_DEBUG("Compute MH: %f MH/s", (double)init_data->total_compute / (end - start) / 1000 / 1000);
    LOG_INFO("Total compute %.2f GH - %.2f MH/s", (double)init_data->total_compute / 1000. / 1000. / 1000., (double)init_data->total_compute / (end - init_data->time_started) / 1000 / 1000);

}