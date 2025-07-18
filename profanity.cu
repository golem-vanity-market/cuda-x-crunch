/* Copyright (c) 1993-2015, NVIDIA CORPORATION. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of NVIDIA CORPORATION nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "create3.h"
#include "private_key.h"
#include "help.hpp"
#include "utils.hpp"
#include "ArgParser.hpp"
#include "debug_utils.hpp"
#include <stdlib.h>
#include <stdio.h>
#include "precomp.hpp"
#include <string>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <csignal>
#include "Logger.hpp"
#include "version.h"
#include <chrono>
#include <thread>

bool g_exiting = false;
// Signal handler function
void signalHandler(int signal) {
	if (signal == SIGINT) {
		std::cout << "\nCtrl + C detected. Exiting gracefully..." << std::endl;
		g_exiting = true;
	}
	if (signal == SIGTERM) {
        std::cout << "\nTermination signal detected. Exiting gracefully..." << std::endl;
        g_exiting = true;
    }
    if (signal == SIGABRT) {
        std::cout << "\nAbort signal detected. Exiting gracefully..." << std::endl;
        g_exiting = true;
    }
}


static std::string::size_type fromHex(char c) {
	if (c >= 'A' && c <= 'F') {
		c += 'a' - 'A';
	}

	const std::string hex = "0123456789abcdef";
	const std::string::size_type ret = hex.find(c);
	return ret;
}

uint32_t htonl(uint32_t x) {
    unsigned char *s = (unsigned char *)&x;
    return (uint32_t)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);
}

#ifndef htonll
#define htonll(x) ((((uint64_t)htonl(x)) << 32) | htonl((x) >> 32))
#endif
static cl_ulong4 fromHexCLUlong(const std::string & strHex) {
	uint8_t data[32];
	std::fill(data, data + sizeof(data), 0);

	auto index = 0;
	for(size_t i = 0; i < strHex.size(); i += 2) {
		const auto indexHi = fromHex(strHex[i]);
		const auto indexLo = i + 1 < strHex.size() ? fromHex(strHex[i+1]) : std::string::npos;

		const auto valHi = (indexHi == std::string::npos) ? 0 : indexHi << 4;
		const auto valLo = (indexLo == std::string::npos) ? 0 : indexLo;

		data[index] = valHi | valLo;
		++index;
	}

	cl_ulong4 res = {
		.s = {
			htonll(*(uint64_t *)(data + 24)),
			htonll(*(uint64_t *)(data + 16)),
			htonll(*(uint64_t *)(data + 8)),
			htonll(*(uint64_t *)(data + 0)),
		}
	};
	return res;
}

std::map<std::string, std::vector<std::string>> parsePattern(const std::string& pattern) {
    std::map<std::string, std::vector<std::string>> result;
    std::stringstream ss(pattern);
    std::string pair;

    // Split by ';' into key=value pairs
    while (std::getline(ss, pair, ';')) {
        size_t eqPos = pair.find('=');
        if (eqPos != std::string::npos) {
            std::string key = pair.substr(0, eqPos);
            std::string valuesStr = pair.substr(eqPos + 1);

            std::vector<std::string> values;
            std::stringstream valueStream(valuesStr);
            std::string val;

            // Split values by ','
            while (std::getline(valueStream, val, ',')) {
                if (!val.empty())
                    values.push_back(val);
            }

            result[key] = values;
        }
    }

    return result;
}

int main(int argc, char ** argv)
{
	std::signal(SIGINT, signalHandler);

    if (sizeof(mp_number) != sizeof(cl_ulong4)) {
        LOG_ERROR("mp_number size is not equal to mp_limb_t size");
        return 1;
    }
    if (sizeof(mp_number) != 32) {
        LOG_ERROR("mp_number size is not equal to 32 bytes");
        return 1;
    }

    ArgParser argp(argc, argv);
    bool bHelp = false;
    double benchmarkLimitTime = 0.0;
    double nicenessParameter = 0.0;
    uint64_t additionalPrefix = 0;
    uint64_t additionalSuffix = 0;

    int benchmarkLimitLoops = 0;
    bool bNoRun = false;
    bool bDebug = false;
    bool bErrorsOnly = false;
    bool bVersion = false;
    uint64_t uSeed = 0;
    bool bUseCPU = false;

    int kernelSize = 128; //256 sometimes give a bit better results, but on older cards it slows a lot
    int groups = 1000;
    int rounds = 1000;
    int device_id = 0;
    std::string publicKey = "";
    std::string strOutputDirectory = "";
    std::string factoryAddr = "0x9E3F8eaE49E442A323EF2094f277Bf62752E6995";
    std::string searchPattern = "";

    argp.addSwitch('c', "cpu", bUseCPU);
    argp.addSwitch('b', "benchmark", benchmarkLimitTime);
    argp.addSwitch('d', "debug", bDebug);
    argp.addSwitch('e', "errors", bErrorsOnly);
    argp.addSwitch('f', "factory", factoryAddr);
    argp.addSwitch('i', "device", device_id);
    argp.addSwitch('g', "groups", groups);
    argp.addSwitch('h', "help", bHelp);
    argp.addSwitch('k', "kernel", kernelSize);
    argp.addSwitch('l', "loops", benchmarkLimitLoops);
    argp.addSwitch('n', "no_run", bNoRun);
    argp.addSwitch('o', "output", strOutputDirectory);
    argp.addSwitch('p', "pattern", searchPattern);
    argp.addSwitch('r', "rounds", rounds);
    argp.addSwitch('s', "seed", uSeed);
    argp.addSwitch('u', "niceness", nicenessParameter);
    argp.addSwitch('v', "version", bVersion);
    argp.addSwitch('z', "public", publicKey);




    if (!argp.parse()) {
        std::cout << "error: bad arguments, -h for help" << std::endl;
        return 1;
    }

    auto parsed = parsePattern(searchPattern);
    std::cout << "Parsed search pattern: " << searchPattern << std::endl;


    bool useNoDefaults = true;
    bool useCommon = false;
    bool useLetters = false;
    bool useTriples = false;
    for (const auto& [key, values] : parsed) {
        std::cout << key << ": ";
        for (const auto& v : values) {
            std::cout << v << " ";
        }
        std::cout << std::endl;

        if (key == "no_default" && values.size() == 1 && values[0] == "1") {
            LOG_INFO("Not processing default search pattern");
            useNoDefaults = true;
        }
        if (key == "prefix" && values.size() == 1 && !values[0].empty()) {
            try {
                additionalPrefix = std::stoull(values[0], nullptr, 16);
                LOG_INFO("Using additional prefix: %llu", additionalPrefix);
            } catch (const std::exception& e) {
                LOG_ERROR("Invalid prefix value: %s", e.what());
                return 1;
            }
        }
        if (key == "suffix" && values.size() == 1 && !values[0].empty()) {
            try {
                additionalSuffix = std::stoull(values[0], nullptr, 16);
                LOG_INFO("Using additional suffix: %llu", additionalSuffix);
            } catch (const std::exception& e) {
                LOG_ERROR("Invalid suffix value: %s", e.what());
                return 1;
            }
        }
        if (key == "letters" && values.size() == 1 && values[0] == "1") {
            LOG_INFO("Using letters in search pattern");
            useLetters = true;
        }
        if (key == "triples" && values.size() == 1 && values[0] == "1") {
            LOG_INFO("Using triples in search pattern");
            useTriples = true;
        }
        if (key == "common" && values.size() == 1 && values[0] == "1") {
            LOG_INFO("Using common search pattern");
            useCommon = true;
        }
    }
    if (!useNoDefaults) {
        LOG_INFO("Using all search pattern by default");
        useCommon = true;
        useLetters = true;
        useTriples = true;
    }
    pattern_descriptor descr = { 0 };
    descr.use_common = useCommon;
    descr.use_letters = useLetters;
    descr.use_triples = useTriples;
    descr.search_prefix = additionalPrefix;
    descr.search_suffix = additionalSuffix;

    if (uSeed) {
        LOG_WARNING("Using custom seed %llx so results will be the same and not random", uSeed);
        init_random(uSeed);
    }
    if (bVersion) {
        std::cout << g_strVersion;
        return 0;
    }
    bool lookForPrivateKeys = false;
    if (publicKey.size() > 0) {

        lookForPrivateKeys = true;
        LOG_INFO("Public key given, searching for private keys instead of create3: %s", publicKey.c_str());
        publicKey = normalize_public_key(publicKey);
        if (publicKey.empty()) {
            std::cout << "error: bad public key" << std::endl;
            return 1;
        }
    }
    if (!bUseCPU) {
        int deviceCount;
        cudaGetDeviceCount(&deviceCount);
        if (device_id >= deviceCount) {
            std::cerr << "error: device id is out of range" << std::endl;
            return 1;
        }
        cudaSetDevice(device_id);

        for (int device = 0; device < deviceCount; ++device) {
            cudaDeviceProp prop;
            cudaGetDeviceProperties(&prop, device);

            LOG_INFO("Device %d: %s", device, prop.name);
            LOG_INFO("  Compute capability: %d.%d", prop.major, prop.minor);
            //number of cuda cores
            LOG_INFO("  CUDA Processors: %d", prop.multiProcessorCount);
            // Calculate the number of CUDA cores
            int cudaCoresPerSM = 0;
            switch (prop.major) {
                case 2: // Fermi
                    cudaCoresPerSM = prop.minor == 0 ? 32 : 48;
                    break;
                case 3: // Kepler
                    cudaCoresPerSM = 192;
                    break;
                case 5: // Maxwell
                    cudaCoresPerSM = 128;
                    break;
                case 6: // Pascal
                    if (prop.minor == 0) cudaCoresPerSM = 64;
                    else if (prop.minor == 1) cudaCoresPerSM = 128;
                    break;
                case 7: // Volta and Turing
                    if (prop.minor == 0) cudaCoresPerSM = 64;  // Volta
                    else if (prop.minor == 5) cudaCoresPerSM = 64;  // Turing
                    break;
                case 8: // Ampere
                    cudaCoresPerSM = 128;
                    break;
                case 9: // Ampere
                    cudaCoresPerSM = 128;
                    break;
                default:
                    LOG_WARNING("Unknown device - assuming 128 CUDA cores per SM");
                    cudaCoresPerSM = 128;
            }
            LOG_INFO("  CUDA Cores: %d", cudaCoresPerSM * prop.multiProcessorCount);
        }
    }


    if (bDebug && bErrorsOnly) {
        std::cout << "error: can't use -d and -e together" << std::endl;
        return 1;
    }
    if (bDebug) {
        Logger::getInstance().setLevel(Logger::Level::DEBUG);
    }
    if (bErrorsOnly) {
        Logger::getInstance().setLevel(Logger::Level::ERROR);
    }

    if (bHelp) {
        std::cout << "Version: " << g_strVersion << "\n" << g_strHelp << std::endl;
        return 0;
    }
    if (benchmarkLimitLoops > 0 || benchmarkLimitTime > 0) {
        LOG_WARNING("Benchmark mode enabled");
    }
    if (bNoRun) {
        return 0;
    }
    if (!lookForPrivateKeys) {
        //normalize address
        factoryAddr = normalize_ethereum_address(factoryAddr);
        if (factoryAddr.empty()) {
            std::cout << "error: bad factory address" << std::endl;
            return 1;
        }
        if (bUseCPU) {
            create3_search_data cpu_init_data = { 0 };
            memcpy(cpu_init_data.factory, factoryAddr.c_str(), 40);
            if (strOutputDirectory.size() > 1000) {
                std::cout << "error: output directory too long" << std::endl;
                return 1;
            }
            memcpy(cpu_init_data.outputDir, strOutputDirectory.c_str(), strOutputDirectory.size());
            cpu_init_data.rounds = rounds;
            cpu_init_data.kernel_group_size = kernelSize;
            cpu_init_data.kernel_groups = groups;

            LOG_INFO("Initializing with params:");
            LOG_INFO("Factory address: 0x%s", cpu_init_data.factory);
            LOG_INFO("Output directory: %s", cpu_init_data.outputDir);
            LOG_INFO("Kernel size: %d", cpu_init_data.kernel_group_size);
            LOG_INFO("Groups: %d", cpu_init_data.kernel_groups);

            cpu_create3_data_init(&cpu_init_data);
            LOG_INFO("Successfully initialised [CPU]: Hashes at one run %.2f MH", ((double)cpu_init_data.kernel_groups * cpu_init_data.kernel_group_size * cpu_init_data.rounds) / 1000000.0);

            double start = get_app_time_sec();
            uint64_t loop_no = 0;
            while(true) {
                if (g_exiting) {
                    break;
                }
                double loop_start = get_app_time_sec();
                cpu_create3_search(&cpu_init_data, descr);
                double end = get_app_time_sec();

                if ((benchmarkLimitTime > 0 && (end - start) > benchmarkLimitTime)
                    || (benchmarkLimitLoops > 0 && loop_no + 1 >= benchmarkLimitLoops)) {
                    break;
                }
                if (nicenessParameter > 0) {
                    double extra_wait_time = nicenessParameter * (end - loop_start);
                    if (extra_wait_time > 0) {
                        LOG_INFO("Sleeping for %.2f seconds", extra_wait_time);
                        std::this_thread::sleep_for(std::chrono::microseconds((uint64_t)(extra_wait_time * 1000000)));
                    }
                }
                loop_no += 1;
            }
            cpu_create3_data_destroy(&cpu_init_data);
            return 0;
        } else {
            create3_search_data init_data = { 0 };
            memcpy(init_data.factory, factoryAddr.c_str(), 40);
            if (strOutputDirectory.size() > 1000) {
                std::cout << "error: output directory too long" << std::endl;
                return 1;
            }
            memcpy(init_data.outputDir, strOutputDirectory.c_str(), strOutputDirectory.size());
            init_data.rounds = rounds;
            init_data.kernel_group_size = kernelSize;
            init_data.kernel_groups = groups;

            LOG_INFO("Initializing with params:");
            LOG_INFO("Factory address: 0x%s", init_data.factory);
            LOG_INFO("Output directory: %s", init_data.outputDir);
            LOG_INFO("Kernel size: %d", init_data.kernel_group_size);
            LOG_INFO("Groups: %d", init_data.kernel_groups);

            create3_data_init(&init_data);
            LOG_INFO("Successfully initialised: Hashes at one run %.2f MH", ((double)init_data.kernel_groups * init_data.kernel_group_size * init_data.rounds) / 1000000.0);

            double start = get_app_time_sec();
            uint64_t loop_no = 0;
            while(true) {
                if (g_exiting) {
                    break;
                }
                double loop_start = get_app_time_sec();
                create3_search(&init_data, descr);
                double end = get_app_time_sec();

                if ((benchmarkLimitTime > 0 && (end - start) > benchmarkLimitTime)
                    || (benchmarkLimitLoops > 0 && loop_no + 1 >= benchmarkLimitLoops)) {
                    break;
                }
                if (nicenessParameter > 0) {
                    double extra_wait_time = nicenessParameter * (end - loop_start);
                    if (extra_wait_time > 0) {
                        LOG_INFO("Sleeping for %.2f seconds", extra_wait_time);
                        std::this_thread::sleep_for(std::chrono::microseconds((uint64_t)(extra_wait_time * 1000000)));
                    }
                }
                loop_no += 1;
            }
            create3_data_destroy(&init_data);
            return 0;
        }
    } else {
        if (bUseCPU) {
            LOG_INFO("Searching for private keys [CPU] for public key: %s", publicKey.c_str());
            //load public key into variables
            if (publicKey.size() != 128) {
                std::cout << "error: bad public key" << std::endl;
                return 1;
            }
            cl_ulong4 clSeedX = fromHexCLUlong(publicKey.substr(0, 64));
            cl_ulong4 clSeedY = fromHexCLUlong(publicKey.substr(64, 64));

            LOG_INFO("Public key SeedX: %llu %llu %llu %llu\n", clSeedX.s0, clSeedX.s1, clSeedX.s2, clSeedX.s3);
            LOG_INFO("Public key SeedY: %llu %llu %llu %llu\n", clSeedY.s0, clSeedY.s1, clSeedY.s2, clSeedY.s3);


            private_search_data cpu_init_data;
            cpu_init_data.rounds = rounds;
            cpu_init_data.kernel_group_size = kernelSize;
            cpu_init_data.kernel_groups = groups;
            cpu_init_data.public_key_x = clSeedX;
            cpu_init_data.public_key_y = clSeedY;

            memset(&cpu_init_data.seed, 0, sizeof(cpu_init_data.seed));

            //LOG_INFO("Factory address: 0x%s", init_data.factory);
            //LOG_INFO("Output directory: %s", init_data.outputDir);
            LOG_INFO("Kernel size: %d", cpu_init_data.kernel_group_size);
            LOG_INFO("Groups: %d", cpu_init_data.kernel_groups);

            cpu_private_data_init(&cpu_init_data);

            double start = get_app_time_sec();
            uint64_t loop_no = 0;
            while(true) {
                if (g_exiting) {
                    break;
                }
                cpu_private_data_search(publicKey, descr, &cpu_init_data);
                double end = get_app_time_sec();
                if ((benchmarkLimitTime > 0 && (end - start) > benchmarkLimitTime)
                    || (benchmarkLimitLoops > 0 && loop_no + 1 >= benchmarkLimitLoops)) {
                    break;
                }
                loop_no += 1;
            }

            cpu_private_data_destroy(&cpu_init_data);
            return 0;
        } else {
            LOG_INFO("Searching for private keys for public key: %s", publicKey.c_str());
            //load public key into variables
            if (publicKey.size() != 128) {
                std::cout << "error: bad public key" << std::endl;
                return 1;
            }
            cl_ulong4 clSeedX = fromHexCLUlong(publicKey.substr(0, 64));
            cl_ulong4 clSeedY = fromHexCLUlong(publicKey.substr(64, 64));

            LOG_INFO("Public key SeedX: %llu %llu %llu %llu\n", clSeedX.s0, clSeedX.s1, clSeedX.s2, clSeedX.s3);
            LOG_INFO("Public key SeedY: %llu %llu %llu %llu\n", clSeedY.s0, clSeedY.s1, clSeedY.s2, clSeedY.s3);


            private_search_data init_data;
            init_data.rounds = rounds;
            init_data.kernel_group_size = kernelSize;
            init_data.kernel_groups = groups;
            init_data.public_key_x = clSeedX;
            init_data.public_key_y = clSeedY;

            memset(&init_data.seed, 0, sizeof(init_data.seed));

            //LOG_INFO("Factory address: 0x%s", init_data.factory);
            //LOG_INFO("Output directory: %s", init_data.outputDir);
            LOG_INFO("Kernel size: %d", init_data.kernel_group_size);
            LOG_INFO("Groups: %d", init_data.kernel_groups);

            private_data_init(&init_data);

            double start = get_app_time_sec();
            uint64_t loop_no = 0;
            while(true) {
                if (g_exiting) {
                    break;
                }
                private_data_search(publicKey, descr, &init_data);
                double end = get_app_time_sec();
                if ((benchmarkLimitTime > 0 && (end - start) > benchmarkLimitTime)
                    || (benchmarkLimitLoops > 0 && loop_no + 1 >= benchmarkLimitLoops)) {
                    break;
                }
                loop_no += 1;
            }

            private_data_destroy(&init_data);
            return 0;
        }
    }

}
