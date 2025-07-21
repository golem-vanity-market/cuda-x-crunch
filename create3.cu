#include "create3.h"
#include "scorer.cuh"

#define ROL(X, S) (((X) << S) | ((X) >> (64 - S)))

#define THETA_(M, N, O) t = b[M] ^ ROL(b[N], 1); \
a[O + 0] = a[O + 0] ^ t; a[O + 5] = a[O + 5] ^ t; a[O + 10] = a[O + 10] ^ t; \
a[O + 15] = a[O + 15] ^ t; a[O + 20] = a[O + 20] ^ t;

#define THETA() \
b[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]; \
b[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]; \
b[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]; \
b[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]; \
b[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]; \
THETA_(4, 1, 0); THETA_(0, 2, 1); THETA_(1, 3, 2); THETA_(2, 4, 3); THETA_(3, 0, 4);

#define RHO_PI_(M, N) t = b[0]; b[0] = a[M]; a[M] = ROL(t, N);

#define RHO_PI() t = a[1]; b[0] = a[10]; a[10] = ROL(t, 1); \
RHO_PI_(7, 3); RHO_PI_(11, 6); RHO_PI_(17, 10); RHO_PI_(18, 15); RHO_PI_(3, 21); RHO_PI_(5, 28); \
RHO_PI_(16, 36); RHO_PI_(8, 45); RHO_PI_(21, 55); RHO_PI_(24, 2); RHO_PI_(4, 14); RHO_PI_(15, 27); \
RHO_PI_(23, 41); RHO_PI_(19, 56); RHO_PI_(13, 8); RHO_PI_(12, 25); RHO_PI_(2, 43); RHO_PI_(20, 62); \
RHO_PI_(14, 18); RHO_PI_(22, 39); RHO_PI_(9, 61); RHO_PI_(6, 20); RHO_PI_(1, 44);

#define CHI_(N) \
b[0] = a[N + 0]; b[1] = a[N + 1]; b[2] = a[N + 2]; b[3] = a[N + 3]; b[4] = a[N + 4]; \
a[N + 0] = b[0] ^ ((~b[1]) & b[2]); \
a[N + 1] = b[1] ^ ((~b[2]) & b[3]); \
a[N + 2] = b[2] ^ ((~b[3]) & b[4]); \
a[N + 3] = b[3] ^ ((~b[4]) & b[0]); \
a[N + 4] = b[4] ^ ((~b[0]) & b[1]);

#define CHI() CHI_(0); CHI_(5); CHI_(10); CHI_(15); CHI_(20);

#define IOTA(X) a[0] = a[0] ^ X;

#define ITER(X) THETA(); RHO_PI(); CHI(); IOTA(X);

#define ITERS() \
ITER(0x0000000000000001); ITER(0x0000000000008082); \
ITER(0x800000000000808a); ITER(0x8000000080008000); \
ITER(0x000000000000808b); ITER(0x0000000080000001); \
ITER(0x8000000080008081); ITER(0x8000000000008009); \
ITER(0x000000000000008a); ITER(0x0000000000000088); \
ITER(0x0000000080008009); ITER(0x000000008000000a); \
ITER(0x000000008000808b); ITER(0x800000000000008b); \
ITER(0x8000000000008089); ITER(0x8000000000008003); \
ITER(0x8000000000008002); ITER(0x8000000000000080); \
ITER(0x000000000000800a); ITER(0x800000008000000a); \
ITER(0x8000000080008081); ITER(0x8000000000008080); \
ITER(0x0000000080000001); ITER(0x8000000080008008);

__device__ void compute_keccak_full(ethhash * hash) {
  uint64_t b[5];
  uint64_t t;
  uint64_t *a = (uint64_t *)hash;
    ITERS();
}
__device__ void partial_keccakf(uint64_t *a)
{
  uint64_t b[5];
  uint64_t t;
  ITER(0x0000000000000001); ITER(0x0000000000008082);
  ITER(0x800000000000808a); ITER(0x8000000080008000);
  ITER(0x000000000000808b); ITER(0x0000000080000001);
  ITER(0x8000000080008081); ITER(0x8000000000008009);
  ITER(0x000000000000008a); ITER(0x0000000000000088);
  ITER(0x0000000080008009); ITER(0x000000008000000a);
  ITER(0x000000008000808b); ITER(0x800000000000008b);
  ITER(0x8000000000008089); ITER(0x8000000000008003);
  ITER(0x8000000000008002); ITER(0x8000000000000080);
  ITER(0x000000000000800a); ITER(0x800000008000000a);
  ITER(0x8000000080008081); ITER(0x8000000000008080);
  ITER(0x0000000080000001);

  // iteration 24 (partial)
#define o ((uint32_t *)(a))
  // Theta (partial)
  b[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
  b[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
  b[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
  b[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
  b[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

  a[0] ^= b[4] ^ ROL(b[1], 1u);
  a[6] ^= b[0] ^ ROL(b[2], 1u);
  a[12] ^= b[1] ^ ROL(b[3], 1u);
  a[18] ^= b[2] ^ ROL(b[4], 1u);
  a[24] ^= b[3] ^ ROL(b[0], 1u);

  // Rho Pi (partial)
  o[3] = (o[13] >> 20) | (o[12] << 12);
  a[2] = ROL(a[12], 43);
  a[3] = ROL(a[18], 21);
  a[4] = ROL(a[24], 14);

  // Chi (partial)
  o[3] ^= ((~o[5]) & o[7]);
  o[4] ^= ((~o[6]) & o[8]);
  o[5] ^= ((~o[7]) & o[9]);
  o[6] ^= ((~o[8]) & o[0]);
  o[7] ^= ((~o[9]) & o[1]);
#undef o
}

__constant__ uint8_t g_factory[20] = {0};
__constant__ salt g_randomSalt = {0};

void update_device_factory(const uint8_t* factory)
{
    cudaMemcpyToSymbol(g_factory, factory, 20);
}

void update_device_salt(const salt* seed_data)
{
    cudaMemcpyToSymbol(g_randomSalt, seed_data, sizeof(salt));
}

#ifdef UNUSED_OLD_TESTS
__global__ void create3_host(factory* const factory_data, salt* const salt_data, int rounds)
{
	const size_t id = (threadIdx.x + blockIdx.x * blockDim.x);

    for (int round = 0; round < rounds; round++) {
        ethhash first;

        first.b[0] = 0xff;
        for (int i = 0; i < 20; i++) {
            first.b[i + 1] = g_factory[i];
        }
        for (int i = 0; i < 32; i++) {
            first.b[i + 21] = salt_data[id].b[i];
        }

        //0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f

        first.b[53] = 0x21;
        first.b[54] = 0xc3;
        first.b[55] = 0x5d;
        first.b[56] = 0xbe;
        first.b[57] = 0x1b;
        first.b[58] = 0x34;
        first.b[59] = 0x4a;
        first.b[60] = 0x24;
        first.b[61] = 0x88;
        first.b[62] = 0xcf;
        first.b[63] = 0x33;
        first.b[64] = 0x21;
        first.b[65] = 0xd6;
        first.b[66] = 0xce;
        first.b[67] = 0x54;
        first.b[68] = 0x2f;
        first.b[69] = 0x8e;
        first.b[70] = 0x9f;
        first.b[71] = 0x30;
        first.b[72] = 0x55;
        first.b[73] = 0x44;
        first.b[74] = 0xff;
        first.b[75] = 0x09;
        first.b[76] = 0xe4;
        first.b[77] = 0x99;
        first.b[78] = 0x3a;
        first.b[79] = 0x62;
        first.b[80] = 0x31;
        first.b[81] = 0x9a;
        first.b[82] = 0x49;
        first.b[83] = 0x7c;
        first.b[84] = 0x1f;
        first.b[85] = 0x01;
        //total length 85
        for (int i = 86; i < 135; ++i)
            first.b[i] = 0;

        first.b[135] = 0x80;
        for (int i = 136; i < 200; ++i)
            first.b[i] = 0;
        compute_keccak_full(&first);

        first.b[0] = 0xd6;
        first.b[1] = 0x94;
        for (int i = 12; i < 32; i++) {
            first.b[i - 10] = first.b[i];
        }

        first.b[22] = 0x01;
        first.b[23] = 0x01;
        for (int i = 24; i < 135; ++i)
            first.b[i] = 0;
        first.b[135] = 0x80;
        for (int i = 136; i < 200; ++i)
            first.b[i] = 0;

        partial_keccakf((uint64_t*)&first);
        if (first.b[0] != 0 && round == rounds - 1) {
            for (int i = 0; i < 20; i++) {
                factory_data[id].b[i] = first.b[i + 12];
            }
        }
    }
}
#endif

__constant__ pattern_descriptor g_search_descr_contract = {0};

void update_search_prefix_contract(const pattern_descriptor &pref)
{
    cudaMemcpyToSymbol(g_search_descr_contract, &pref, sizeof(pattern_descriptor));
}


__global__ void create3_search_kernel(search_result* const results, int rounds)
{
	const size_t id = (threadIdx.x + blockIdx.x * blockDim.x);

    //test

    for (int round = 1; round <= rounds; round++) {
        ethhash first;

        first.b[0] = 0xff;
        for (int i = 0; i < 20; i++) {
            first.b[i + 1] = g_factory[i];
        }
        salt salt_data;
        salt_data.d[0] = id;
        salt_data.d[1] = round;
        salt_data.d[2] = g_randomSalt.d[2];
        salt_data.d[3] = g_randomSalt.d[3];
        salt_data.d[4] = g_randomSalt.d[4];
        salt_data.d[5] = g_randomSalt.d[5];
        salt_data.d[6] = g_randomSalt.d[6];
        salt_data.d[7] = g_randomSalt.d[7];

        for (int i = 0; i < 32; i++) {
            first.b[i + 21] = salt_data.b[i];
        }

        //0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f

        first.b[53] = 0x21;
        first.b[54] = 0xc3;
        first.b[55] = 0x5d;
        first.b[56] = 0xbe;
        first.b[57] = 0x1b;
        first.b[58] = 0x34;
        first.b[59] = 0x4a;
        first.b[60] = 0x24;
        first.b[61] = 0x88;
        first.b[62] = 0xcf;
        first.b[63] = 0x33;
        first.b[64] = 0x21;
        first.b[65] = 0xd6;
        first.b[66] = 0xce;
        first.b[67] = 0x54;
        first.b[68] = 0x2f;
        first.b[69] = 0x8e;
        first.b[70] = 0x9f;
        first.b[71] = 0x30;
        first.b[72] = 0x55;
        first.b[73] = 0x44;
        first.b[74] = 0xff;
        first.b[75] = 0x09;
        first.b[76] = 0xe4;
        first.b[77] = 0x99;
        first.b[78] = 0x3a;
        first.b[79] = 0x62;
        first.b[80] = 0x31;
        first.b[81] = 0x9a;
        first.b[82] = 0x49;
        first.b[83] = 0x7c;
        first.b[84] = 0x1f;
        first.b[85] = 0x01;
        //total length 85
        for (int i = 86; i < 135; ++i)
            first.b[i] = 0;

        first.b[135] = 0x80;
        for (int i = 136; i < 200; ++i)
            first.b[i] = 0;
        compute_keccak_full(&first);

        first.b[0] = 0xd6;
        first.b[1] = 0x94;
        for (int i = 12; i < 32; i++) {
            first.b[i - 10] = first.b[i];
        }

        first.b[22] = 0x01;
        first.b[23] = 0x01;
        for (int i = 24; i < 135; ++i)
            first.b[i] = 0;
        first.b[135] = 0x80;
        for (int i = 136; i < 200; ++i)
            first.b[i] = 0;

        partial_keccakf((uint64_t*)&first);

        ethaddress& addr = *(ethaddress*)&first.b[12];
        if (scorer(addr, g_search_descr_contract) == SCORE_ACCEPTED) {
            results[id].round = round;
            results[id].id = id;

            for (int i = 0; i < 20; i++) {
                results[id].addr[i] = first.b[i + 12];
            }
        }


    }
}

#ifdef UNUSED_OLD_TESTS
void test_create3()
{
    const int kernel_group_size = 256;
    const uint64_t data_count = 2500 * kernel_group_size;
    printf("Generating test data %lld...\n", data_count);


    salt* s = new salt[data_count]();
    {
        uint8_t salt[32];
        const char* test_salt = "f666cd402db9720a1c0e39000000000000000000000000000000000000000000";
        for (int i = 0; i < 32; i++) {
            unsigned int byte;
            sscanf(test_salt + i * 2, "%2x", &byte); // Parse 2-character hex string
            salt[i] = (uint8_t)(byte);
        }
        for (int n = 0; n < data_count; n++) {
            memcpy(s[n].b, salt, 32);
        }
    }

    factory* f = new factory[data_count]();
    {
        uint8_t factory[20];
        const char* test_factory = "9e3f8eae49e442a323ef2094f277bf62752e6995";
        for (int i = 0; i < 20; i++) {
            unsigned int byte;
            sscanf(test_factory + i * 2, "%2x", &byte); // Parse 2-character hex string
            factory[i] = (uint8_t)(byte);
        }
        for (int n = 0; n < data_count; n++) {
            memcpy(f[n].b, factory, 20);
        }
    }

    cudaMemcpyToSymbol(g_factory, &f[0].b, 20);

    salt* deviceSalt = NULL;
    cudaMalloc(&deviceSalt, sizeof(salt) * data_count);
    factory* deviceFactory = NULL;
    cudaMalloc(&deviceFactory, sizeof(factory) * data_count);

    printf("Copying data to device %d MB...\n", (uint32_t)(sizeof(salt) * data_count / 1024 / 1024 + sizeof(factory) * data_count / 1024 / 1024));

    cudaMemcpy(deviceSalt, s, sizeof(salt) * data_count, cudaMemcpyHostToDevice);
    cudaMemcpy(deviceFactory, f, sizeof(factory) * data_count, cudaMemcpyHostToDevice);
    cudaDeviceSynchronize();

    auto error = cudaGetLastError();
    if (error != cudaSuccess)
    {
        printf("Initialize keccak test failed %s\n",cudaGetErrorString(error));
        exit(1);
    }
    printf("Running keccak kernel...\n");
    auto start = std::chrono::high_resolution_clock::now();
    const uint64_t current_time = time(NULL);
    int rounds = 1100;
    create3_host<<<data_count / kernel_group_size, kernel_group_size>>>(deviceFactory, deviceSalt, rounds);
    cudaDeviceSynchronize();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

    // Output the duration
    std::cout << "Time taken: " << duration.count() / 1000.0 / 1000.0 << " ms" << std::endl;

    printf("Addresses computed: %lld\n", rounds * data_count);
    printf("Compute MH: %f MH/s\n", (double)rounds * data_count / duration.count() * 1000.0);
    printf("Start data factory: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", f[0].b[i]);
    }
    printf("\n");
    printf("Start data salt: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", s[0].b[i]);
    }
    printf("\n");


    printf("Copying data back...\n");
    cudaMemcpy(f, deviceFactory, data_count * sizeof(factory), cudaMemcpyDeviceToHost);
    cudaMemcpy(s, deviceSalt, data_count * sizeof(salt), cudaMemcpyDeviceToHost);

    printf("Freeing device memory...\n");
    cudaFree(deviceFactory);
    cudaFree(deviceSalt);
    error = cudaGetLastError();
    if (error != cudaSuccess)
    {
        LOG_ERROR("Initialize keccak test failed %s\n", cudaGetErrorString(error));
        exit(1);
    }

    printf("Checking results...\n");
    char hexAddr[43] = { 0 };
    for (int n = 0; n < data_count; n++) {
        hexAddr[0] = '0';
        hexAddr[1] = 'x';
        for (int i = 0; i < 20; i++) {
            sprintf(&hexAddr[(i) * 2 + 2], "%02x", f[n].b[i]);
        }
        if (strcmp(hexAddr, "0x000000000000d710b854d2cfd38baca6b87f4494") != 0) {
            printf("Keccak test failed expected %s got %s\n", "0x000000000000d710b854d2cfd38baca6b87f4494", hexAddr);
            exit(1);
        }
    }
    printf("Keccak test passed: %s\n", hexAddr);

    printf("Freeing host memory...\n");
    delete[] f;
    delete[] s;
}
#endif

void run_kernel_create3_search(create3_search_data * data) {
    create3_search_kernel<<<(int)(data->kernel_groups), data->kernel_group_size>>>(data->device_result, data->rounds);
}
