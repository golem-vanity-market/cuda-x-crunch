#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <random>
#include <mutex>

std::string string_replace(const std::string & str, const std::string & from, const std::string & to)
{
    std::string ret = str;
    size_t start_pos = 0;
    while((start_pos = ret.find(from, start_pos)) != std::string::npos) {
        ret.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
        return ret;
    }

std::string string_to_lower(const std::string & str)
{
    std::string ret = str;
    std::transform(ret.begin(), ret.end(), ret.begin(), [](unsigned char c){ return std::tolower(c); });
    return ret;
}

std::string decode_pub_key_x(const std::string& publicKey)
{
    std::string ret = publicKey;
    ret = string_replace(ret, "0x", "");
    if (ret.find_first_not_of("0123456789abcdef") != std::string::npos) {
        std::cerr << "Invalid pub key, only hex characters are allowed: " << publicKey << std::endl;
        return "";
    }
    if (ret.length() != 128) {
        std::cerr << "Invalid pub key, length has to be 128, given length " << ret.length() << std::endl;
        return "";
    }
    return ret;
}


std::string normalize_public_key(const std::string & publicKey)
{
    if (publicKey.substr(0, 4) == "xpub") {
        return publicKey;
    }
    std::string ret = publicKey;
    ret = string_replace(ret, "0x", "");
    if (ret.find_first_not_of("0123456789abcdef") != std::string::npos) {
        std::cerr << "Invalid pub key, only hex characters are allowed: " << publicKey << std::endl;
        return "";
    }
    if (ret.length() != 128) {
        std::cerr << "Invalid pub key, length has to be 128, given length " << ret.length() << std::endl;
        return "";
    }
    return ret;
}

std::string normalize_ethereum_address(const std::string & address)
{
    std::string ret = address;
    ret = string_replace(ret, "0x", "");
    ret = string_to_lower(ret);
    //check if ret contains only hex characters
    if (ret.find_first_not_of("0123456789abcdef") != std::string::npos) {
        std::cerr << "Invalid ethereum address, only hex characters are allowed: " << address << std::endl;
        return "";
    }
    if (ret.length() != 40) {
        std::cerr << "Invalid ethereum address, length has to be 40, given length " << ret.length() << std::endl;
        return "";
    }
    return ret;
}

const uint64_t start = std::chrono::nanoseconds(std::chrono::high_resolution_clock::now().time_since_epoch()).count();;
double get_app_time_sec() {
    auto now = std::chrono::nanoseconds(std::chrono::high_resolution_clock::now().time_since_epoch()).count();;
    return (now - start) / 1.0E9;
}

std::string bytes_to_ethereum_address(const uint8_t *bytes) {
    char buf[43];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 20; i++) {
        sprintf(buf + i * 2 + 2, "%02x", bytes[i]);
    }
    return std::string(buf, 42);
}

std::string get_utc_time() {
    // Get the current time point
    auto now = std::chrono::system_clock::now();

    // Convert the time point to a time_t, which represents the time in seconds since the epoch
    auto now_time_t = std::chrono::system_clock::to_time_t(now);

    // Convert the time_t to a tm structure in UTC
    auto now_tm = *std::gmtime(&now_time_t);

    // Get the milliseconds part
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    // Create a string stream to format the output
    std::ostringstream oss;

    // Format the time as "YYYY-MM-DDTHH:MM:SS.sssZ"
    oss << std::put_time(&now_tm, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << now_ms.count()
        << 'Z';

    // Return the formatted string
    return oss.str();
}

std::unique_ptr<std::mt19937_64> generator;
std::mutex mutex;
void _init_random(uint64_t seed) {
    generator = std::make_unique<std::mt19937_64>(seed);
}

uint64_t get_next_random()
{
    std::lock_guard<std::mutex> lock(mutex);
    if (!generator) {
        _init_random(std::chrono::nanoseconds(std::chrono::high_resolution_clock::now().time_since_epoch()).count());
    }
    return (*generator)();
}

void init_random(uint64_t seed)
{
    std::lock_guard<std::mutex> lock(mutex);
    _init_random(seed);
}

