#pragma once

#include <string>

constexpr size_t nonce_size = 16;

struct MineResult {
    bool success = false;
    unsigned char padding[64] = {0};
    unsigned char nonce[nonce_size] = {0};
    unsigned char hash[20] = {0};
};

MineResult mine(std::string const &prefix, size_t difficulty, size_t threads_count);
std::string hash2str(unsigned char const hash[20]);
