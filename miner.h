#pragma once

#include <string>
#include "sha1.h"

constexpr size_t nonce_size = 16;

struct MineResult {
    bool success = false;
    sha1::buf<64> padding;
    sha1::buf<nonce_size> nonce;
    sha1::hash hash;
    size_t hashes_count = 0;

    inline MineResult const &ok() {
        success = true;
        return *this;
    }
};

using nonce = sha1::buf<nonce_size>;

size_t nonce_inc(nonce &nonce);
size_t nonce_rand(nonce &nonce);

MineResult mine(std::string const &prefix, size_t difficulty, size_t threads_count, size_t nonce_func(nonce&), size_t *counter);
std::string hash2str(sha1::hash const &hash);
