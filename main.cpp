#include <openssl/sha.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <array>

std::string hash2str(unsigned char const *hash, size_t size) {
    constexpr char digits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string str(size*2, ' ');
    for (size_t i = 0; i < size; ++i) {
        str[i*2] = digits[(hash[i] & 0xFA) >> 4];
        str[i*2 + 1] = digits[hash[i] & 0x0F];
    }
    return str;
}

bool difficulty_eq(unsigned char const *buf, size_t d) {
    while (d > 1) {
        if (*buf == 0) {
            d -= 2;
            ++buf;
        } else {
            return false;
        }
    }
    if (d == 1) {
        return ((*buf & 0xF0) >> 4) == 0;
    }
    return true;
}

bool difficulty_eq(SHA_CTX const &ctx, unsigned char hash[20], size_t difficulty) {
    SHA_CTX tmp = ctx;
    SHA1_Final(hash, &tmp);
    return difficulty_eq(hash, difficulty);
}

bool nonce_inc(unsigned char *buf, size_t size, size_t *buf_length, size_t start=0) {
    // alphabet: 0-9a-zA-Z
    if (start >= size - 1) {
        return false;
    }
    if (buf[start] == 0) {
        buf[start] = '0';
        ++(*buf_length);
        return true;
    }
    if (buf[start] == '9') {
        buf[start] = 'a';
    } else if (buf[start] == 'z') {
        buf[start] = 'A';
    } else if (buf[start] == 'Z') {
        buf[start] = '0';
        return nonce_inc(buf, size, buf_length, start + 1);
    } else {
        ++buf[start];
    }
    return true;
}

enum class MineWorkerResult {
    FOUND,
    NOTFOUND,
    FINISHED,
};

MineWorkerResult mine_worker(SHA_CTX const &prefix_ctx, unsigned char nonce[64], size_t *nonce_len, unsigned char hash[20], size_t difficulty) {
    for (size_t i = 0; i < 9999999; ++i) {
        if (!nonce_inc(nonce, 64, nonce_len)) {
            return MineWorkerResult::FINISHED;
        }
        SHA_CTX ctx = prefix_ctx;
        SHA1_Update(&ctx, nonce, *nonce_len);
        SHA1_Final(hash, &ctx);
        if (difficulty_eq(hash, difficulty)) {
            return MineWorkerResult::FOUND;
        }
    }
    return MineWorkerResult::NOTFOUND;
}

struct MineResult {
    bool success = false;
    unsigned char padding[64] = {0};
    unsigned char nonce[64] = {0};
    unsigned char hash[20] = {};
};

void miner_thread() {

}

MineResult mine(std::string const &prefix, size_t difficulty) {
    MineResult result;
    result.success = true;

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, prefix.c_str(), prefix.size());
    unsigned char hash[20] = {0};

    if (difficulty_eq(ctx, hash, difficulty)) {
        return result;
    }

    unsigned char padding_str[64] = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};
    size_t padding = 64 - prefix.size() % 64;
    SHA1_Update(&ctx, padding_str, padding);
    memcpy(result.padding, padding_str, padding);

    if (difficulty_eq(ctx, hash, difficulty)) {
        memcpy(result.hash, hash, sizeof(hash));
        return result;
    }

    unsigned char nonce[64] = {0};
    size_t nonce_len = 0;

    MineWorkerResult r = MineWorkerResult::NOTFOUND;

    while(r == MineWorkerResult::NOTFOUND) {
        r = mine_worker(ctx, nonce, &nonce_len, hash, difficulty);
    }

    if (r == MineWorkerResult::FOUND) {
        memcpy(result.nonce, nonce, sizeof(nonce));
        memcpy(result.hash, hash, sizeof(hash));
        return result;
    }

    result.success = false;
    return result;
}

std::string to_string(unsigned char const data[64]) {
    return std::string((char const*)data, 64);
}

struct Foo {
    char bar[10] = {0};
};

int main() {
    std::string const prefix = "hello world";
    const auto r = mine(prefix, 7);
    if (!r.success) {
        std::cerr << "Hash not found" << std::endl;
        return 1;
    }
    std::cout << prefix << to_string(r.padding) << to_string(r.nonce) << std::endl;
    std::cout << hash2str(r.hash, sizeof(r.hash)) << std::endl;
    return 0;
}
