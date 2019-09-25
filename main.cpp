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
    SHA_CTX ctx;
    for (size_t i = 0; i < 9999999; ++i) {
        if (!nonce_inc(nonce, 64, nonce_len)) {
            return MineWorkerResult::FINISHED;
        }
        memcpy(&ctx, &prefix_ctx, sizeof(ctx));
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

std::atomic<int> result_id = -1;
std::mutex m;
std::condition_variable thread_exit;;

void miner_thread(SHA_CTX const &prefix_ctx, MineResult &result, size_t difficulty, int id) {
    size_t nonce_len;
    MineWorkerResult r = MineWorkerResult::NOTFOUND;
    while(result_id == -1 && r == MineWorkerResult::NOTFOUND) {
        r = mine_worker(prefix_ctx, result.nonce, &nonce_len, result.hash, difficulty);
    }
    if (r == MineWorkerResult::FOUND) {
        result_id = id;
        result.success = true;
        thread_exit.notify_one();
    }
}

MineResult mine(std::string const &prefix, size_t difficulty, size_t threads_count) {
    MineResult result;
    result.success = false;

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, prefix.c_str(), prefix.size());

    if (difficulty_eq(ctx, result.hash, difficulty)) {
        result.success = true;
        return result;
    }

    unsigned char padding_alphabet[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

    assert(threads_count < sizeof(padding_alphabet));

    std::vector<MineResult> results(threads_count, result);
    std::vector<SHA_CTX> ctxs(threads_count, ctx);

    const size_t padding_size = 64 - prefix.size() % 64;
    for (size_t i = 0; i < threads_count; ++i) {
        memset(results[i].padding, padding_alphabet[i], padding_size);
        SHA1_Update(&ctxs[i], results[i].padding, padding_size);
        if (difficulty_eq(ctxs[i], results[i].hash, difficulty)) {
            return results[i];
        }
    }

    std::vector<std::thread> threads;

    for (size_t i = 0; i < threads_count; ++i) {
        threads.emplace_back(std::thread([&ctxs, i, &results, difficulty] {
                                             miner_thread(ctxs[i], results[i], difficulty, i);
                                         }));
    }

    std::unique_lock<std::mutex> lock(m);
    thread_exit.wait(lock);

    for (auto &t : threads) {
        t.join();
    }

    if (result_id != -1) {
        return results[result_id];
    }
    return result;
}

std::string to_string(unsigned char const data[64]) {
    return std::string((char const*)data, 64);
}

int main() {
    std::string const prefix = "hello world";
    const auto r = mine(prefix, 9, 2);
    if (!r.success) {
        std::cerr << "Hash not found" << std::endl;
        return 1;
    }
    std::cout << prefix << to_string(r.padding) << to_string(r.nonce) << std::endl;
    std::cout << hash2str(r.hash, sizeof(r.hash)) << std::endl;
    return 0;
}
