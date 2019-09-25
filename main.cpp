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

constexpr size_t npos = size_t(-1);
constexpr size_t nonce_size = 16;

// Nonce alphabet is [0-9a-zA-Z]
size_t nonce_inc(unsigned char nonce[nonce_size], size_t i=(nonce_size - 1)) {
    if (nonce[i] == '9') {
        nonce[i] = 'a';
        return i;
    } else if (nonce[i] == 'z') {
        nonce[i] = 'A';
        return i;
    } else if (nonce[i] != 'Z') {
        ++nonce[i];
        return i;
    }
    nonce[i] = '0';
    if (i == 0) {
        return npos;
    }
    return nonce_inc(nonce, i - 1);
}

enum class MineWorkerResult {
    FOUND,
    NOTFOUND,
    FINISHED,
};

MineWorkerResult mine_worker(SHA_CTX const &prefix_ctx, unsigned char nonce[nonce_size], unsigned char hash[20], size_t difficulty) {
    for (size_t i = 0; i < 9999999; ++i) {
        size_t changed_index = nonce_inc(nonce);
        if (changed_index == npos) {
            return MineWorkerResult::FINISHED;
        }
        SHA_CTX ctx = prefix_ctx;
        SHA1_Update(&ctx, nonce, nonce_size);
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
    unsigned char nonce[nonce_size] = {0};
    unsigned char hash[20] = {};
};

std::atomic<int> result_id = -1;
std::mutex m;
std::condition_variable thread_exit;;

void miner_thread(SHA_CTX const &prefix_ctx, MineResult &result, size_t difficulty, int id) {
    MineWorkerResult r = MineWorkerResult::NOTFOUND;
    while(result_id == -1 && r == MineWorkerResult::NOTFOUND) {
        r = mine_worker(prefix_ctx, result.nonce, result.hash, difficulty);
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
        memset(results[i].nonce, '0', nonce_size);
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

template<size_t N>
std::string to_string(unsigned char const data[N]) {
    return std::string((char const*)data, N);
}

int main() {
    std::string const prefix = "hello world";
    const auto r = mine(prefix, 7, 2);
    if (!r.success) {
        std::cerr << "Hash not found" << std::endl;
        return 1;
    }
    std::cout << prefix << to_string<64>(r.padding) << to_string<nonce_size>(r.nonce) << std::endl;
    std::cout << hash2str(r.hash, sizeof(r.hash)) << std::endl;
    return 0;
}
