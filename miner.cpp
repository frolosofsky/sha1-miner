#include "miner.h"
#include <openssl/sha.h>
#include <thread>
#include <vector>

static bool difficulty_eq(unsigned char const *buf, size_t d) {
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

static bool difficulty_eq(SHA_CTX const &ctx, unsigned char hash[20], size_t const difficulty) {
    SHA_CTX tmp = ctx;
    SHA1_Final(hash, &tmp);
    return difficulty_eq(hash, difficulty);
}

constexpr size_t npos = size_t(-1);

// Nonce alphabet is [0-9a-zA-Z]
static size_t nonce_inc(unsigned char nonce[nonce_size], size_t const i=(nonce_size - 1)) {
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

static MineWorkerResult mine_worker(SHA_CTX const &prefix_ctx,
                                    unsigned char nonce[nonce_size],
                                    unsigned char hash[20],
                                    size_t const difficulty) {
    for (size_t i = 0; i < 9999999; ++i) {
        size_t const changed_index = nonce_inc(nonce);
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

MineResult mine(std::string const &prefix, size_t const difficulty, size_t const threads_count) {
    MineResult result;
    result.success = false;

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, prefix.c_str(), prefix.size());

    if (difficulty_eq(ctx, result.hash, difficulty)) {
        result.success = true;
        return result;
    }

    constexpr unsigned char padding_alphabet[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    assert(threads_count < sizeof(padding_alphabet));

    std::vector<MineResult> results(threads_count, result);
    std::vector<SHA_CTX> ctxs(threads_count, ctx);

    size_t const padding_size = 64 - prefix.size() % 64;
    for (size_t i = 0; i < threads_count; ++i) {
        memset(results[i].padding, padding_alphabet[i], padding_size);
        memset(results[i].nonce, '0', nonce_size);
        SHA1_Update(&ctxs[i], results[i].padding, padding_size);
        if (difficulty_eq(ctxs[i], results[i].hash, difficulty)) {
            return results[i];
        }
    }

    std::vector<std::thread> threads;
    std::atomic<int> result_id = -1;
    std::mutex m;
    std::condition_variable thread_exit;;
    std::atomic<size_t> active_threads = threads_count;

    for (size_t i = 0; i < threads_count; ++i) {
        threads.emplace_back(std::thread([&ctxs, i, &results, difficulty, &result_id, &active_threads, &thread_exit] {
                                             MineWorkerResult r = MineWorkerResult::NOTFOUND;
                                             while(result_id == -1 && r == MineWorkerResult::NOTFOUND) {
                                                 r = mine_worker(ctxs[i], results[i].nonce, results[i].hash, difficulty);
                                             }
                                             if (r == MineWorkerResult::FOUND) {
                                                 result_id = i;
                                                 results[i].success = true;
                                             }
                                             --active_threads;
                                             thread_exit.notify_one();
                                         }));
    }

    while (result_id == -1 && active_threads > 0) {
        std::unique_lock<std::mutex> lock(m);
        thread_exit.wait(lock);
    }

    // at this moment at least one thread is finished, and others have been notified to stop.
    for (auto &t : threads) {
        t.join();
    }

    if (result_id != -1) {
        return results[result_id];
    }
    return result;
}

std::string hash2str(unsigned char const hash[20]) {
    constexpr char digits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string str(40, ' ');
    for (size_t i = 0; i < 20; ++i) {
        str[i*2] = digits[(hash[i] & 0xFA) >> 4];
        str[i*2 + 1] = digits[hash[i] & 0x0F];
    }
    return str;
}
