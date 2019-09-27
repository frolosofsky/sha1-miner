#include "miner.h"
#include <thread>
#include <vector>
#include <stdlib.h>

static bool difficulty_eq(sha1::hash const &hash, size_t d) {
    unsigned char const *buf = hash.data();
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

static bool difficulty_eq(sha1 const &sha, sha1::hash &hash, size_t const difficulty) {
    sha1 tmp = sha;
    tmp.finalize(hash);
    return difficulty_eq(hash, difficulty);
}

constexpr size_t npos = size_t(-1);

// Nonce alphabet is [0-9a-zA-Z]
static size_t nonce_inc_impl(nonce &nonce, size_t const i) {
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
    return nonce_inc_impl(nonce, i - 1);
}

size_t nonce_inc(nonce &nonce) {
    return nonce_inc_impl(nonce, nonce_size - 1);
}

size_t nonce_rand(nonce &nonce) {
    constexpr unsigned char alphabet[] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    };
    for (auto &c : nonce) {
        c = alphabet[rand() % sizeof(alphabet)];
    }
    return nonce.size() - 1;
}

enum class MineWorkerResult {
    FOUND,
    NOTFOUND,
    FINISHED,
};

static MineWorkerResult mine_worker(sha1 const &prefix_sha, nonce &nonce, sha1::hash &hash, size_t const difficulty, size_t nonce_func(::nonce&), size_t &counter) {
    for (size_t i = 0; i < 9999999; ++i) {
        size_t const changed_index = nonce_func(nonce);
        ++counter;
        if (changed_index == npos) {
            return MineWorkerResult::FINISHED;
        }
        sha1 sha = prefix_sha;
        sha.update(nonce);
        sha.finalize(hash);
        if (difficulty_eq(hash, difficulty)) {
            return MineWorkerResult::FOUND;
        }
    }
    return MineWorkerResult::NOTFOUND;
}

MineResult mine(std::string const &prefix, size_t const difficulty, size_t const threads_count, size_t nonce_func(nonce&), size_t *counter) {
    MineResult result;
    result.success = false;

    sha1 sha;
    sha.update(prefix);

    if (difficulty_eq(sha, result.hash, difficulty)) {
        return result.ok();
    }

    constexpr unsigned char padding_alphabet[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    assert(threads_count < sizeof(padding_alphabet));

    // per thread results
    std::vector<MineResult> results(threads_count, result);
    // per thread prefix sha1 (they have different paddings)
    std::vector<sha1> ctxs(threads_count, sha);

    size_t const padding_size = 64 - prefix.size() % 64;
    for (size_t i = 0; i < threads_count; ++i) {
        memset(results[i].padding.data(), padding_alphabet[i], padding_size);
        results[i].nonce.fill('0');
        ctxs[i].update(results[i].padding, padding_size);
        if (difficulty_eq(ctxs[i], results[i].hash, difficulty)) {
            return results[i].ok();
        }
    }

    std::vector<std::thread> threads;
    std::atomic<int> result_id = -1;
    std::mutex m;
    std::condition_variable thread_exit;;
    std::atomic<size_t> active_threads = threads_count;

    for (size_t i = 0; i < threads_count; ++i) {
        threads.emplace_back(std::thread([&ctxs, i, &results, difficulty, &result_id, &active_threads, &thread_exit, &nonce_func] {
                                             MineWorkerResult r = MineWorkerResult::NOTFOUND;
                                             while(result_id == -1 && r == MineWorkerResult::NOTFOUND) {
                                                 r = mine_worker(ctxs[i], results[i].nonce, results[i].hash, difficulty, nonce_func, results[i].hashes_count);
                                             }
                                             if (r == MineWorkerResult::FOUND) {
                                                 result_id = i;
                                                 results[i].ok();
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

    if (counter != nullptr) {
        *counter = 0;
        for (auto const &r : results) {
            *counter += r.hashes_count;
        }
    }

    if (result_id != -1) {
        return results[result_id];
    }
    return result; // success=false
}

std::string hash2str(sha1::hash const &hash) {
    constexpr char digits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string str(hash.size() * 2, ' ');
    for (size_t i = 0; i < hash.size(); ++i) {
        str[i*2] = digits[(hash[i] & 0xFA) >> 4];
        str[i*2 + 1] = digits[hash[i] & 0x0F];
    }
    return str;
}
