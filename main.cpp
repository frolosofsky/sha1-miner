#include <chrono>
#include <iostream>
#include <stdlib.h>
#include <time.h>

#include "miner.h"
#include "sha1.h"

template <typename Os, size_t N>
Os &operator <<(Os &os, sha1::buf<N> const &buf) {
    for (auto const &c : buf) {
        if (c == 0) {
            break;
        }
        os << (char)c;
    }
    return os;
}

int help(char **argv, int exit=0) {
    std::cout << "Usage: " << argv[0] << " <prefix> [-t <threads_count>] [-d <difficulty>] [-r] [-p] [-h]" << std::endl
              << "Find a suffix so that sha1(<prefix><suffix>) has <difficulty>" << std::endl
              << "  -d <difficulty>      an amount of leading zeros in the hex view" << std::endl
              << "                       of the hash (i.e. every difficulty point represents" << std::endl
              << "                       a 4 bits of the hash, max difficulty is 40)" << std::endl
              << "  -t <threads_count>   how many threads to launch to mine a hash" << std::endl
              << "  -r                   use a random nonce generator" << std::endl
              << "  -p                   measure mega-hashes per second but drops overal performace" << std::endl;
    return exit;
}

// Performace check workaround.
// Lambda cannot be converted to a function pointer when it captures values.
// Making these variables global injects them into the lambda body.
// std::function is quite heavy and function pointer seems to be a good approach
// to this function be optimized and called directly.
static auto nonce_func = nonce_inc;
std::atomic<size_t> ticks = 0;

int main(int argc, char **argv) {
    std::string prefix;
    size_t threads_count = 1;
    size_t difficulty = 1;
    bool perf = false;

    for (int i = 1; i < argc; ++i) {
        std::string const arg(argv[i]);
        if (arg == "-h") {
            return help(argv, 0);
        } else if (arg == "-t" && i < argc - 1) {
            threads_count = std::max(0, std::atoi(argv[++i]));
        } else if (arg == "-d" && i < argc - 1) {
            difficulty = std::max(0, std::atoi(argv[++i]));
        } else if (arg == "-r") {
            srand(time(0));
            nonce_func = nonce_rand;
        } else if (arg == "-p") {
            perf = true;
        } else {
            prefix = arg;
        }
    }

    if (prefix.empty() || threads_count ==0 || difficulty == 0 || difficulty > 40) {
        return help(argv, 1);
    }

    auto nonce_func_copy = nonce_func;

    if (perf) {
        nonce_func_copy = [](nonce &nonce) {
                              ++ticks;
                              return nonce_func(nonce);
                     };
    }

    auto const start = std::chrono::system_clock::now();

    MineResult const r = mine(prefix, difficulty, threads_count, nonce_func_copy);
    if (!r.success) {
        std::cerr << "Hash not found" << std::endl;
        return 1;
    }

    std::cout << prefix << r.padding << r.nonce << std::endl;
    std::cout << hash2str(r.hash) << std::endl;
    if (perf) {
        auto const end = std::chrono::system_clock::now();
        std::chrono::microseconds const elapsed = end - start;
        std::cout << "Hashrate is " << (ticks/double(elapsed.count())) << "M/s" << std::endl;
    }
    return 0;
}
