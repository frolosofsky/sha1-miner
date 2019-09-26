#include <iostream>
#include "miner.h"
#include "sha1.h"

template<size_t N>
std::string to_string(sha1::buf<N> const &data) {
    return std::string((char const*)data.data(), data.size());
}

int help(char **argv, int exit=0) {
    std::cout << "Usage: " << argv[0] << " <prefix> [-t <threads_count>] [-d <difficulty>] [-h]" << std::endl
              << "Find a suffix so that sha1(<prefix><suffix>) has <difficulty>" << std::endl
              << "  -d <difficulty>      an amount of leading zeros in the hex view" << std::endl
              << "                       of the hash (i.e. every difficulty point represents" << std::endl
              << "                       a 4 bits of the hash, max difficulty is 40)." << std::endl
              << "  -t <threads_count>   how many threads to launch to mine a hash." << std::endl;
    return exit;
}

int main(int argc, char **argv) {
    std::string prefix;
    size_t threads_count = 1;
    size_t difficulty = 1;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "-h") {
            return help(argv, 0);
        } else if (arg == "-t" && i < argc - 1) {
            threads_count = std::max(0, std::atoi(argv[++i]));
        } else if (arg == "-d" && i < argc - 1) {
            difficulty = std::max(0, std::atoi(argv[++i]));
        } else {
            prefix = arg;
        }
    }

    if (prefix.empty() || threads_count ==0 || difficulty == 0 || difficulty > 40) {
        return help(argv, 1);
    }

    MineResult const r = mine(prefix, difficulty, threads_count);
    if (!r.success) {
        std::cerr << "Hash not found" << std::endl;
        return 1;
    }

    std::cout << prefix << to_string(r.padding) << to_string(r.nonce) << std::endl;
    std::cout << hash2str(r.hash) << std::endl;
    return 0;
}
