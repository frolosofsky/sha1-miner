#include <iostream>
#include "miner.h"

template<size_t N>
std::string to_string(unsigned char const data[N]) {
    return std::string((char const*)data, N);
}

int main() {
    std::string const prefix = "hello world";
    MineResult const r = mine(prefix, 7, 2);
    if (!r.success) {
        std::cerr << "Hash not found" << std::endl;
        return 1;
    }
    std::cout << prefix << to_string<64>(r.padding) << to_string<nonce_size>(r.nonce) << std::endl;
    std::cout << hash2str(r.hash) << std::endl;
    return 0;
}
