#pragma once
#include <openssl/sha.h>
#include <array>
#include <string>

class sha1 {
public:
    template <size_t N>
    using buf = std::array<unsigned char, N>;
    using hash = buf<SHA_DIGEST_LENGTH>;

    inline sha1() {
        SHA1_Init(&_ctx);
    }

    inline sha1(sha1 const &o): _ctx(o._ctx) { }

    template <typename T>
    inline sha1(T const &data) : sha1() {
        update(data);
    }

    template <size_t N>
    inline bool update(buf<N> const &data, size_t s=0) {
        return SHA1_Update(&_ctx, data.data(), s != 0 ? s : data.size());
    }

    inline bool update(std::string const &data) {
        return SHA1_Update(&_ctx, data.c_str(), data.size());
    }

    inline bool finalize(hash &hash) {
        return SHA1_Final(hash.data(), &_ctx);
    }

private:
    SHA_CTX _ctx;
};
