SSL_LD=-L/usr/local/opt/openssl/lib -lssl -l crypto
SSL_I=-I/usr/local/opt/openssl/include

CPPFLAGS=-std=c++17 -Wextra -Werror -pedantic -O2 ${SSL_I}
LDFLAGS=${SSL_LD}

.PHONY: clean

sha1-miner: main.cpp miner.h miner.cpp sha1.h
	/usr/bin/clang++ ${CPPFLAGS} ${LDFLAGS} main.cpp miner.cpp -o $@

clean:
	rm -f sha1-miner
