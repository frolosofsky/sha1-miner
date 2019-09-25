LDFLAGS="-L/usr/local/opt/openssl/lib"
CPPFLAGS="-I/usr/local/opt/openssl/include"

.PHONY: profile

exasol-test: main.cpp miner.h miner.cpp
	/usr/bin/clang++ ${CPPFLAGS} ${LDFLAGS} -std=c++17 -Wextra -Werror -pedantic -lssl -lcrypto -g main.cpp miner.cpp -o exasol-test -O2

profile: exasol-test
	sudo dtrace -c './exasol-test' -o out.stacks -n 'profile-997 /execname == "exasol-test"/ { @[ustack(100)] = count(); }'
	../FlameGraph/stackcollapse.pl out.stacks | ../FlameGraph/flamegraph.pl > pretty-graph.svg

run: exasol-test
	time ./exasol-test
