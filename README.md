# C++/OpenSSL SHA1 miner

Miner finds a nonce for a given prefix and difficulty by using multithread brute force algorithm.

1. Cache SHA1 for prefix + padding to 512 bits.
2. Increments a nonce of characters from `0-9a-zA-Z` alphabet until hash found.

## Build
1. Install `openssl` binaries and headers, `make`, and C++17 compiler;
2. Adjust Makefile;
3. run `make`.

## Use

`./sha1-miner some-prefix -d 5 -t 2`

Runs miner in two threads to find a hash with difficulty 5.

Run `./sha1-miner -h` for info.

## Examples

### Use sequential nonce search

```
./sha1-miner "hello world" -d 7 -t 2 -p
make: `sha1-miner' is up to date.
hello world0000000000000000000000000000000000000000000000000000000000000000efyMs
0000000fc220ad3cfd3647556e8ed3657173a9ad
Hashrate is 14.258M/s
```

### Use random nonce generation

```
./sha1-miner "hello world" -d 7 -t 2 -p -r
/usr/bin/clang++ -std=c++17 -Wextra -Werror -pedantic -O2 -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -l crypto main.cpp miner.cpp -o sha1-miner
hello world11111111111111111111111111111111111111111111111111111QRpEZPSu9Ks0iSpB
00000005ddb4dba209de9c7ed7f27d411f1119b8
Hashrate is 6.04797M/s
```

### Notes
Performace measurement (`-p`) costs CPU itself due to using atomic integer counter.
In my tests, overal performace loss is about 15%.

## TODO

* To progress when the first-round nonce counting doesn't give a result.
* Rework performace measurement (use independent counters per thread).
