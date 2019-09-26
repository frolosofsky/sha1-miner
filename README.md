# C++/OpenSSL SHA1 miner

Miner finds a nonce for a given prefix and difficulty by using multithread brute force algorithm.

1. Cache SHA1 for prefix + padding to 512 bits.
2. Increments a nonce of characters from `0-9a-zA-Z` alphabet until hash found.

## Build
1. Install `openssl` binaries and headers, `make`, and C++17 compiler;
2. Adjust Makefile;
3. run `make`.

## Use
```
Usage: ./sha1-miner <prefix> [-t <threads_count>] [-d <difficulty>] [-h]
Find a suffix so that sha1(<prefix><suffix>) has <difficulty>
  -d <difficulty>      an amount of leading zeros in the hex view
                       of the hash (i.e. every difficulty point represents
                       a 4 bits of the hash, max difficulty is 40).
  -t <threads_count>   how many threads to launch to mine a hash.
```

## TODO
To progress when the first-round nonce counting doesn't give a result.
