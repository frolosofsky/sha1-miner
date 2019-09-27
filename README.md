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

#### One thread

```
hello world0000000000000000000000000000000000000000000000000000000000000000efyMs
0000000fc220ad3cfd3647556e8ed3657173a9ad
Hashrate is 9.43239M/s
```

#### Two threads

```
./sha1-miner "hello world" -d 7 -t 2 -p
hello world0000000000000000000000000000000000000000000000000000000000000000efyMs
0000000fc220ad3cfd3647556e8ed3657173a9ad
Hashrate is 17.5783M/s
```

### Use random nonce generation

```
./sha1-miner "hello world" -d 7 -t 2 -p -r
hello world000000000000000000000000000000000000000000000000000009ItwHhN0Am0VC3NH
0000000367e43c366b7431f25f0ff860b939607b
Hashrate is 8.02728M/s
```

## TODO

* To progress when the first-round nonce counting doesn't give a result.
* Uptimize random suffix generation.