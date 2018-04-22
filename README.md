# haskell-perf-crypto

Benchmarks for cryptographic libraries.

# Time

``` bash
stack bench
```

| Name | Time |
|------|------|
| encrypt/AES-128-CBC/cryptonite | 1.782 μs |
| encrypt/AES-128-CBC/HsOpenSSL | 2.058 μs |
| encrypt/AES-256-CBC/cryptonite | 2.325 μs |
| encrypt/AES-256-CBC/HsOpenSSL | 2.595 μs |
| encrypt/Blowfish-128-CBC/cryptonite | 129.5 μs |
| encrypt/Blowfish-128-CBC/HsOpenSSL | 43.44 μs |
| encrypt/Twofish-128-CBC/cryptonite | 243.0 μs |
