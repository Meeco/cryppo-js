# WebCrypto vs. node-forge performance

Comparison of cryptographic primitive performance between the WebCrypto-based implementation (`@meeco/cryppo` v4.0.0+) and the previous node-forge-based implementation (v3.0.2), checked out to a separate local working tree.

## Test machine

- MacBook (Apple Silicon), Apple M1 Pro, 32 GB RAM
- macOS 26.6.1 (build 25G76)
- Node.js v24.14.0

Numbers are single-run averages on this machine only — treat them as directional (order-of-magnitude comparisons between the two implementations), not as absolute/portable performance guarantees.

## Results

### AES-256-GCM (symmetric encrypt/decrypt)

| Size | Encrypt (WebCrypto) | Encrypt (node-forge) | Encrypt speedup | Decrypt (WebCrypto) | Decrypt (node-forge) | Decrypt speedup |
|---|---|---|---|---|---|---|
| 1 KB | 0.055 ms | 0.234 ms | 4.3x faster | 0.044 ms | 0.087 ms | 2.0x faster |
| 100 KB | 0.712 ms | 4.978 ms | 7.0x faster | 0.515 ms | 4.368 ms | 8.5x faster |
| 1 MB | 6.989 ms | 72.358 ms | 10.4x faster | 4.932 ms | 47.956 ms | 9.7x faster |
| 10 MB | 74.123 ms | 1445.230 ms | 19.5x faster | 45.368 ms | 823.148 ms | 18.1x faster |

WebCrypto wins at every size, by roughly 2-20x, growing with payload size.

### RSA-OAEP (asymmetric encrypt/decrypt, key generation)

| Operation | WebCrypto | node-forge | Speedup |
|---|---|---|---|
| Keygen 2048-bit | 49.796 ms | 39.280 ms | 1.3x slower |
| Encrypt 2048-bit | 0.122 ms | 0.729 ms | 6.0x faster |
| Decrypt 2048-bit | 0.869 ms | 17.933 ms | 20.6x faster |
| Keygen 4096-bit | 302.109 ms | 406.765 ms | 1.3x faster |
| Encrypt 4096-bit | 0.165 ms | 2.347 ms | 14.2x faster |
| Decrypt 4096-bit | 4.324 ms | 138.027 ms | 31.9x faster |

Key generation is roughly a wash (a small 5-run sample, high variance either way); encrypt/decrypt are dominated by WebCrypto, especially decrypt (private-key operation) at larger key sizes.

### PBKDF2-HMAC-SHA256 (key derivation)

| Iterations | WebCrypto | node-forge | Speedup |
|---|---|---|---|
| 20,000 | 2.755 ms | 375.059 ms | 136.1x faster |
| 100,000 | 12.441 ms | 1865.054 ms | 149.9x faster |

### HMAC-SHA256 (keyed digest)

| Size | WebCrypto | node-forge | Speedup |
|---|---|---|---|
| 1 KB | 0.045 ms | 0.033 ms | 1.4x slower |
| 1 MB | 2.023 ms | 18.197 ms | 9.0x faster |
| 10 MB | 19.509 ms | 179.585 ms | 9.2x faster |

At 1 KB, per-call fixed overhead (e.g. WebCrypto's `importKey` call on every invocation) dominates and node-forge is marginally faster; WebCrypto pulls ahead sharply as payload size grows.

### RSA signing (RSASSA-PKCS1-v1_5 / SHA-256)

| Key size / payload | Sign (WebCrypto) | Sign (node-forge) | Sign speedup | Verify (WebCrypto) | Verify (node-forge) | Verify speedup |
|---|---|---|---|---|---|---|
| 2048-bit, 1 KB | 0.881 ms | 18.230 ms | 20.7x faster | 0.084 ms | 0.739 ms | 8.8x faster |
| 2048-bit, 1 MB | 8.525 ms | 96.962 ms | 11.4x faster | 0.620 ms | 37.392 ms | 60.3x faster |
| 4096-bit, 1 KB | 4.519 ms | 141.607 ms | 31.3x faster | 0.134 ms | 2.196 ms | 16.4x faster |

## Method

Both repos expose the same async API shape for every primitive (`encryptWithKey`, `decryptWithKey`, `generateRSAKeyPair`, `encryptWithPublicKey`, `decryptWithPrivateKey`, `generateDerivedKey`, `hmacSha256Digest`, `signWithPrivateKey`, `verifyWithPublicKey`), so the same benchmark script could be copied unmodified between the two repos and run against each implementation via `npx vitest run <file>`.

For each primitive:

1. A `test/bench-*.manual.test.ts` file was added (outside the normal test run — not matched by `npm test`, invoked explicitly). It imports the public API from `../src/index.js` — no mocking, exercising the exact code path a consumer would use.
2. Each benchmark:
   - generates random input of a given size with `crypto.getRandomValues`,
   - runs one warm-up call (to pay for one-time costs like JIT warmup / WebCrypto key import) before timing starts,
   - runs N iterations with `performance.now()` around each call, and reports the mean per-call time.
   - N is scaled down as payload size grows (e.g. 500 iterations at 1 KB, 10 iterations at 10 MB) to keep total run time reasonable.
3. The identical script file was then copied into a separate local checkout of the node-forge v3.0.2 codebase and run the same way, so both sides see the same inputs, sizes, and iteration counts.

This is a simple wall-clock micro-benchmark (not `vitest bench`, not a statistical/percentile harness) — good enough for spotting order-of-magnitude differences and regressions, not for sub-millisecond precision claims.

## Reproducing

The benchmark files (`test/bench-*.manual.test.ts`) are excluded from the normal `npm test` run. To run one:

```sh
npx vitest run test/bench-aes-gcm.manual.test.ts --reporter=verbose
npx vitest run test/bench-rsa.manual.test.ts --reporter=verbose
npx vitest run test/bench-pbkdf2-hmac-sign.manual.test.ts --reporter=verbose
```

To compare against node-forge, copy the same file into a checkout of `@meeco/cryppo` v3.0.2 and run it there.
