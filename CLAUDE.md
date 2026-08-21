# cryppo-js

JS/TS port of Ruby's `cryppo` library (sibling repo, also has an Elixir port `cryppo_ex`).
Provides encryption/decryption/signing primitives usable in both Node (>=22) and browsers.

## Crypto engine

As of v4.0.0, all cryptographic primitives run on native WebCrypto (`globalThis.crypto.subtle`) —
AES-256-GCM, PBKDF2-HMAC-SHA256, RSA-OAEP, RSA-PKCS1v15/SHA-256 signing, HMAC-SHA256, random bytes.
`node-forge` was fully removed. Key implementation notes:

- RSA private keys interop as **PKCS#1** PEM; WebCrypto only understands **PKCS#8**, so
  `src/der.ts` has small fixed-shape DER conversion helpers (`pkcs1ToPkcs8`/`pkcs8ToPkcs1`,
  `pemToDer`/`derToPem`). This is not general ASN.1 parsing — the PKCS#8-for-RSA shape is fixed.
- RSA-OAEP uses `hash: 'SHA-1'` deliberately — this matches Ruby's OpenSSL and Elixir's Erlang
  defaults for OAEP/MGF1, which are legacy SHA-1. Do not "fix" this to SHA-256; it would break
  cross-port interop.
- AES-GCM: WebCrypto returns ciphertext with the 16-byte tag appended, unlike forge which kept
  them separate — `encryption.ts`/`decryption.ts` slice/concatenate the tag to preserve the
  existing artifact shape.
- `signWithPrivateKey`, `verifyWithPublicKey`, `keyLengthFromPublicKeyPem`,
  `keyLengthFromPrivateKeyPem`, `hmacSha256Digest`, `encryptWithKeyUsingArtefacts`,
  `decryptWithKeyUsingArtefacts` are all `async` (WebCrypto is Promise-based).
- Password-protected RSA private keys (`encryptPrivateKeyWithPassword`) were removed in v4 —
  WebCrypto has no API to build/parse PKCS#8 `EncryptedPrivateKeyInfo`/PBES2, and neither the
  Ruby nor Elixir port ever had this feature, so there was no interop to preserve.
- `tsconfig.json` explicitly sets `"types": ["node"]`. This is required, not optional: without it,
  `@types/node` (Buffer, process, fs, etc.) silently fails to load — TypeScript's automatic
  `@types` inclusion is not actually active in this project's config, and previously the types
  only ever got pulled in transitively via `@types/node-forge`'s own reference directive.

## Cross-port compatibility

`test/compatibility/compat.json` holds 190+ fixtures generated from the Ruby/Elixir ports.
`test/compatibility/compatibility.test.ts` verifies AES-256-GCM/PBKDF2/RSA-OAEP/RSA-signature
output is byte-for-byte identical to those ports. Any change to a crypto primitive's parameters
(hash algorithm, key format, encoding) must keep this suite green — it's the authoritative
interop check, not just a regression test.

## Commands

- `npm test` — vitest
- `npm run lint` / `npm run format:check` / `npm run format:write`
- `npm run build` — builds both `dist/cjs` and `dist/esm` (excludes `test/`)
- `npm start` (or `npm run demo`) — Vite demo app, for manually exercising the browser code path
