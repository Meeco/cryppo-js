# Changelog

## 4.0.0 (19.08.2026)

- Typescript upgraded from 5.9.3 to 6.0.3
- **BREAKING**: Replaced `node-forge` with native WebCrypto (`globalThis.crypto.subtle`) for every cryptographic primitive — AES-256-GCM, PBKDF2-HMAC-SHA256, RSA-OAEP, RSA-PKCS1v15/SHA-256 signing, HMAC-SHA256, and random byte generation. `node-forge` and `@types/node-forge` are no longer dependencies. Verified byte-for-byte compatible with the Ruby and Elixir cryppo ports against the full `compat.json` fixture suite.
- Note: as a consequence of using `crypto.subtle` directly, this now requires browser support for the Web Crypto API. In practice this is essentially every browser in current use — Chrome/Edge ≥37 (Aug 2014), Firefox ≥34 (Dec 2014), Safari/iOS Safari ≥11 (Sept 2017), Android ≥5.0 (Nov 2014) — it only excludes browsers a decade or more old (and Internet Explorer, which was never fully supported). See the README's Requirements section for details.
- Note: on Node, `crypto.subtle` has been a stable, unflagged global since Node 19 (Oct 18, 2022) — comfortably below this package's existing `>=22.0.0` requirement, so nothing changes there.
- **BREAKING**: The following functions are now `async` (return a `Promise`) since WebCrypto's API is Promise-based, where they were previously synchronous:
  - `signWithPrivateKey`
  - `verifyWithPublicKey`
  - `keyLengthFromPublicKeyPem`
  - `keyLengthFromPrivateKeyPem`
  - `hmacSha256Digest`
  - `encryptWithKeyUsingArtefacts`
  - `decryptWithKeyUsingArtefacts`
- **BREAKING**: Removed `encryptPrivateKeyWithPassword` and the `password` parameter from `decryptWithPrivateKey`/`decryptSerializedWithPrivateKey`. This password-protected an RSA private key PEM as a PKCS#8 `EncryptedPrivateKeyInfo`/PBES2 structure, which WebCrypto has no API to build or parse. Neither the Ruby (`cryppo`) nor Elixir (`cryppo_ex`) port has an equivalent feature, so this was cryppo-js-only with no cross-port interop to preserve.
- Added a [Claude Code](https://claude.com/claude-code) skill (`.claude/skills/cryppo-migrate-v3-to-v4/SKILL.md`, shipped in the published package) that automates the mechanical parts of upgrading a consumer codebase from v3 to v4 — adding `await` at the newly-async call sites and flagging removed-password-feature usages for manual review. See the README's "Upgrading from v3 to v4" section.
- PBKDF2 key derivation and RSA operations (key generation, encryption, signing) are now dramatically faster, since they run on native implementations instead of forge's pure-JS ones. Measured against this repo, comparing the last pre-migration commit to this release:
  - **`npm test`**: ~37s → ~2.9s (~12.6x faster) — dominated by PBKDF2 and RSA key generation moving off forge's pure-JS implementations.
  - **Production bundle size** (this package's `dist/esm` bundled and minified with esbuild, as a consumer's bundler would): 499,807 bytes → 215,707 bytes (~57% smaller); gzipped, 139,927 bytes → 65,042 bytes (~54% smaller). (The unbundled `dist/` output itself is slightly larger, 152 KiB → 182 KiB, since `node-forge` lived in `node_modules` rather than `dist` and new DER-conversion code was added — the bundle size above is the number that matters for consumers.)

## 3.0.2 (14.08.2026)

- README.md improved: fixed inaccurate/broken code examples, added Installation, Requirements, License, and API overview sections
- Upgrade vitest 3 → 4, vite 7 → 8
- Upgrade eslint 9 → 10, @eslint/js 9 → 10, typescript-eslint 8.55 → 8.67
- Rename `vite.config.ts` → `vite.config.mts` to avoid a Vite 8 deprecation warning about loading ESM config as CommonJS
- Fix `SerializationFormat` and `EncodingVersions` not being exported from the package root (#38)
- Fix `IEncryptionOptions` being defined twice with incompatible shapes, breaking imports for `decryptWithKeyUsingArtefacts`'s options type; it now uses the existing `IEncryptionArtifacts` type (#35)

## 3.0.1 (07.03.2026)

- Fix published Node ESM output
- Add dist package metadata generation required for valid dual CJS + ESM package output

## 3.0.0 (13.02.2026)

- **BREAKING**: Minimum Node.js version raised from 12.4 to 22
- Upgrade TypeScript 3.9 → 5.9
- Replace bili/rollup build with dual CJS + ESM tsc output
- Upgrade node-forge 0.10.0 → 1.3.x
- Upgrade bson 4 → 7, yaml 1 → 2, buffer 5 → 6
- Replace Jest + ts-jest with Vitest (native TypeScript support via Vite)
- Upgrade Prettier 2 → 3
- Replace TSLint (deprecated) with ESLint 9 flat config
- Remove Karma browser test runner (deprecated since Apr 2023, no longer maintained; all crypto logic uses node-forge which is pure JS — Vitest covers all code paths)
- Update GitHub Actions to v4, Node 22
