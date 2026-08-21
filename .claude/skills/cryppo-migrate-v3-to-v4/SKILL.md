---
name: cryppo-migrate-v3-to-v4
description: 'Migrate a consumer codebase from @meeco/cryppo v3 to v4 (the WebCrypto migration): add `await` at now-async call sites, flag removed password-protected-private-key usage for manual review, bump the dependency, and verify with typecheck/tests. Triggers: "migrate to cryppo v4", "upgrade @meeco/cryppo to v4", "migrate cryppo v3 to v4", "update to the new cryppo", "cryppo webcrypto migration".'
allowed-tools: Read, Edit, Grep, Glob, Bash(npm:*), Bash(git:*), Bash(tsc:*)
---

# Skill: Migrate a consumer of @meeco/cryppo from v3 to v4

v4 replaced `node-forge` with native WebCrypto (`crypto.subtle`) for every cryptographic
primitive. This skill runs in the **consumer's** repository (not cryppo-js itself) and fixes
the two breaking changes that are mechanical, then reports the rest for manual review. See
`@meeco/cryppo`'s `CHANGELOG.md` (4.0.0 entry) for full background on *why* each change
happened — this skill only covers *how to adapt to it*.

Only run this if the target repo actually imports from `@meeco/cryppo` and is currently on
`^3.x` (check `package.json`). If it's already on `^4.x`, say so and stop.

## Phase 1: Find call sites

These 7 functions became `async` (previously synchronous) in v4 — nothing else in the public
API changed shape:

- `signWithPrivateKey`
- `verifyWithPublicKey`
- `keyLengthFromPublicKeyPem`
- `keyLengthFromPrivateKeyPem`
- `hmacSha256Digest`
- `encryptWithKeyUsingArtefacts`
- `decryptWithKeyUsingArtefacts`

Grep the repo (excluding `node_modules`) for each name to find every call site and every
import from `@meeco/cryppo`. Separately, grep for `encryptPrivateKeyWithPassword` (removed
entirely in v4) and for calls to `decryptWithPrivateKey`/`decryptSerializedWithPrivateKey`
that pass a `password` field (that parameter was removed).

Report counts before changing anything, so the user knows the scope.

## Phase 2: Fix the async call sites

For each call site found in Phase 1 (the 7 functions):

1. Add `await` immediately before the call expression.
2. If the call isn't already inside a function marked `async`, mark the enclosing function
   `async` too.

Don't try to statically trace the full cascade by hand (a caller three levels up may also
need to become `async`, and in a large codebase that's easy to miss or over-apply). Instead,
after making the direct edits from step 1–2:

3. Run the project's typecheck (`npx tsc --noEmit`, or whatever script `package.json` defines
   — check for `typecheck`/`build`/`tsc` scripts first). TypeScript will report every caller
   that now needs `await`/`async` propagated further up the chain (e.g. "await has no effect
   on this type" is fine to ignore, but "Property does not exist" / "This expression is not
   callable" / a `Promise<T>` being used where `T` was expected are exactly the propagation
   signal you're looking for).
4. Fix each reported site the same way (add `await`, mark enclosing function `async`), and
   re-run typecheck. Repeat until clean.
5. If the repo is plain JavaScript with no typecheck to lean on, do the best static trace you
   can from the Phase 1 call sites, then rely on the test suite (Phase 4) and a careful manual
   read of anything that returns one of these 7 functions' results synchronously (e.g. stores
   it, compares it, or returns it from a non-async function) — those are the cases a
   type-checker would have caught automatically.

## Phase 3: Report (don't auto-fix) the removed password feature

`encryptPrivateKeyWithPassword` is gone, and `decryptWithPrivateKey`/
`decryptSerializedWithPrivateKey` no longer accept a `password` parameter — this
password-protected an RSA private key PEM as PKCS#8 `EncryptedPrivateKeyInfo`, which
WebCrypto has no API to build or parse. There's no drop-in replacement, so **don't attempt to
auto-fix this** — list every usage site (file:line) found in Phase 1 and let the user decide:
keep that specific code path on `@meeco/cryppo@^3`, drop it if it's dead code, or design a
replacement (e.g. storing the private key encrypted at rest some other way).

## Phase 4: Bump the dependency and verify

1. Update `@meeco/cryppo` to `^4.0.0` in `package.json` (match the existing version-range
   style — if it was pinned exactly before, pin exactly now), then run `npm install`.
2. Run the typecheck/build/lint scripts.
3. Run the test suite. If any test asserts on the return value of one of the 7 functions
   without `await`ing it (e.g. `expect(signWithPrivateKey(...)).toEqual(...)`), that's a real
   bug the migration needs to fix in the test too, not something to skip.

## Phase 5: Flag the non-code-level changes

These aren't things this skill can fix in code — just surface them so the user can judge
whether they matter for this specific deployment:

- **Browser support floor**: v4 requires the Web Crypto API (`crypto.subtle`), a native
  browser API — v3's `node-forge` was pure JS and worked anywhere. In practice this excludes
  only browsers roughly a decade or older (see `@meeco/cryppo`'s README `Requirements`
  section for exact versions/dates) and Internet Explorer. If this consumer has done
  deliberate work to support old browsers or specific old devices, that's worth a second look
  before shipping this upgrade — check for any browserslist config, polyfill setup, or
  documented device-support commitments in this repo.
- **Node**: no new constraint — `crypto.subtle` has been a stable Node global since Node 19,
  and `@meeco/cryppo` has required Node ≥22 since a prior release.

## Reporting

At the end, summarize: how many call sites were fixed automatically, how many
password-feature usages need manual decisions (with file:line list), whether
typecheck/build/tests are green, and a one-line reminder about the browser support floor.
