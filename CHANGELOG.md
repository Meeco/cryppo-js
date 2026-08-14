# Changelog

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
