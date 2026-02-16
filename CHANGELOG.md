# Changelog

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
