// Jest 30 migration note: All async tests had their done() callback patterns removed.
// Jest 30 does not allow mixing async/await with done() callbacks. Async functions that
// reject are automatically caught by Jest, so the try { ... done() } catch { done(err) }
// wrapper is no longer needed (or permitted).

/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  reporters: ['default', 'jest-junit'],
  roots: ['<rootDir>'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: 'tsconfig.json' }]
  },
  testMatch: ['<rootDir>/test/**/*.(test|spec).ts'],
  testTimeout: 10000,
};
