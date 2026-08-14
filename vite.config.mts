import { defineConfig } from 'vitest/config';

export default defineConfig({
  server: {
    open: '/demo/encryption_with_derived_key.html'
  },
  test: {
    include: ['test/**/*.{test,spec}.ts'],
    testTimeout: 10000,
    globals: true
  }
});
