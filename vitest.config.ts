import { defineConfig } from 'vitest/config';

// Unit tests live in src/**/*.test.ts. The Playwright accessibility suite in
// e2e/ must NOT be collected by vitest (it uses @playwright/test's runner).
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
