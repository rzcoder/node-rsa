import { defineConfig, devices } from '@playwright/test';

// Single-project Playwright config: spin up Vite, point the test at the
// served page, run on Chromium. The CI flag flips reuseExistingServer so a
// developer running `npm test` locally with a live `npm run dev` instance
// gets quick re-runs instead of port-conflict errors.
export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  retries: 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:5174',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run dev',
    port: 5174,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
