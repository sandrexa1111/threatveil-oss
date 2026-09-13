import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests', fullyParallel: false, workers: 1, timeout: 60_000,
  use: { baseURL: process.env.TV_TEST_WEB_URL || 'http://127.0.0.1:3000', headless: true, viewport: { width: 1440, height: 1000 },
    screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  outputDir: '../../.local/browser-tests', reporter: 'list',
});
