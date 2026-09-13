import { defineConfig } from '@playwright/test';

// Screenshot capture for design review (the §25 contact sheet), kept apart from the acceptance
// suite in ../tests so `playwright test` never runs a twenty-screen capture by accident.
//   TV_TEST_WEB_URL=http://127.0.0.1:3000 npx playwright test --config redesign-capture/playwright.config.ts final-capture
//   SHEET_DIR=<shots> npx playwright test --config redesign-capture/playwright.config.ts contact-sheet
export default defineConfig({
  testDir: '.', fullyParallel: false, workers: 1, timeout: 900_000,
  use: { baseURL: process.env.TV_TEST_WEB_URL || 'http://127.0.0.1:3000', headless: true, viewport: { width: 1440, height: 1000 } },
  outputDir: '../../../.local/redesign-capture-output', reporter: 'list',
});
