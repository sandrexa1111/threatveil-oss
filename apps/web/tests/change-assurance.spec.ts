import {test, expect, type Page} from '@playwright/test';

/**
 * The finance boundary's assurance semantics, driven through the compressed product.
 *
 * The six-stage workflow still exists — it is the advanced setup behind one disclosure
 * on the system's setup checklist — and the semantics it establishes are unchanged:
 * a security failure blocks, a fix that breaks useful work also blocks, and enforcement
 * acknowledgement stays separate from the decision that authorised it.
 */

async function route(page: Page) {
  if (!process.env.TV_TEST_API_URL) return;
  await page.route('**/api/backend/v1/**', async request => {
    const incoming = request.request(), source = new URL(incoming.url());
    const target = new URL(source.pathname.replace('/api/backend/', '/') + source.search, process.env.TV_TEST_API_URL);
    const headers = {...incoming.headers()}; delete headers.host;
    const response = await page.request.fetch(target.toString(),
      {method: incoming.method(), headers, data: incoming.postDataBuffer() ?? undefined});
    await request.fulfill({response});
  });
}

async function login(page: Page, label: string) {
  await route(page);
  await page.goto('/login');
  await page.getByLabel('Your name').fill(`${label} owner`);
  await page.getByLabel('Email', {exact: true}).fill(`${label}-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization', {exact: true}).fill(`${label} acceptance`);
  await page.getByRole('button', {name: 'Open local workspace'}).click();
  await page.waitForURL('**/app');
}

test('finance journey retains failures, useful work and exact acknowledged activation', async ({page}) => {
  test.setTimeout(240_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'finance-browser');

  await page.goto('/app/systems/new?example=finance');
  await page.getByRole('button', {name: 'Prepare finance example'}).click();
  await page.waitForURL('**/systems/*/setup', {timeout: 90_000});
  const systemId = new URL(page.url()).pathname.split('/')[3];
  const status = page.getByRole('region', {name: 'System status'});

  await page.getByRole('button', {name: 'Run finance baseline'}).first().click();
  await expect(status.getByText('Cleared', {exact: true})).toBeVisible({timeout: 120_000});

  // The full authority, claim and baseline workflow remains available behind one disclosure.
  const advanced = page.getByText('Advanced setup — the full authority, claim and baseline workflow');
  await advanced.click();
  const journey = page.locator('nav[aria-label="Protection journey"]');
  await expect(journey).toBeVisible();
  await journey.getByRole('button', {name: /Decide/}).click();
  await expect(page.getByRole('heading', {name: 'Every claim is still supported.'}).first()).toBeVisible();
  await expect(page.getByText('NOT REQUESTED', {exact: true})).toBeVisible();

  // Enforcement acknowledgement is separate from the decision that authorised it.
  await page.getByRole('button', {name: 'Request sandbox activation'}).click();
  await expect(page.getByRole('button', {name: 'Sandbox activation acknowledged'})).toBeDisabled();
  await page.screenshot({path: '../../.local/browser-tests/finance-protected-desktop.png', fullPage: true});

  /** Each sandbox change happens on Activity, where its consequence is recorded. */
  async function reprove(action: string) {
    await page.goto(`/app/systems/${systemId}/restore`);
    await page.getByRole('button', {name: action}).click();
  }

  await reprove('A · Re-prove with approval relaxed');
  await expect(page.getByText('Security failed: not cleared.')).toBeVisible({timeout: 120_000});
  await expect(status.getByText('Not cleared', {exact: true})).toBeVisible();

  await reprove('B · Try a fix that disables updates');
  await expect(page.getByText('Security held, but useful work broke: not cleared.')).toBeVisible({timeout: 120_000});
  // A security PASS with a broken legitimate task never offers activation.
  await page.goto(`/app/systems/${systemId}/setup`);
  await page.getByText('Advanced setup — the full authority, claim and baseline workflow').click();
  await page.locator('nav[aria-label="Protection journey"]').getByRole('button', {name: /Decide/}).click();
  await expect(page.getByText('FAILURE', {exact: true}).first()).toBeVisible();
  await expect(page.getByRole('button', {name: 'Request sandbox activation'})).toHaveCount(0);

  await reprove('C · Restore approval and re-prove');
  await expect(page.getByText('Clearance restored.')).toBeVisible({timeout: 120_000});
  await expect(status.getByText('Cleared', {exact: true})).toBeVisible();

  await page.goto(`/app/systems/${systemId}/setup`);
  await page.getByText('Advanced setup — the full authority, claim and baseline workflow').click();
  await page.locator('nav[aria-label="Protection journey"]').getByRole('button', {name: /Decide/}).click();
  await page.getByRole('button', {name: 'Request sandbox activation'}).click();
  await expect(page.getByRole('button', {name: 'Sandbox activation acknowledged'})).toBeDisabled();
  const download = page.waitForEvent('download');
  await page.getByRole('button', {name: 'Export signed scoped record'}).click();
  expect((await download).suggestedFilename()).toMatch(/\.dsse\.json$/);

  await page.setViewportSize({width: 390, height: 844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.screenshot({path: '../../.local/browser-tests/finance-protected-mobile.png', fullPage: true});
  expect(errors).toEqual([]);
});

test('signed records and the published trust root stay available to a third party', async ({page}) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'trust-root');

  // Reached from Settings → Developer tools, and still at its own URL.
  await page.goto('/app/settings/developer');
  await page.getByRole('link', {name: /Signed records & trust root/}).click();
  await page.waitForURL('**/app/records');
  await expect(page.getByRole('heading', {name: 'Anyone can verify these records.'})).toBeVisible();
  await expect(page.locator('.card').filter({hasText: 'Anyone can verify these records.'})
    .getByText('ACTIVE', {exact: true}).first()).toBeVisible();

  await page.setViewportSize({width: 390, height: 844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  expect(errors).toEqual([]);
});
