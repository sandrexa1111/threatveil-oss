import {test, expect, type Page} from '@playwright/test';

/**
 * The canonical demonstration, driven through the compressed experience.
 *
 * Journey C: a change arrives, Home surfaces it, the change review names the affected
 * claim and the ones that still hold, and Restore assurance brings the system back.
 * Journey D: a Passport is previewed, confirmed, shared, verified outside, and then
 * correctly reported as no longer current after the system changes again.
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

async function noOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
}

test('canonical demonstration: change, consequence, restore, gate and an externally verified passport',
  async ({page, browser}) => {
  test.setTimeout(240_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await route(page);
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Founder');
  await page.getByLabel('Email', {exact: true}).fill(`canonical-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization', {exact: true}).fill('Canonical demonstration');
  await page.getByRole('button', {name: 'Open local workspace'}).click();
  await page.waitForURL('**/app');

  // The example is reached from the one onboarding experience, not from a global route.
  await page.getByRole('button', {name: 'Explore an example'}).click();
  await expect(page.getByText('RUNNABLE · SYNTHETIC DATA ONLY')).toBeVisible();
  await page.getByRole('link', {name: 'Run the Finance example'}).click();
  await page.getByRole('button', {name: 'Prepare finance example'}).click();
  await page.waitForURL('**/systems/*/setup', {timeout: 90_000});
  const systemId = new URL(page.url()).pathname.split('/')[3];
  const status = page.getByRole('region', {name: 'System status'});

  // 1. Current.
  await page.getByRole('button', {name: 'Run finance baseline'}).first().click();
  await expect(status.getByText('Cleared', {exact: true})).toBeVisible({timeout: 120_000});
  await page.goto(`/app/systems/${systemId}`);
  await expect(page.getByLabel('System at a glance')).toContainText('3 of 3');
  await page.screenshot({path: '../../.local/browser-tests/canonical-cleared.png', fullPage: true});

  // 2. A tool permission changes outside code. 3. The exact consequence.
  // The synthetic controls sit behind one labelled disclosure on Overview, not in its body.
  await expect(page.getByRole('button', {name: 'Relax beneficiary approval'})).toBeHidden();
  await page.getByText('Synthetic example controls').click();
  await page.getByRole('button', {name: 'Relax beneficiary approval'}).click();
  await expect(status.getByText('Needs attention', {exact: true})).toBeVisible({timeout: 60_000});
  await expect(status).toContainText('Beneficiary update authority expanded');

  // JOURNEY C — Home carries the attention item without opening the system.
  await page.goto('/app');
  await expect(page.getByLabel('Attention summary')).toContainText('1 system needs attention');
  const item = page.locator('article').filter({hasText: 'Finance Agent'}).first();
  await expect(item).toContainText('Beneficiary update authority expanded');
  await page.screenshot({path: '../../.local/browser-tests/canonical-attention.png', fullPage: true});
  await item.getByRole('link', {name: 'Review change'}).click();
  await page.waitForURL(`**/systems/${systemId}/activity`);

  // The change review names what is affected and what still holds, on one page.
  await expect(page.getByRole('heading', {name: 'Beneficiary update authority expanded'}).first()).toBeVisible();
  await expect(page.getByText('Still current').first()).toBeVisible();
  await expect(page.getByText('Needs fresh evidence', {exact: true}).first()).toBeVisible();
  // The full reasoning stays one disclosure away.
  await page.getByText('Why ThreatVeil concluded this').first().click();
  await expect(page.getByText('2 other claims remain supported.').first()).toBeVisible();
  await page.screenshot({path: '../../.local/browser-tests/canonical-change-review.png', fullPage: true});

  // Authority movement lives with the system's capabilities, not in a global section.
  await page.goto(`/app/systems/${systemId}/capabilities`);
  await expect(page.getByText('Authority expanded', {exact: true}).first()).toBeVisible();
  await expect(page.getByText('approval_required = false').first()).toBeVisible();
  await page.screenshot({path: '../../.local/browser-tests/canonical-authority-diff.png', fullPage: true});

  // The system map is a secondary visualization of the same system.
  await page.goto(`/app/systems/${systemId}/map`);
  await page.getByRole('button', {name: /Beneficiary changes require finance approval/}).first().click();
  await expect(page.getByText('depends on').first()).toBeVisible();

  // 4. Restore assurance, reached contextually: failure, broken useful work, restored.
  await page.goto(`/app/systems/${systemId}`);
  await page.getByRole('link', {name: 'Restore assurance'}).first().click();
  await page.waitForURL(`**/systems/${systemId}/restore`);
  await expect(page.getByRole('heading',
    {name: 'What must be re-established before this system is current again.'})).toBeVisible();
  await page.getByRole('button', {name: 'A · Re-prove with approval relaxed'}).click();
  await expect(page.getByText('Security failed: not cleared.')).toBeVisible({timeout: 120_000});
  await page.getByRole('button', {name: 'B · Try a fix that disables updates'}).click();
  await expect(page.getByText('Security held, but useful work broke: not cleared.')).toBeVisible({timeout: 120_000});
  await page.getByRole('button', {name: /C · Restore approval and re-prove/}).click();
  await expect(page.getByText('Clearance restored.')).toBeVisible({timeout: 120_000});
  await expect(status.getByText('Cleared', {exact: true})).toBeVisible();

  // 5. The machine-consumable answer, contextual to the system.
  await page.goto(`/app/systems/${systemId}`);
  const gate = page.getByRole('region', {name: 'Assurance Gate'});
  await expect(gate.getByText('Cleared', {exact: true})).toBeVisible();
  await expect(gate.getByText(/never grants permission/)).toBeVisible();
  await expect(gate.getByText(/assurance\/current/)).toBeVisible();
  // The full consumer configuration lives on Integrations, not duplicated on the system.
  await page.goto(`/app/integrations?system=${systemId}`);
  await expect(page.getByText(/UNKNOWN never means authorization/)).toBeVisible();
  await expect(page.locator('#assurance-gate').getByText(/assurance\/current/).first()).toBeVisible();

  // JOURNEY D — a Passport is previewed, confirmed and verified by an outside party.
  await page.goto(`/app/systems/${systemId}/share`);
  await page.getByRole('button', {name: 'Issue a signed passport'}).click();
  await expect(page.getByLabel('Current Assurance Passport')).toBeVisible({timeout: 60_000});
  await page.getByRole('button', {name: 'Review what would be shared'}).click();
  await expect(page.getByLabel('What would be shared')).toBeVisible();
  await expect(page.getByText(/Withheld from the signed document/)).toBeVisible();
  await page.screenshot({path: '../../.local/browser-tests/canonical-disclosure.png', fullPage: true});
  await page.getByRole('button', {name: 'I reviewed this · create the link'}).click();
  const link = await page.locator('code').filter({hasText: '/passport/'}).first().textContent();
  expect(link).toContain('/passport/');

  const outsider = await browser.newContext({viewport: {width: 1280, height: 900}});
  const external = await outsider.newPage();
  external.on('pageerror', e => errors.push(e.message));
  await route(external);
  await external.goto(new URL(link!).pathname);
  await expect(external.getByText(/Current status: Still current/)).toBeVisible();
  await external.getByRole('button', {name: 'Verify authenticity in this browser'}).click();
  await expect(external.getByText(/Authentic: signed by key/)).toBeVisible();

  // The system changes again: the passport stays authentic and stops being current.
  await page.goto(`/app/systems/${systemId}/activity`);
  await page.getByRole('button', {name: 'Relax beneficiary approval'}).click();
  await expect(page.getByRole('heading', {name: 'Beneficiary update authority expanded'}).first())
    .toBeVisible({timeout: 60_000});
  await external.reload();
  await expect(external.getByText(/Current status: Superseded by a later change/)).toBeVisible();
  await external.getByRole('button', {name: 'Verify authenticity in this browser'}).click();
  await expect(external.getByText(/Authentic: signed by key/)).toBeVisible();
  await external.screenshot({path: '../../.local/browser-tests/canonical-passport-superseded.png', fullPage: true});

  // 6. A customer's judgement about a consequence changes nothing about it.
  await page.getByRole('button', {name: 'Correct', exact: true}).first().click();
  await expect(page.getByText(/Recorded beside this consequence/).first()).toBeVisible();

  // Claims and dependency mapping live with the system they belong to.
  await page.goto(`/app/systems/${systemId}/claims`);
  await expect(page.getByRole('heading', {name: 'What must stay true'})).toBeVisible();
  // Levels stay distinct and canonical, but raw enum names are not body copy.
  await expect(page.getByText('DECLARED, NOT_YET_VERIFIED, QUALIFIED and CURRENT')).toHaveCount(0);
  await expect(page.locator('[title^="Canonical status: CURRENT"]').first()).toBeVisible();
  await page.goto(`/app/systems/${systemId}/evidence`);
  await page.getByText('Dependency mapping — which source facts control which claims').click();
  await expect(page.getByRole('heading',
    {name: 'Only an approved mapping narrows which claims a change reaches.'})).toBeVisible();

  for (const target of [page, external]) {
    await target.setViewportSize({width: 390, height: 844});
    await noOverflow(target);
  }
  await page.goto(`/app/systems/${systemId}/capabilities`);
  await noOverflow(page);
  await page.goto('/app');
  await noOverflow(page);
  await outsider.close();
  expect(errors).toEqual([]);
});
