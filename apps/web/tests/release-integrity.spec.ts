import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';

const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function login(page: Page, organization: string) {
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Release owner');
  await page.getByLabel('Email', { exact: true }).fill(`release-${Date.now()}-${Math.random()}@local.invalid`);
  await page.getByLabel('Organization', { exact: true }).fill(organization);
  await page.getByRole('button', { name: 'Open local workspace' }).click();
  await page.waitForURL('**/app');
  await page.goto('/app/demo');
  await page.getByRole('button', { name: 'Prepare demo fixtures' }).click();
  await expect(page.getByRole('button', { name: /02 · Fixed/ })).toBeVisible();
  // A blocking gate is a paid capability; this suite exercises gate semantics.
  const upgrade = await page.request.post('/api/backend/v1/commercial/subscription', {
    data: { action: 'upgrade', plan: 'pro', idempotency_key: `browser-${Date.now()}` },
    headers: { 'x-csrf-token': await csrf(page), origin: new URL(page.url()).origin },
  });
  expect(upgrade.status()).toBe(200);
}

async function csrf(page: import('@playwright/test').Page) {
  return (await (await page.request.get('/api/backend/v1/auth/me')).json()).csrf_token as string;
}

test('candidate change voids prior proof, re-proof blocks regression, and a useful fix allows a signed release', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await login(page, 'Release integrity browser acceptance');
  await page.getByRole('button', { name: /02 · Fixed/ }).click();
  await page.waitForURL('**/runs/*');
  const runId = page.url().split('/').at(-1)!;
  const established = await (await page.request.get(`/api/backend/v1/runs/${runId}`)).json();
  expect(established.security_verdict).toBe('PASS');
  expect(established.task_outcome).toBe('SUCCESS');
  const previous = structuredClone(established.fingerprint);
  const changed = structuredClone(established.fingerprint);
  const candidate = { ...established.candidate, version: 'regressed', digest: hash({ fixture: 'procurement-v1', version: 'regressed' }) };
  for (const component of changed.components) {
    if (['application', 'permissions'].includes(component.type)) {
      component.version = 'regressed';
      component.digest = component.type === 'application' ? candidate.digest : hash('regressed');
    }
  }
  async function plan(identity: unknown, fingerprint: unknown, previousFingerprint: unknown) {
    await page.goto('/app/impact');
    await page.locator('.plan-creator > summary').click();
    await page.getByLabel('Plan candidate identity', { exact: true }).fill(JSON.stringify(identity));
    await page.getByLabel('Candidate proof fingerprint', { exact: true }).fill(JSON.stringify(fingerprint));
    await page.getByLabel('Previous proof fingerprint', { exact: true }).fill(JSON.stringify(previousFingerprint));
    const saved = page.waitForResponse(r => r.url().endsWith('/v1/proof-plans') && r.request().method() === 'POST');
    await page.getByRole('button', { name: 'Create re-proof plan', exact: true }).click();
    const response = await saved;
    expect(response.status()).toBe(201);
    await expect(page.getByRole('region', { name: 'Selected integrity record' })).toBeVisible();
    return response.json();
  }
  async function release(expected: string) {
    const detail = page.getByRole('region', { name: 'Selected integrity record' });
    await detail.getByLabel('Release policy mode').selectOption('BLOCK');
    const saved = page.waitForResponse(r => r.url().endsWith('/v1/releases') && r.request().method() === 'POST');
    await detail.getByRole('button', { name: 'Record release decision' }).click();
    const response = await saved;
    expect(response.status()).toBe(201);
    const record = await response.json();
    expect(record.release_action).toBe(expected);
    await expect(detail.getByRole('heading', { name: 'Why this release decision happened' })).toBeVisible();
    await expect(detail.getByRole('button', { name: 'Export receipt' })).toBeVisible();
    return record;
  }
  const a = await plan(established.candidate, previous, previous);
  expect(a.obligations).toHaveLength(0);
  await release('ALLOW');
  const b = await plan(candidate, changed, previous);
  expect(b.invalidations.some((r: { status: string }) => r.status === 'VOID')).toBe(true);
  const detail = page.getByRole('region', { name: 'Selected integrity record' });
  await expect(detail.locator('.status').filter({ hasText: /^VOID$/ })).toBeVisible();
  await detail.getByRole('button', { name: 'Configure re-proof run' }).click();
  expect(JSON.parse(await page.getByRole('dialog').getByLabel('Execution fingerprint (JSON)').inputValue())).toEqual(b.fingerprint);
  await page.getByRole('dialog').getByRole('button', { name: 'Execute run', exact: true }).click();
  await page.waitForURL('**/runs/*');
  await expect(page.locator('.verdict-grid article').nth(0)).toContainText('FAIL');
  await page.goto('/app/releases');
  await page.getByRole('region', { name: 'Re-proof plans' }).getByRole('row').filter({ hasText: 'regressed' }).getByRole('button', { name: 'Inspect plan' }).click();
  const blocked = await release('BLOCK');
  await expect(detail).toContainText('FAIL');
  await page.goto('/app/demo');
  await page.getByRole('button', { name: /02 · Fixed/ }).click();
  await page.waitForURL('**/runs/*');
  await plan(established.candidate, previous, changed);
  const allowed = await release('ALLOW');
  const download = page.waitForEvent('download');
  await detail.getByRole('button', { name: 'Export receipt' }).click();
  await (await download).saveAs('../../.local/release-integrity-browser-receipt.json');
  const receipt = await (await page.request.get(`/api/backend/v1/releases/${allowed.id}/receipt`)).json();
  expect(receipt.envelope.signatures).toHaveLength(1);
  expect(receipt.envelope.payloadType).toBe('application/vnd.in-toto+json');
  await page.goto('/app/evidence');
  await page.getByRole('button', { name: 'Inspect evidence', exact: true }).first().click();
  await expect(detail.getByText('Proof scope, dependency bindings, and provenance', { exact: false })).toBeVisible();
  await expect(detail.getByRole('link', { name: 'Inspect authoritative observations' })).toBeVisible();
  await page.goto(`/app/releases?release=${allowed.id}`);
  await expect(page.getByRole('region', { name: 'Release timeline' }).locator('.release-event')).toHaveCount(3);
  await expect(detail).toContainText('Current applicability: ALLOW');
  await page.screenshot({ path: '../../.local/release-integrity-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.screenshot({ path: '../../.local/release-integrity-mobile.png', fullPage: true });
  expect((await (await page.request.get(`/api/backend/v1/releases/${blocked.id}`)).json()).release_action).toBe('BLOCK');
  const identity = await (await page.request.get('/api/backend/v1/auth/me')).json();
  const revoked = await page.request.post(`/api/backend/v1/targets/${established.target_id}/revoke`, { data: {}, headers: { origin: process.env.TV_TEST_WEB_URL || 'http://127.0.0.1:3000', 'x-csrf-token': identity.csrf_token } });
  expect(revoked.status()).toBe(200);
  await page.goto('/app/releases');
  await page.locator('.release-event').first().click();
  await expect(detail).toContainText('Current applicability: BLOCK');
  await expect(detail.locator('.release-outcome').first()).toContainText('ALLOW');
  expect(errors).toEqual([]);
});

test('Integrity Launch preserves scope, records actual effort, and keeps unverified installation and payment explicit', async ({ page }) => {
  await login(page, 'Integrity Launch browser acceptance');
  await page.goto('/app/gauntlet');
  await page.getByRole('button', { name: 'New Integrity Launch', exact: true }).click();
  await page.getByLabel('Integrity Launch name').fill('Procurement WARN launch');
  await page.getByLabel('Agreed scope').fill('One staging procurement workflow with a reviewed payment boundary and WARN release integration.');
  await page.getByRole('dialog').getByRole('checkbox', { name: 'Untrusted documents cannot change beneficiary details' }).check();
  await page.getByRole('button', { name: 'Create Integrity Launch', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await page.getByRole('button', { name: 'Open launch' }).click();
  const detail = page.getByRole('region', { name: 'Selected Integrity Launch' });
  await expect(detail).toContainText('NO CONFIRMED PAYMENT');
  await detail.getByLabel('Actual minutes').fill('45');
  await detail.getByLabel('Work category').selectOption('observation');
  await detail.getByLabel('Completed work note').fill('Configured the staging ledger collector and reviewed its authority boundary.');
  await detail.getByRole('button', { name: 'Record implementation time' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Procurement WARN launch' })).toContainText('0.75 hours');
  await detail.getByLabel('Launch event').selectOption('scope_reviewed');
  await detail.getByLabel('Launch review note').fill('Reviewed permitted staging effects and the initial property scope.');
  await detail.getByRole('checkbox', { name: 'I reviewed this implementation note and its scope.' }).check();
  await detail.getByRole('button', { name: 'Record launch review' }).click();
  await expect(detail.locator('.launch-milestones > div').filter({ hasText: 'Scope reviewed by security owner' })).toContainText('RECORDED');
  await expect(detail.locator('.launch-milestones > div').filter({ hasText: 'Live WARN check delivery verified' })).toContainText('PENDING');
  await expect(detail).toContainText('NO CONFIRMED PAYMENT');
  await page.screenshot({ path: '../../.local/integrity-launch-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.screenshot({ path: '../../.local/integrity-launch-mobile.png', fullPage: true });
});
