import {test, expect, type Page} from '@playwright/test';

/** Accessibility checks over the canonical surfaces: landmarks, names, focus, keyboard. */
async function audit(page: Page, label: string) {
  const findings = await page.evaluate(() => {
    const problems: string[] = [];
    // Every interactive control needs an accessible name.
    for (const el of Array.from(document.querySelectorAll('button, a[href], select, input, textarea, summary'))) {
      const node = el as HTMLElement;
      if (node.closest('[aria-hidden="true"]') || node.offsetParent === null) continue;
      const label = (node.getAttribute('aria-label') || node.getAttribute('title') ||
        node.textContent || '').trim() ||
        (node.id ? (document.querySelector(`label[for="${node.id}"]`)?.textContent || '') : '') ||
        (node.closest('label')?.textContent || '');
      if (!label.trim()) problems.push(`unnamed ${node.tagName.toLowerCase()}: ${node.outerHTML.slice(0, 90)}`);
    }
    // Headings must not skip a level.
    const levels = Array.from(document.querySelectorAll('h1,h2,h3,h4')).map(h => Number(h.tagName[1]));
    for (let i = 1; i < levels.length; i++) if (levels[i] - levels[i - 1] > 1) problems.push(`heading jump h${levels[i - 1]}→h${levels[i]}`);
    // One main landmark, and navigation landmarks named when there is more than one.
    if (document.querySelectorAll('main').length !== 1) problems.push('expected exactly one main landmark');
    const navs = Array.from(document.querySelectorAll('nav'));
    if (navs.length > 1) for (const nav of navs) {
      if (!nav.getAttribute('aria-label') && !nav.getAttribute('aria-labelledby')) problems.push('unnamed nav landmark');
    }
    // Status must never be conveyed by colour alone: each pill carries a word.
    for (const pill of Array.from(document.querySelectorAll('[data-tone]'))) {
      if (!(pill.textContent || '').trim()) problems.push('tone element with no text');
    }
    return problems;
  });
  expect(findings, `${label}: ${findings.join(' | ')}`).toEqual([]);
}

test('the canonical surfaces are keyboard reachable and correctly labelled', async ({page}) => {
  test.setTimeout(240_000);
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Access owner');
  await page.getByLabel('Email', {exact: true}).fill(`a11y-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization', {exact: true}).fill('Accessibility acceptance');
  await page.getByRole('button', {name: 'Open local workspace'}).click();
  await page.waitForURL('**/app');
  await audit(page, '/app (zero state)');

  await page.goto('/app/systems/new?example=finance');
  await page.getByRole('button', {name: 'Prepare finance example'}).click();
  await page.waitForURL('**/systems/*/setup', {timeout: 90_000});
  const id = new URL(page.url()).pathname.split('/')[3];
  await page.getByRole('button', {name: 'Run finance baseline'}).first().click();
  await expect(page.getByRole('region', {name: 'System status'}).getByText('Cleared', {exact: true}))
    .toBeVisible({timeout: 120_000});

  for (const route of ['/app', '/app/systems', `/app/systems/${id}`, `/app/systems/${id}/capabilities`,
                       `/app/systems/${id}/claims`, `/app/systems/${id}/evidence`, `/app/systems/${id}/activity`,
                       `/app/systems/${id}/share`, `/app/systems/${id}/setup`, '/app/changes',
                       '/app/changes/propose', '/app/integrations']) {
    await page.goto(route);
    await page.waitForTimeout(900);
    await audit(page, route);
  }

  // The skip link is the first stop, and it reaches main content.
  await page.goto('/app');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', {name: 'Skip to content'})).toBeFocused();

  // System tabs are links, so they are reachable and activated from the keyboard.
  await page.goto(`/app/systems/${id}`);
  const tab = page.getByRole('navigation', {name: 'System sections'}).getByRole('link', {name: 'Evidence'});
  await tab.focus();
  await expect(tab).toBeFocused();
  await page.keyboard.press('Enter');
  await page.waitForURL(`**/systems/${id}/evidence`);

  // The system switcher opens and closes from the keyboard.
  await page.goto('/app/systems/new');
  await page.getByRole('button', {name: 'Advanced manual setup'}).click();
  await page.getByLabel('System name').fill('Second system');
  await page.getByLabel('What useful work does it do?').fill('A second consequential workflow for switcher coverage.');
  await page.getByLabel('Operating boundary').fill('Staging only.');
  const identity = await (await page.request.get('/api/backend/v1/auth/me')).json();
  await page.request.post('/api/backend/v1/commercial/subscription', {
    data: {action: 'upgrade', plan: 'pro', idempotency_key: `a11y-${Date.now()}`},
    headers: {'x-csrf-token': identity.csrf_token, origin: new URL(page.url()).origin}});
  await page.getByRole('button', {name: 'Connect system'}).click();
  await page.waitForURL('**/systems/*/claims', {timeout: 60_000});
  const switcher = page.getByRole('button', {name: 'Second system'});
  await switcher.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('listbox', {name: 'Switch protected system'})).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('listbox', {name: 'Switch protected system'})).toHaveCount(0);
});
