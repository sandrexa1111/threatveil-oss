import {test, expect, type Page} from '@playwright/test';

/**
 * Acceptance for the compressed product experience.
 *
 * Journeys A, B, E and F: a new organization meets one onboarding experience, an
 * existing current system reads as current from Home, several systems keep their
 * context, and old bookmarks still land on the canonical surface.
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

/** The example is the only runnable system, so every journey that needs one starts here. */
async function financeSystem(page: Page) {
  await page.goto('/app/systems/new?example=finance');
  await page.getByRole('button', {name: 'Prepare finance example'}).click();
  await page.waitForURL('**/systems/*/setup', {timeout: 90_000});
  return new URL(page.url()).pathname.split('/')[3];
}

/** Two protected systems exceed the Free allowance, so capacity is raised explicitly. */
async function proPlan(page: Page) {
  const identity = await (await page.request.get('/api/backend/v1/auth/me')).json();
  const response = await page.request.post('/api/backend/v1/commercial/subscription', {
    data: {action: 'upgrade', plan: 'pro', idempotency_key: `ux-${Date.now()}`},
    headers: {'x-csrf-token': identity.csrf_token, origin: new URL(page.url()).origin}});
  expect(response.status()).toBe(200);
}

async function baseline(page: Page) {
  await page.getByRole('button', {name: 'Run finance baseline'}).first().click();
  await expect(page.getByRole('region', {name: 'System status'}).getByText('Cleared', {exact: true}))
    .toBeVisible({timeout: 120_000});
}

const NAV = ['Home', 'Systems', 'Changes', 'Integrations'];
// Capabilities that used to be global links, and must no longer be.
const RETIRED = ['System map', 'What it can do', 'Claims', 'What still holds', 'Re-establish',
  'Clearance', 'Passport', 'Sources', 'Advanced'];

test('JOURNEY A — a new organization meets one onboarding experience and reaches a real answer', async ({page}) => {
  test.setTimeout(180_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'journey-a');

  // Primary navigation is four product destinations and nothing else.
  const sidebar = page.locator('.sidebar');
  const primary = sidebar.getByRole('navigation', {name: 'Workspace navigation'});
  for (const label of NAV) await expect(primary.getByRole('link', {name: label, exact: true})).toBeVisible();
  for (const label of RETIRED) await expect(sidebar.getByRole('link', {name: label, exact: true})).toHaveCount(0);
  // No more than four core product destinations.
  await expect(primary.getByRole('link')).toHaveCount(NAV.length);

  // One onboarding experience: one action-led heading, one primary action, no marketing panel.
  await expect(page.getByRole('heading', {name: 'Protect your first AI system'})).toBeVisible();
  await expect(page.getByRole('link', {name: 'Import a definition'})).toBeVisible();
  await expect(page.getByRole('list', {name: 'How ThreatVeil works'}).getByRole('listitem')).toHaveCount(5);
  await expect(page.getByLabel('Import or connect from')).toContainText('Claude Code');
  await expect(page.getByText('CHANGE ASSURANCE FOR AI AGENTS')).toHaveCount(0);
  await expect(page.getByText('Protection journey')).toHaveCount(0);
  await page.screenshot({path: '../../.local/browser-tests/ux-home-zero.png', fullPage: true});

  // Onboarding is not repeated on unrelated routes.
  for (const other of ['/app/changes', '/app/integrations', '/app/billing']) {
    await page.goto(other);
    await expect(page.getByRole('heading', {name: 'Protect your first AI system'})).toHaveCount(0);
  }

  // 1 — CONNECT. Import first: ThreatVeil reads the definition before asking anything.
  await page.goto('/app/systems/new');
  await expect(page.getByLabel('System name')).toHaveCount(0);
  await page.getByRole('button', {name: 'Paste definition'}).click();
  await page.getByLabel('Paste a definition').fill(JSON.stringify({
    permissions: {allow: ['Bash(git:*)', 'mcp__payments__refund_issue'], deny: ['Bash(rm:*)']},
    model: 'claude-opus-5',
  }));
  await page.getByRole('button', {name: 'Read this definition'}).click();
  // What was detected is shown before any system exists, and nothing is inferred.
  await expect(page.getByRole('heading', {name: 'ThreatVeil found'})).toBeVisible({timeout: 30_000});
  await expect(page.getByText('mcp__payments__refund_issue', {exact: true})).toBeVisible();
  await page.getByLabel('System name').fill('Support refund agent');
  await page.getByLabel('What useful work does it do?').fill('Answers support tickets and issues refunds against the payments ledger.');
  await page.getByLabel('Operating boundary').fill('Staging tenant A support workflow and its refund tooling.');
  await page.getByRole('button', {name: 'Connect system'}).click();

  // 2 — DEFINE. Connecting lands on the claim the customer must now state.
  await page.waitForURL('**/systems/*/claims', {timeout: 60_000});
  const systemId = new URL(page.url()).pathname.split('/')[3];
  await expect(page.getByRole('heading', {name: 'What must stay true'})).toBeVisible();
  await expect(page.getByText('No claims defined.')).toBeVisible();
  await page.getByLabel('What does it govern?').fill('customer refunds');
  await page.getByRole('button', {name: 'Build a draft'}).click();
  await expect(page.getByRole('button', {name: 'Save declared claim'})).toBeVisible();
  await page.getByLabel('Declared dependencies (comma separated)').fill('permissions:approval, tool:mcp__payments__refund_issue');
  await page.getByRole('button', {name: 'Save declared claim'}).click();
  // A declared claim is never reported as supported.
  await expect(page.getByText('Needs evidence').first()).toBeVisible({timeout: 30_000});

  // 3 — CHECK. A proposed change is reachable and answers at claim level.
  await page.goto('/app');
  await page.getByRole('link', {name: 'Check a proposed change'}).click();
  await page.waitForURL('**/changes/propose');
  await expect(page.getByText('Check a change', {exact: true})).toBeVisible();
  await page.getByRole('button', {name: 'Paste candidate definition'}).click();
  await page.getByLabel('Candidate definition').fill(JSON.stringify({
    permissions: {allow: ['Bash(git:*)', 'mcp__payments__refund_issue', 'Bash(rm:*)'], deny: []},
    model: 'claude-opus-5',
  }));
  // Pasted text is read like an upload: the format is detected before anything is evaluated.
  await page.getByRole('button', {name: 'Read and check this change'}).click();
  await expect(page.getByRole('status').filter({hasText: 'Detected'})).toBeVisible({timeout: 30_000});
  await page.getByRole('button', {name: 'Check this change', exact: true}).click();
  const states = page.getByRole('region', {name: 'Assurance before and after'});
  await expect(states).toBeVisible({timeout: 60_000});
  // The dry run states, in as many words, that it changed nothing.
  await expect(page.getByText('This check reads only. It has not changed current assurance.')).toBeVisible();
  await expect(states.getByText('Current system')).toBeVisible();
  await expect(states.getByText('Unchanged by this check.')).toBeVisible();
  await expect(states.getByText('If shipped')).toBeVisible();
  await expect(page.getByRole('heading', {name: /security claim/})).toBeVisible();
  // Once a result exists the form folds away behind one disclosure.
  await expect(page.getByText('Check another change')).toBeVisible();
  await page.screenshot({path: '../../.local/browser-tests/ux-proposed-change.png', fullPage: true});
  expect(systemId).toBeTruthy();
  expect(errors).toEqual([]);
});

test('JOURNEY B — a current system reads as current from Home, and every tab opens', async ({page}) => {
  test.setTimeout(240_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'journey-b');
  const systemId = await financeSystem(page);
  await baseline(page);

  // Home answers "what needs my attention" without opening the system.
  await page.goto('/app');
  await expect(page.getByLabel('Attention summary')).toContainText('Every system is current');
  await expect(page.getByRole('heading', {name: 'Current systems'})).toBeVisible();
  await expect(page.getByRole('link', {name: /Finance Agent/})).toBeVisible();
  await page.screenshot({path: '../../.local/browser-tests/ux-home-current.png', fullPage: true});

  // Status is visible without navigating to a dedicated clearance page.
  await page.goto(`/app/systems/${systemId}`);
  const status = page.getByRole('region', {name: 'System status'});
  await expect(status.getByText('Cleared', {exact: true})).toBeVisible();
  await expect(page.getByLabel('System at a glance')).toContainText('3 of 3');
  await page.screenshot({path: '../../.local/browser-tests/ux-system-overview.png', fullPage: true});

  const tabs = page.getByRole('navigation', {name: 'System sections'});
  for (const [slug, label] of [['capabilities', 'Capabilities'], ['claims', 'Security claims'],
                               ['evidence', 'Evidence'], ['activity', 'Activity'], ['share', 'Share']]) {
    await tabs.getByRole('link', {name: label, exact: true}).click();
    await page.waitForURL(`**/systems/${systemId}/${slug}`);
    await expect(tabs.getByRole('link', {name: label, exact: true})).toHaveAttribute('aria-current', 'page');
    // The header keeps the same system context on every tab.
    await expect(status.getByRole('heading', {name: 'Finance Agent'})).toBeVisible();
  }
  // The system map is secondary: reachable from Overview, never a global destination.
  await page.goto(`/app/systems/${systemId}`);
  await page.getByRole('link', {name: 'System map'}).click();
  await page.waitForURL(`**/systems/${systemId}/map`);
  await expect(page.getByRole('heading', {name: /What makes up this system/})).toBeVisible();
  expect(errors).toEqual([]);
});

test('JOURNEY G — a claim is inspected in place, deep-linked, and the command menu reaches any system', async ({page}) => {
  test.setTimeout(240_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'journey-f');
  const systemId = await financeSystem(page);
  await baseline(page);

  // A claim opens in a side panel over the list rather than on a new route.
  await page.goto(`/app/systems/${systemId}/claims`);
  await page.getByRole('button', {name: /Beneficiary changes require finance approval/}).click();
  const drawer = page.getByRole('dialog');
  await expect(drawer.getByRole('heading', {name: 'Beneficiary changes require finance approval'})).toBeVisible();
  await expect(drawer.getByText('Must keep working')).toBeVisible();
  // Technical identifiers are present but behind Advanced.
  await expect(drawer.getByText('Claim ID')).toBeHidden();
  await drawer.getByText('Advanced').click();
  await expect(drawer.getByText('Claim ID')).toBeVisible();
  // ↓ walks to the adjacent claim without closing the panel, and the deep link follows.
  const firstClaim = new URL(page.url()).searchParams.get('claim');
  expect(firstClaim).toBeTruthy();
  await page.keyboard.press('ArrowDown');
  await expect.poll(() => new URL(page.url()).searchParams.get('claim')).not.toBe(firstClaim);
  await expect(drawer.getByRole('heading', {name: 'Beneficiary changes require finance approval'})).toHaveCount(0);
  await page.keyboard.press('ArrowUp');
  await expect.poll(() => new URL(page.url()).searchParams.get('claim')).toBe(firstClaim);
  await expect(drawer.getByRole('heading', {name: 'Beneficiary changes require finance approval'})).toBeVisible();
  // The open claim is a deep link that survives a reload.
  expect(new URL(page.url()).searchParams.get('claim')).toBeTruthy();
  await page.reload();
  await expect(page.getByRole('dialog').getByRole('heading', {name: 'Beneficiary changes require finance approval'})).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(new URL(page.url()).searchParams.get('claim')).toBeNull();

  // Cmd/Ctrl-K opens the command menu from anywhere and reaches a system by name.
  await page.goto('/app/integrations');
  await page.keyboard.press('ControlOrMeta+k');
  const menu = page.getByRole('dialog', {name: 'Command menu'});
  await expect(menu).toBeVisible();
  await menu.getByRole('combobox').fill('finance');
  // The system appears under Recent as well as Systems once it has been visited.
  await expect(menu.getByRole('option', {name: /Finance Agent/}).first()).toBeVisible();
  await page.keyboard.press('Enter');
  await page.waitForURL(`**/systems/${systemId}`);
  await expect(page.getByRole('dialog', {name: 'Command menu'})).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('JOURNEY E — several systems: Home prioritises attention and context never crosses over', async ({page}) => {
  test.setTimeout(240_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'journey-e');
  const finance = await financeSystem(page);
  await baseline(page);
  await proPlan(page);

  // A second system, declared only: it has no baseline, so it is never called cleared.
  await page.goto('/app/systems/new');
  await page.getByRole('button', {name: 'Advanced manual setup'}).click();
  await page.getByLabel('System name').fill('Infrastructure agent');
  await page.getByLabel('What useful work does it do?').fill('Applies reviewed infrastructure changes to the staging project.');
  await page.getByLabel('Operating boundary').fill('Staging project only; no production deployment.');
  await page.getByRole('button', {name: 'Connect system'}).click();
  await page.waitForURL('**/systems/*/claims', {timeout: 60_000});
  const second = new URL(page.url()).pathname.split('/')[3];
  expect(second).not.toBe(finance);

  await page.goto('/app');
  await expect(page.getByLabel('Attention summary')).toContainText('1 system needs attention');
  const attention = page.getByRole('heading', {name: 'Needs attention'});
  await expect(attention).toBeVisible();
  // The system without a baseline is the one that needs attention; the cleared one does not.
  await expect(page.getByRole('link', {name: 'Infrastructure agent'})).toBeVisible();
  await expect(page.getByRole('heading', {name: 'Current systems'})).toBeVisible();
  await page.screenshot({path: '../../.local/browser-tests/ux-home-attention.png', fullPage: true});

  // Every non-current system exposes an obvious next action.
  await page.getByRole('link', {name: 'Set up assurance'}).click();
  await page.waitForURL(`**/systems/${second}/setup`);

  // The switcher moves context, and the tab travels with it.
  await page.goto(`/app/systems/${second}/claims`);
  await page.getByRole('button', {name: 'Infrastructure agent'}).click();
  await page.getByRole('option', {name: 'Finance Agent'}).click();
  await page.waitForURL(`**/systems/${finance}/claims`);
  await expect(page.getByRole('region', {name: 'System status'})
    .getByRole('heading', {name: 'Finance Agent'})).toBeVisible();
  // Context persists across a reload: a direct URL always wins.
  await page.reload();
  await expect(page).toHaveURL(new RegExp(`/systems/${finance}/claims$`));
  expect(errors).toEqual([]);
});

test('JOURNEY F — old bookmarks still land on the canonical surface', async ({page}) => {
  test.setTimeout(240_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'journey-f');
  const systemId = await financeSystem(page);

  for (const [legacy, canonical] of [
    ['/app/overview', '/app'],
    ['/app/map', `/app/systems/${systemId}/map`],
    ['/app/authority', `/app/systems/${systemId}/capabilities`],
    ['/app/claims', `/app/systems/${systemId}/claims`],
    ['/app/holds', `/app/systems/${systemId}/evidence`],
    ['/app/mappings', `/app/systems/${systemId}/evidence`],
    ['/app/reestablish', `/app/systems/${systemId}/restore`],
    ['/app/decisions', `/app/systems/${systemId}`],
    ['/app/passport', `/app/systems/${systemId}/share`],
    ['/app/assurance', `/app/systems/${systemId}/setup`],
    ['/app/sources', '/app/integrations'],
    ['/app/propose', '/app/changes/propose'],
    [`/app/reestablish/${systemId}`, `/app/systems/${systemId}/restore`],
    [`/app/passport/${systemId}`, `/app/systems/${systemId}/share`],
  ]) {
    await page.goto(legacy);
    await expect(page, `${legacy} should reach ${canonical}`).toHaveURL(new RegExp(`${canonical.replace(/\//g, '\\/')}$`), {timeout: 30_000});
  }
  // Record-level developer surfaces keep their own URLs and are reachable from Settings.
  await page.goto('/app/settings');
  await expect(page.getByRole('heading', {name: 'General', exact: true})).toBeVisible();
  await page.goto('/app/settings/developer');
  await expect(page.getByRole('heading', {name: 'Developer tools'})).toBeVisible();
  await page.getByRole('link', {name: /Execution history/}).click();
  await page.waitForURL('**/app/runs');
  await expect(page.getByRole('heading', {name: 'Execution history'})).toBeVisible();
  expect(errors).toEqual([]);
});
