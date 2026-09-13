import {test, expect, type Page} from '@playwright/test';

/**
 * Acceptance for product completion.
 *
 * NEW USER: truthful ecosystem presence, method choice, deterministic format detection,
 * the factual system stack, an uploaded proposed change, integrations as an operating
 * surface, and organised settings.
 * FULL LOOP: the guided example drives only the synthetic fixture's existing controls,
 * and the Assurance Chain, Change Impact, Evidence, Activity, Gate and Passport agree.
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

async function noOverflow(page: Page, label: string) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), label).toBe(true);
}

const SETTINGS = {permissions: {allow: ['Bash(git:*)', 'mcp__payments__refund_issue'], deny: ['Bash(rm:*)']},
  mcpServers: {payments: {command: 'payments-mcp'}}, model: 'claude-opus-5'};
const CANDIDATE = {...SETTINGS, permissions: {allow: [...SETTINGS.permissions.allow, 'Bash(rm:*)'], deny: []}};
const CREW = 'researcher:\n  role: Researcher\n  goal: Find sources\n  allow_delegation: true\n  tools: [search]\n';
const file = (name: string, body: string, mimeType = 'application/json') => ({name, mimeType, buffer: Buffer.from(body)});

test('NEW USER — truthful ecosystem, detected import, factual stack, uploaded check, operating integrations, organised settings', async ({page}) => {
  test.setTimeout(300_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'completion-new');

  // Home: the loop, and where agents live — each identity with exactly its relationship.
  await expect(page.getByRole('heading', {name: 'Protect your first AI system'})).toBeVisible();
  const ecosystem = page.getByLabel('Import or connect from');
  for (const [name, relation] of [['GitHub', 'live source'], ['Claude Code', 'import'], ['MCP', 'connect or import'],
    ['LangGraph', 'import'], ['CrewAI', 'import'], ['OpenAI Agents SDK', 'trace import']]) {
    await expect(ecosystem.getByRole('listitem').filter({hasText: name}).first()).toContainText(relation);
  }
  await expect(page.locator('main')).not.toContainText(/partner|official integration|certified/i);
  await expect(page.getByRole('link', {name: 'Explore how ThreatVeil works'})).toBeVisible();

  // Connect: choose a method. A live GitHub source without a registered credential says so.
  await page.goto('/app/systems/new');
  await expect(page.getByRole('heading', {name: 'How do you want to connect your AI system?'})).toBeVisible();
  await page.getByRole('button', {name: /Watch a repository/}).click();
  await expect(page.getByText('Configuration required', {exact: true})).toBeVisible({timeout: 30_000});

  // Upload: the format is detected, never selected at the first level.
  await page.getByRole('button', {name: /Upload configuration/}).click();
  await page.getByLabel('Upload configuration file').setInputFiles(file('settings.json', JSON.stringify(SETTINGS)));
  await expect(page.getByRole('status').filter({hasText: 'Detected'})).toContainText('Claude Code settings', {timeout: 30_000});
  await expect(page.getByLabel('Definition format', {exact: true})).toBeHidden();
  const found = page.getByRole('region', {name: 'ThreatVeil found'});
  await expect(found).toContainText('claude-opus-5');
  await expect(found).toContainText('mcp__payments__refund_issue');
  await expect(found).toContainText('1 denied');
  await page.getByLabel('System name').fill('Refund agent');
  await page.getByLabel('What useful work does it do?').fill('Issues refunds against the payments ledger for support tickets.');
  await page.getByLabel('Operating boundary').fill('Staging support workflow and its refund tooling only.');
  await page.getByRole('button', {name: 'Connect system'}).click();
  await page.waitForURL('**/systems/*/claims', {timeout: 60_000});
  const systemId = new URL(page.url()).pathname.split('/')[3];

  // The stack shows only what the import established: nothing inferred, nothing called live.
  const stack = page.getByRole('list', {name: 'System stack'});
  await expect(stack.getByRole('listitem')).toHaveCount(2, {timeout: 30_000});
  await expect(stack.getByRole('listitem').filter({hasText: 'Claude Code'})).toContainText('imported');
  await expect(stack.getByRole('listitem').filter({hasText: 'MCP'})).toContainText('declared');
  await expect(stack).not.toContainText('live');

  // Define: a claim, declared and never reported as supported.
  await page.getByLabel('What does it govern?').fill('customer refunds');
  await page.getByRole('button', {name: 'Build a draft'}).click();
  await page.getByLabel('Declared dependencies (comma separated)').fill('permissions:approval, tool:mcp__payments__refund_issue');
  await page.getByRole('button', {name: 'Save declared claim'}).click();
  await expect(page.getByText('Needs evidence').first()).toBeVisible({timeout: 30_000});

  // Check: an uploaded candidate, detected, answered with two states and its source.
  await page.goto('/app/changes/propose');
  await page.getByLabel('Upload candidate configuration').setInputFiles(file('settings.json', JSON.stringify(CANDIDATE)));
  await expect(page.getByRole('status').filter({hasText: 'Detected'})).toBeVisible({timeout: 30_000});
  await page.getByRole('button', {name: 'Check this change', exact: true}).click();
  const states = page.getByRole('region', {name: 'Assurance before and after'});
  await expect(states).toBeVisible({timeout: 60_000});
  await expect(states).toContainText('Current system');
  await expect(states).toContainText('If shipped');
  await expect(page.getByText('This check reads only. It has not changed current assurance.')).toBeVisible();
  await expect(page.locator('article').filter({hasText: 'Imported snapshot'}).first()).toContainText('Agent definition');

  // Integrations: relationship, real state, one real action — and no import shown as connected.
  await page.goto(`/app/integrations?system=${systemId}`);
  const row = (name: string) => page.getByRole('listitem').filter({has: page.getByRole('strong').getByText(name, {exact: true})});
  await expect(row('GitHub')).toContainText('Live source');
  await expect(row('GitHub')).toContainText('Configuration required');
  await expect(row('Claude Code')).toContainText('Import available');
  await expect(row('OpenAI Agents SDK')).toContainText('Trace import');
  await expect(row('SARIF')).toContainText('Advanced security import');
  await expect(page.locator('main')).not.toContainText('Connected ·');
  await expect(page.getByLabel('GitHub Checks consumer')).toContainText('Configuration required');
  await row('CrewAI').getByRole('button', {name: 'Import configuration'}).click();
  const drawer = page.getByRole('dialog');
  await drawer.getByLabel('Upload configuration file').setInputFiles(file('agents.yaml', CREW, 'text/yaml'));
  await expect(drawer.getByRole('status').filter({hasText: 'Detected'})).toContainText('CrewAI', {timeout: 30_000});
  await drawer.getByRole('button', {name: 'Import', exact: true}).click();
  await expect(drawer.getByText(/^Imported\./)).toBeVisible({timeout: 30_000});
  await page.keyboard.press('Escape');

  // The stack gains CrewAI once, and a stack item leads to its source.
  await page.goto(`/app/systems/${systemId}`);
  await expect(stack.getByRole('listitem')).toHaveCount(3, {timeout: 30_000});
  await expect(stack.getByRole('listitem').filter({hasText: 'CrewAI'})).toContainText('imported');
  await expect(page.getByRole('region', {name: 'Assurance setup'})).toContainText('3 of 6');
  await stack.getByRole('link', {name: /Claude Code/}).click();
  await page.waitForURL(/\/evidence#sources$/);
  await expect(page.getByRole('region', {name: 'Where changes and observations come from'})).toContainText('Imported snapshot');

  // Settings: five sections, not one long page, with every developer tool still reachable.
  await page.goto('/app/settings');
  expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBeLessThan(2600);
  const nav = page.getByRole('navigation', {name: 'Settings sections'});
  for (const [label, slug] of [['General', 'general'], ['Members', 'members'], ['Security', 'security'],
    ['Developer', 'developer'], ['Data & export', 'data']]) {
    await nav.getByRole('link', {name: label, exact: true}).click();
    await page.waitForURL(`**/app/settings/${slug}`);
    await expect(page.getByRole('heading', {name: label, exact: true})).toBeVisible();
  }
  await page.goto('/app/settings/developer');
  await expect(page.getByLabel('Token name')).toBeVisible();
  await expect(page.getByRole('heading', {name: 'Qualified observation sources'})).toBeVisible();
  await expect(page.getByRole('link', {name: /Execution history/})).toBeVisible();

  await page.setViewportSize({width: 390, height: 844});
  for (const target of ['/app', `/app/systems/${systemId}`, `/app/systems/${systemId}/evidence`, '/app/integrations',
    '/app/settings/developer', '/app/changes/propose', '/app/billing']) {
    await page.goto(target);
    await page.waitForTimeout(900);
    await noOverflow(page, target);
  }
  expect(errors).toEqual([]);
});

test('FULL LOOP — the guided example drives the real fixture, and every surface agrees', async ({page}) => {
  test.setTimeout(480_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await login(page, 'completion-tour');

  await page.goto('/app?tour=start');
  const tour = page.locator('aside[role="dialog"]');
  await expect(tour).toContainText('Step 1 of 11');
  await expect(tour).toContainText('Synthetic demonstration');
  await tour.getByLabel('I approve these synthetic checks and the legitimate invoice fixture.').check();
  await tour.getByRole('button', {name: 'Prepare the synthetic example'}).click();
  await page.waitForURL(/\/app\/systems\/[0-9a-f-]+$/, {timeout: 90_000});
  const systemId = new URL(page.url()).pathname.split('/')[3];
  const status = page.getByRole('region', {name: 'System status'});
  const chain = page.getByRole('region', {name: 'Assurance chain'});
  const next = () => tour.getByRole('button', {name: /^(Next|Finish)$/}).click();

  // 1–2. Current: every link holds, and the stack is the imported MCP snapshot only.
  await next();
  await expect(tour).toContainText('Step 2 of 11');
  await tour.getByRole('button', {name: 'Establish the baseline'}).click();
  await expect(tour.getByText('Baseline established')).toBeVisible({timeout: 120_000});
  await expect(status.getByText('Cleared', {exact: true})).toBeVisible({timeout: 30_000});
  await expect(chain).toContainText('Why this answer holds');
  await expect(chain).toContainText('Cleared');
  const stack = page.getByRole('list', {name: 'System stack'});
  await expect(stack.getByRole('listitem')).toHaveCount(1);
  await expect(stack).toContainText('MCP');
  await expect(stack).toContainText('imported');

  // 3. A consequential permission changes; the chain breaks where it stops holding.
  await next();
  await tour.getByRole('button', {name: 'Relax beneficiary approval'}).click();
  await expect(tour.getByText('Gateway changed')).toBeVisible({timeout: 60_000});
  await expect(status.getByText('Needs attention', {exact: true})).toBeVisible({timeout: 30_000});
  await expect(chain).toContainText('Where the answer stops holding');
  await expect(chain).toContainText('Authority expanded');
  await expect(chain).toContainText('1 claim affected');

  // 4. Change Impact: source, before → after, authority effect, claims split, two states.
  await next();
  const change = page.getByRole('region', {name: /change awaiting review/});
  await expect(change).toContainText('MCP');
  await expect(change).toContainText('Imported snapshot');
  await expect(change).toContainText('approval_required');
  await expect(change.locator('b').filter({hasText: /^true$/})).toBeVisible();
  await expect(change.locator('b').filter({hasText: /^false$/})).toBeVisible();
  await expect(change).toContainText('Authority expanded');
  await expect(change).toContainText('Beneficiary changes require finance approval');
  await expect(change).toContainText('Still current');
  const states = change.getByRole('region', {name: 'Assurance before and after'});
  await expect(states).toContainText('Before this change');
  await expect(states).toContainText('Current system');
  await expect(states).toContainText('Needs attention');

  // 5–6. Evidence: one claim needs fresh evidence, the others are current; detail under a drawer.
  await next(); await next();
  await page.waitForURL(`**/systems/${systemId}/evidence`);
  const evidence = page.getByRole('region', {name: 'Evidence status'});
  await expect(evidence).toContainText(/1\s*Needs fresh evidence/);
  await expect(evidence).toContainText(/2\s*Current/);
  await page.getByRole('button', {name: /Beneficiary changes require finance approval/}).click();
  const detail = page.getByRole('dialog', {name: 'Beneficiary changes require finance approval'});
  await expect(detail).toContainText('Synthetic committed SQLite ledger');
  await expect(detail.getByText('Claim ID')).toBeHidden();
  await detail.getByText('Advanced').click();
  await expect(detail.getByText('Claim ID')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(detail).toHaveCount(0);

  // 7–9. Verification fails, a bad fix is rejected, the proper fix restores assurance.
  await next();
  await page.waitForURL(`**/systems/${systemId}/restore`);
  await tour.getByRole('button', {name: 'Re-prove with approval relaxed'}).click();
  await expect(page.getByText('Security failed: not cleared.')).toBeVisible({timeout: 120_000});
  await next();
  await tour.getByRole('button', {name: 'Try a fix that disables updates'}).click();
  await expect(page.getByText('Security held, but useful work broke: not cleared.')).toBeVisible({timeout: 120_000});
  await next();
  await tour.getByRole('button', {name: 'Restore approval and re-prove'}).click();
  await expect(page.getByText('Clearance restored.')).toBeVisible({timeout: 120_000});
  await expect(status.getByText('Cleared', {exact: true})).toBeVisible({timeout: 30_000});

  // 10–11. The Gate answers for machines; the Passport is issued only on request.
  await next();
  await page.waitForURL(new RegExp(`/systems/${systemId}$`));
  const gate = page.getByRole('region', {name: 'Assurance Gate'});
  await expect(gate.getByText('Cleared', {exact: true})).toBeVisible({timeout: 30_000});
  await expect(gate).toContainText('Never');
  await next();
  await page.waitForURL(`**/systems/${systemId}/share`);
  await expect(page.getByRole('region', {name: 'External assurance'})).toContainText('Not issued');
  await next();
  await expect(tour).toHaveCount(0);

  // Activity is assurance memory, in the same order the tour just produced it.
  await page.goto(`/app/systems/${systemId}/activity`);
  const history = page.getByRole('region', {name: 'Assurance history'});
  for (const text of ['Previous assurance superseded', 'Security failed', 'Useful task failed', 'Verification passed',
    'Assurance established', 'Assurance restored']) await expect(history).toContainText(text);
  await history.getByRole('button', {name: /^Verification/}).click();
  await expect(history).not.toContainText('Assurance restored');
  await expect(history).toContainText('Useful task failed');
  await history.getByRole('button', {name: /^All/}).click();
  await history.getByRole('link', {name: 'Beneficiary update authority expanded'}).first().click();
  const preview = page.getByRole('dialog', {name: 'Beneficiary update authority expanded'});
  await expect(preview.getByRole('link', {name: /Open full review/})).toBeVisible();
  expect(new URL(page.url()).searchParams.get('change')).toBeTruthy();
  await page.keyboard.press('Escape');
  await expect(preview).toHaveCount(0);

  // The same change previews from Home, and the system is a recent destination in ⌘K.
  await page.goto('/app');
  await page.getByRole('link', {name: 'Beneficiary update authority expanded'}).first().click();
  await expect(page.getByRole('dialog', {name: 'Beneficiary update authority expanded'})).toBeVisible({timeout: 30_000});
  await page.keyboard.press('Escape');
  await page.keyboard.press('ControlOrMeta+k');
  const menu = page.getByRole('dialog', {name: 'Command menu'});
  await expect(menu.getByText('Recent', {exact: true}).first()).toBeVisible();
  await page.keyboard.press('Escape');

  await page.setViewportSize({width: 390, height: 844});
  for (const target of [`/app/systems/${systemId}`, `/app/systems/${systemId}/activity`, '/app']) {
    await page.goto(target);
    await page.waitForTimeout(900);
    await noOverflow(page, target);
  }
  expect(errors).toEqual([]);
});
