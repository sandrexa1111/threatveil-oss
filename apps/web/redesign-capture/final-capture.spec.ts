import { test, type Page } from '@playwright/test';
import * as fs from 'fs';

// Final redesign capture for the contact sheet (mandate §25). Not part of the acceptance suite.
const SHOTS = process.env.SHOTS_DIR || '/work/.local/final-shots';
fs.mkdirSync(SHOTS, {recursive: true});
const metrics: Record<string, unknown>[] = [];
const RELAXED = {
  protocol_version: '2026-07-28', supported_versions: ['2026-07-28', '2025-11-25'], complete: true,
  server_info: {name: 'synthetic-finance-tool-gateway', version: '1'},
  tools: [{name: 'beneficiary.update', description: "Update a synthetic vendor's payment beneficiary", inputSchema: {type: 'object'}},
          {name: 'invoice.update', description: 'Update a synthetic invoice status', inputSchema: {type: 'object'}}],
  authorization: {tools: {'beneficiary.update': {approval_required: false, tenant_bound: true},
                          'invoice.update': {approval_required: false, tenant_bound: true}}},
};

async function shot(page: Page, name: string, label: string, full = true) {
  await page.waitForTimeout(900);
  await page.screenshot({path: `${SHOTS}/${name}.png`, fullPage: full});
  const m = await page.evaluate(() => {
    const main = document.querySelector('main') || document.body;
    const visible: string[] = [];
    const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const el = node.parentElement;
      if (!el || el.closest('.sr-only, code, pre, script, style, [hidden]')) continue;
      const closed = el.closest('details:not([open])');
      if (closed && !el.closest('summary')) continue;
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0 || getComputedStyle(el).visibility === 'hidden') continue;
      visible.push(node.textContent || '');
    }
    const text = visible.join(' ');
    const eyebrows = Array.from(main.querySelectorAll('.eyebrow')).filter(e => (e as HTMLElement).offsetParent).length;
    const rawEnums = (text.match(/\b[A-Z]{3,}(?:_[A-Z]+)+\b/g) || []);
    return {height: document.documentElement.scrollHeight,
      horizontalScroll: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      eyebrows, rawEnumsVisible: rawEnums.length, rawEnumSamples: Array.from(new Set(rawEnums)).slice(0, 5)};
  });
  metrics.push({name, label, ...m});
  console.log(`SHOT ${name} ${JSON.stringify(m)}`);
}

test('final capture', async ({page}) => {
  test.setTimeout(900_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(String(e).slice(0, 200)));

  await page.goto('/login');
  await page.getByLabel('Your name').fill('Final owner');
  await page.getByLabel('Email', {exact: true}).fill(`final-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization', {exact: true}).fill('Northwind Support');
  await page.getByRole('button', {name: 'Open local workspace'}).click();
  await page.waitForURL('**/app');
  await shot(page, '01-home-zero', 'Home — zero state');

  await page.goto('/app/systems/new');
  await page.getByLabel(/paste its contents/).fill(JSON.stringify({
    permissions: {allow: ['Bash(git:*)', 'Read', 'mcp__payments__refund_issue'], deny: ['WebFetch'], ask: ['Bash(rm:*)']},
    mcpServers: {payments: {command: 'payments-mcp'}, github: {command: 'gh-mcp'}}, model: 'claude-opus-5'}));
  await page.getByRole('button', {name: 'Read this definition'}).click();
  await page.getByRole('heading', {name: 'Detected'}).waitFor();
  await shot(page, '02-onboarding', 'Onboarding — detected');

  await page.goto('/app/systems/new?example=finance');
  await page.getByRole('button', {name: 'Prepare finance example'}).click();
  await page.waitForURL('**/systems/*/setup', {timeout: 120_000});
  const id = new URL(page.url()).pathname.split('/')[3];
  await page.waitForTimeout(2500);
  await page.getByRole('button', {name: /Run finance baseline/i}).first().click();
  await page.waitForTimeout(45_000);

  await page.goto(`/app/systems/${id}`); await shot(page, '04-system-current', 'System — current');
  await page.goto('/app'); await shot(page, '03-home-current', 'Home — all current');

  await page.goto('/app/changes/propose');
  await page.waitForTimeout(2500);
  await page.getByLabel('Proposed configuration (JSON)').fill(JSON.stringify(RELAXED));
  await page.getByLabel(/^Reference$/).fill('#482');
  await page.getByRole('button', {name: 'Check this change'}).click();
  await page.getByRole('region', {name: 'Assurance before and after'}).waitFor({timeout: 60_000});
  await shot(page, '09-proposed-review', 'Proposed-change review');

  await page.goto(`/app/systems/${id}/activity`);
  await page.waitForTimeout(2500);
  await page.getByRole('button', {name: /Relax beneficiary approval/i}).first().click();
  await page.waitForTimeout(25_000);

  await page.goto('/app'); await shot(page, '05-home-attention', 'Home — attention');
  await page.goto('/app/systems'); await shot(page, '06-systems', 'Systems list');
  await page.goto(`/app/systems/${id}`); await shot(page, '07-system-attention', 'System — attention');
  await page.goto(`/app/systems/${id}/claims`); await shot(page, '08-claims', 'System — claims');
  await page.getByRole('button', {name: /Beneficiary changes require finance approval/}).click();
  await page.getByRole('dialog').waitFor();
  await shot(page, '10-claim-drawer', 'Claim drawer', false);
  await page.keyboard.press('Escape');
  await page.goto(`/app/systems/${id}/evidence`); await shot(page, '11-evidence', 'System — evidence');
  await page.goto(`/app/systems/${id}/activity`); await shot(page, '12-activity', 'System — activity');
  await page.goto(`/app/systems/${id}/share`); await shot(page, '13-share', 'Passport / Share');
  await page.goto('/app/changes'); await shot(page, '14-changes', 'Changes');
  await page.goto('/app/integrations'); await shot(page, '15-integrations', 'Integrations');
  await page.goto('/app/billing'); await shot(page, '16-billing', 'Usage & billing');
  await page.goto('/app/settings'); await shot(page, '17-settings', 'Settings');
  await page.goto(`/app/systems/${id}`);
  await page.keyboard.press('ControlOrMeta+k');
  await page.getByRole('dialog', {name: 'Command menu'}).waitFor();
  await shot(page, '18-command-menu', 'Command menu', false);
  await page.keyboard.press('Escape');

  await page.setViewportSize({width: 390, height: 844});
  await page.goto('/app'); await shot(page, '19-mobile-home', 'Mobile — home');
  await page.goto(`/app/systems/${id}`); await shot(page, '20-mobile-system', 'Mobile — system');

  fs.writeFileSync(`${SHOTS}/metrics.json`, JSON.stringify({metrics, pageErrors: errors}, null, 2));
  console.log(`PAGE_ERRORS=${errors.length}`);
});
