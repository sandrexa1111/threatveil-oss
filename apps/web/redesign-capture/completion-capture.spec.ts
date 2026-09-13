import { test, type Page } from '@playwright/test';
import * as fs from 'fs';

// Product-completion capture for the contact sheet (mandate §67). Not part of the acceptance suite.
//   SHOTS_DIR=/work/.local/completion/after npx playwright test --config redesign-capture/playwright.config.ts completion-capture
const SHOTS = process.env.SHOTS_DIR || '/work/.local/completion/after';
fs.mkdirSync(SHOTS, {recursive: true});
const metrics: Record<string, unknown>[] = [];
const SETTINGS = {permissions: {allow: ['Bash(git:*)', 'Read', 'mcp__payments__refund_issue'], deny: ['WebFetch'], ask: ['Bash(rm:*)']},
  mcpServers: {payments: {command: 'payments-mcp'}, github: {command: 'gh-mcp'}}, model: 'claude-opus-5'};
const RELAXED = {
  protocol_version: '2026-07-28', supported_versions: ['2026-07-28', '2025-11-25'], complete: true,
  server_info: {name: 'synthetic-finance-tool-gateway', version: '1'},
  tools: [{name: 'beneficiary.update', description: "Update a synthetic vendor's payment beneficiary", inputSchema: {type: 'object'}},
          {name: 'invoice.update', description: 'Update a synthetic invoice status', inputSchema: {type: 'object'}}],
  authorization: {tools: {'beneficiary.update': {approval_required: false, tenant_bound: true},
                          'invoice.update': {approval_required: false, tenant_bound: true}}},
};

async function shot(page: Page, name: string, label: string, full = true) {
  await page.waitForTimeout(1200);
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
    const rawEnums = text.match(/\b[A-Z]{3,}(?:_[A-Z]+)+\b/g) || [];
    return {height: document.documentElement.scrollHeight,
      horizontalScroll: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      eyebrows, rawEnumsVisible: rawEnums.length, rawEnumSamples: Array.from(new Set(rawEnums)).slice(0, 5)};
  });
  metrics.push({name, label, ...m});
  console.log(`SHOT ${name} ${JSON.stringify(m)}`);
}

test('completion capture', async ({page}) => {
  test.setTimeout(900_000);
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(String(e).slice(0, 200)));

  await page.goto('/login');
  await page.getByLabel('Your name').fill('Capture owner');
  await page.getByLabel('Email', {exact: true}).fill(`completion-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization', {exact: true}).fill('Northwind Support');
  await page.getByRole('button', {name: 'Open local workspace'}).click();
  await page.waitForURL('**/app');
  await shot(page, '01-home-zero', 'Home — zero state and ecosystem presence');

  await page.goto('/app/systems/new');
  await page.getByRole('heading', {name: 'How do you want to connect your AI system?'}).waitFor();
  await shot(page, '02-connect-methods', 'Connect — methods');
  await page.getByRole('button', {name: /Watch a repository/}).click();
  await shot(page, '03-connect-github', 'Connect — GitHub, configuration required', false);
  await page.getByRole('button', {name: /Upload configuration/}).click();
  await page.getByLabel('Upload configuration file').setInputFiles({name: 'settings.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(SETTINGS))});
  await page.getByRole('heading', {name: 'ThreatVeil found'}).waitFor({timeout: 30_000});
  await shot(page, '04-definition-detected', 'Connect — definition detected');

  await page.goto('/app?tour=start');
  await page.locator('aside[role="dialog"]').waitFor();
  await page.getByLabel('I approve these synthetic checks and the legitimate invoice fixture.').check();
  await page.getByRole('button', {name: 'Prepare the synthetic example'}).click();
  await page.waitForURL(/\/app\/systems\/[0-9a-f-]+$/, {timeout: 120_000});
  const id = new URL(page.url()).pathname.split('/')[3];
  await page.getByRole('button', {name: 'Next'}).click();
  await page.getByRole('button', {name: 'Establish the baseline'}).click();
  await page.getByText('Baseline established').waitFor({timeout: 120_000});
  await shot(page, '05-guided-example', 'Guided example — step 2', false);
  await page.getByRole('button', {name: 'Exit tour'}).first().click();

  await page.goto(`/app/systems/${id}`); await shot(page, '06-system-current', 'System — current, stack and chain');
  await page.goto('/app/changes/propose');
  await page.getByRole('button', {name: 'GitHub pull request'}).waitFor();
  await page.getByRole('button', {name: 'GitHub pull request'}).click();
  await shot(page, '07-proposed-input', 'Check a change — input');
  await page.getByLabel('Pull request').fill('#482');
  await page.getByLabel('Link (https, optional)').fill('https://github.com/northwind/finance-agent/pull/482');
  await page.getByLabel('Upload candidate configuration').setInputFiles({name: 'tools.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(RELAXED))});
  await page.getByRole('status').filter({hasText: 'Detected'}).waitFor({timeout: 30_000});
  await page.getByRole('button', {name: 'Check this change', exact: true}).click();
  await page.getByRole('region', {name: 'Assurance before and after'}).waitFor({timeout: 60_000});
  await shot(page, '08-proposed-result-github', 'Proposed result — GitHub pull request reference');

  await page.goto(`/app/systems/${id}`);
  await page.getByText('Synthetic example controls').click();
  await page.getByRole('button', {name: 'Relax beneficiary approval'}).click();
  await page.getByRole('region', {name: /change awaiting review/}).waitFor({timeout: 60_000});
  await shot(page, '09-system-attention', 'System — attention, MCP-origin change impact');
  await page.goto('/app'); await shot(page, '10-home-attention', 'Home — attention');
  await page.goto('/app/systems'); await shot(page, '11-systems', 'Systems');
  await page.goto(`/app/systems/${id}/capabilities`); await shot(page, '12-capabilities', 'Capabilities');
  await page.goto(`/app/systems/${id}/claims`); await shot(page, '13-claims', 'Security claims');
  await page.goto(`/app/systems/${id}/evidence`); await shot(page, '14-evidence', 'Evidence');
  await page.getByRole('button', {name: /Beneficiary changes require finance approval/}).click();
  await page.getByRole('dialog').waitFor();
  await shot(page, '15-evidence-detail', 'Evidence detail', false);
  await page.keyboard.press('Escape');
  await page.goto(`/app/systems/${id}/activity`); await shot(page, '16-activity', 'Activity — assurance history');
  await page.getByRole('region', {name: 'Assurance history'}).getByRole('link').first().click();
  await page.getByRole('dialog').waitFor();
  await shot(page, '17-change-preview', 'Change preview', false);
  await page.keyboard.press('Escape');
  await page.goto('/app/changes'); await shot(page, '18-changes', 'Changes — detected');

  await page.goto(`/app/systems/${id}/restore`);
  await page.getByRole('button', {name: /C · Restore approval and re-prove/}).click();
  await page.getByText('Clearance restored.').waitFor({timeout: 120_000});
  await page.goto(`/app/systems/${id}/share`);
  await page.getByRole('button', {name: 'Issue a signed passport'}).click();
  await page.getByLabel('Current Assurance Passport').waitFor({timeout: 60_000});
  await shot(page, '19-share-passport', 'Share — Passport');
  await page.goto(`/app/systems/${id}`);
  await page.getByRole('region', {name: 'Assurance Gate'}).scrollIntoViewIfNeeded();
  await shot(page, '20-gate-passport-primitives', 'System — Gate and Passport primitives', false);
  await page.goto(`/app/integrations?system=${id}`); await shot(page, '21-integrations', 'Integrations');
  await page.goto('/app/settings/general'); await shot(page, '22-settings-general', 'Settings — General');
  await page.goto('/app/settings/members'); await shot(page, '23-settings-members', 'Settings — Members');
  await page.goto('/app/settings/developer'); await shot(page, '24-settings-developer', 'Settings — Developer');
  await page.goto('/app/billing'); await shot(page, '25-billing', 'Usage & billing');

  await page.setViewportSize({width: 390, height: 844});
  await page.goto('/app'); await shot(page, '26-mobile-home', 'Mobile — home');
  await page.goto(`/app/systems/${id}`); await shot(page, '27-mobile-system', 'Mobile — system');

  fs.writeFileSync(`${SHOTS}/metrics.json`, JSON.stringify({metrics, pageErrors: errors}, null, 2));
  console.log(`PAGE_ERRORS=${errors.length}`);
});
