import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

test('a customer proves failure, verifies a useful fix, and blocks historical regression', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Acceptance Customer');
  await page.getByLabel('Email', { exact: true }).fill(`acceptance-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization', { exact: true }).fill('Browser acceptance');
  await page.getByRole('button', { name: 'Open local workspace' }).click();
  await page.waitForURL('**/app');
  await page.goto('/app/demo');
  await page.getByRole('button', { name: /Prepare/ }).click();
  async function candidate(label: string, security: string, task: string, release: string) {
    await page.goto('/app/demo');
    await page.getByRole('button', { name: new RegExp(label) }).click();
    await page.waitForURL('**/runs/*');
    const cards = page.locator('.verdict-grid');
    await expect(cards.locator('article').nth(0)).toContainText(security);
    await expect(cards.locator('article').nth(1)).toContainText(task);
    await expect(cards.locator('article').nth(2)).toContainText(release);
    return page.url().split('/').at(-1)!;
  }
  const failed = await candidate('01 · Vulnerable', 'FAIL', 'SUCCESS', 'BLOCK');
  const fixed = await candidate('02 · Fixed', 'PASS', 'SUCCESS', 'ALLOW');
  await page.getByRole('button', { name: 'Verify the fix' }).click();
  await page.getByLabel('Original failing run').selectOption(failed);
  await page.getByLabel('Verification run', { exact: false }).selectOption(fixed);
  await page.getByLabel('What changed in the fix?').fill('Enforced human authorization at the beneficiary write boundary.');
  await page.getByRole('button', {name:'Verify and retain baseline'}).click();
  await expect(page.locator('dialog')).not.toBeVisible();
  await candidate('03 · Regressed', 'FAIL', 'SUCCESS', 'BLOCK');
  await expect(page.getByText('Historical regression detected.', { exact: true })).toBeVisible();
  await candidate('04 · Missing witness', 'INCONCLUSIVE', 'UNKNOWN', 'BLOCK');
  await candidate('05 · Bad fix', 'PASS', 'FAILURE', 'BLOCK');
  await expect(page.getByText('This is not a useful verified fix.', { exact: true })).toBeVisible();
  await page.goto('/app/reports');
  await expect(page.locator('main')).toContainText('SCOPED');
  await page.goto('/app/billing');
  await expect(page.getByRole('heading', {name:/^FREE/})).toBeVisible();
  await page.setViewportSize({width:390,height:844});
  await expect(page.locator('.sidebar')).not.toBeVisible();
  await page.getByRole('button',{name:'Open navigation'}).click();
  await expect(page.locator('.sidebar')).toBeVisible();
  await page.getByRole('link',{name:'Systems',exact:true}).first().click();
  await expect(page.locator('.sidebar')).not.toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
  expect(errors).toEqual([]);
});

test('public pages work on a narrow screen without horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const route of ['/', '/product', '/pricing', '/security', '/docs', '/contact']) {
    const response = await page.goto(route);
    expect(response?.status()).toBe(200);
    await expect(page.locator('h1')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  }
});

test('an owner issues and revokes access, schedules approved verification, and reuses a property as a draft', async ({page}) => {
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Workflow Owner');
  await page.getByLabel('Email', {exact:true}).fill(`operations-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization', {exact:true}).fill('Workflow acceptance');
  await page.getByRole('button', {name:'Open local workspace'}).click();
  await page.waitForURL('**/app');
  await page.goto('/app/demo');
  await page.getByRole('button', {name:'Prepare demo fixtures'}).click();
  await expect(page.getByRole('button', {name:/01 · Vulnerable/})).toBeVisible();

  await page.goto('/app/settings/developer');
  await page.getByLabel('Token name').fill('Acceptance CI');
  await page.getByRole('combobox', {name:'Permission',exact:true}).selectOption('execute');
  await page.getByRole('button', {name:'Create API token'}).click();
  await expect(page.getByLabel('New API token')).toHaveValue(/^tvk_/);
  await expect(page.getByLabel('New API token')).toHaveAttribute('type','password');
  await page.getByRole('button', {name:'Dismiss token secret'}).click();
  const tokenRow=page.getByRole('row').filter({hasText:'Acceptance CI'});
  await tokenRow.getByRole('button', {name:'Revoke'}).click();
  await expect(tokenRow).toContainText('REVOKED');
  await expect(page.getByRole('heading', {name:'Qualified observation sources'})).toBeVisible();
  await page.locator('.observer-register > summary').click();
  await page.getByRole('combobox', {name:'Observer property',exact:true}).selectOption({label:'Untrusted documents cannot change beneficiary details'});
  await expect(page.getByRole('combobox', {name:'Observer target',exact:true}).locator('option')).toHaveCount(1);
  await expect(page.getByRole('button', {name:'Register source',exact:true})).toBeDisabled();
  await expect(page.getByText('The synthetic demo target cannot qualify a customer collector.', {exact:false})).toBeVisible();

  await page.goto('/app/billing');
  await page.getByRole('button', {name:'Choose Pro', exact:true}).click();
  await expect(page.getByRole('heading', {name:/^PRO/})).toBeVisible();
  await page.goto('/app/schedules');
  await page.getByLabel('Schedule name').fill('Daily procurement check');
  await page.getByRole('combobox', {name:'Approved property',exact:true}).selectOption({label:'Untrusted documents cannot change beneficiary details'});
  await page.getByRole('combobox', {name:'Authorized target',exact:true}).selectOption({label:'Synthetic procurement ledger'});
  await page.getByLabel('Candidate version', {exact:true}).fill('fixed');
  await page.getByRole('button', {name:'Create schedule'}).click();
  const schedule=page.getByRole('row').filter({hasText:'Daily procurement check'});
  await expect(schedule).toContainText('ACTIVE');
  await schedule.getByRole('button', {name:'Disable'}).click();
  await expect(schedule).toContainText('DISABLED');

  await page.goto('/app/systems');
  await page.getByRole('link', {name:'Connect system'}).click();
  await page.waitForURL('**/systems/new');
  await page.getByRole('button', {name:'Advanced manual setup'}).click();
  await page.getByLabel('System name').fill('Accounts payable');
  await page.getByLabel('What useful work does it do?').fill('Updates approved payment records for our accounts payable team.');
  await page.getByLabel('Operating boundary').fill('Staging accounts payable ledger and its approval workflow.');
  await page.getByLabel('What can it access?').fill('payments');
  await page.getByLabel('What can it do?').fill('write, approve');
  await page.getByRole('button', {name:'Connect system'}).click();
  await page.waitForURL('**/systems/*/claims', {timeout:60_000});
  await page.goto('/app/propagation');
  await expect(page.getByText('Shared declared access: payments')).toBeVisible();
  await page.getByRole('button', {name:'Create destination draft'}).first().click();
  await expect(page.getByRole('link', {name:'Review copied draft'}).first()).toBeVisible();
  await page.getByRole('link', {name:'Review copied draft'}).first().click();
  const copied=page.getByRole('row').filter({hasText:'Accounts payable'});
  await expect(copied).toContainText('DRAFT');
  await expect(copied).not.toContainText('PASS');
});

test('contact request records explicit consent without claiming configured CRM delivery', async ({page})=>{
  await page.goto('/contact');
  await page.getByLabel('Name', {exact:true}).fill('Local Review Request');
  await page.getByLabel('Work email').fill(`review-${Date.now()}@local.invalid`);
  await page.getByLabel('Company', {exact:true}).fill('Local test organization');
  await page.getByLabel('What does your agent do?').fill('Synthetic test request: procurement approval boundary.');
  await page.getByLabel('I agree to be contacted about this request.').check();
  await page.getByRole('button', {name:'Request an Integrity Launch'}).click();
  await expect(page.getByRole('status')).toContainText(/recorded. Follow-up delivery is pending configuration|received and queued/);
});

test('older approved properties remain accessible beyond the recent record window', async ({page})=>{
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Pagination owner');
  await page.getByLabel('Email',{exact:true}).fill(`pagination-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization',{exact:true}).fill('Pagination acceptance');
  await page.getByRole('button',{name:'Open local workspace'}).click();
  await page.waitForURL('**/app');
  const identity=await (await page.request.get('/api/backend/v1/auth/me')).json();
  const demo=await (await page.request.post('/api/backend/v1/demo/setup',{data:{},headers:{'x-csrf-token':identity.csrf_token,origin:process.env.TV_TEST_WEB_URL || 'http://127.0.0.1:3000'}})).json();
  const root=path.resolve(process.cwd(),'../..');
  execFileSync(path.join(root,'.venv/bin/python'),[path.join(process.cwd(),'tests/seed-pagination.py')],{input:JSON.stringify({organization_id:identity.organization.id,system_id:demo.system.id,property_id:demo.property.id}),encoding:'utf8'});
  await page.goto('/app/properties');
  await expect(page.getByText('200 of 206 properties loaded',{exact:false})).toBeVisible();
  await page.getByRole('button',{name:'Load older properties',exact:true}).click();
  await expect(page.getByText('206 of 206 properties loaded',{exact:false})).toBeVisible();
  await page.getByLabel('Search properties').fill('Untrusted documents');
  await expect(page.getByRole('row').filter({hasText:'Untrusted documents cannot change beneficiary details'})).toContainText('APPROVED');
  await page.goto('/app/demo');
  await page.getByRole('button',{name:'New run',exact:true}).click();
  await page.getByRole('dialog').getByRole('button',{name:'Load older properties',exact:true}).click();
  await expect(page.getByRole('dialog').getByRole('combobox',{name:'Approved property',exact:false})).toContainText('Untrusted documents cannot change beneficiary details');
});

test('external capture evidence supports a scoped canary and selection audit',async({page})=>{
  const root=path.resolve(process.cwd(),'../..');
  const output=execFileSync(path.join(root,'.venv/bin/python'),[path.join(process.cwd(),'tests/seed-capture.py')],{encoding:'utf8'});
  const fixture=JSON.parse(output.split('\n').find(line=>line.startsWith('BROWSER_FIXTURE:'))!.slice('BROWSER_FIXTURE:'.length));
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Capture acceptance');
  await page.getByLabel('Email',{exact:true}).fill(fixture.email);
  await page.getByLabel('Organization',{exact:true}).fill('Existing capture fixture');
  await page.getByRole('button',{name:'Open local workspace'}).click();
  await page.waitForURL('**/app');
  await page.goto(`/app/runs/${fixture.run_id}`);
  await expect(page.locator('.verdict-grid').locator('article').first()).toContainText('FAIL');
  await page.getByRole('button',{name:'Inspect capture',exact:true}).first().click();
  const capture=page.getByRole('region',{name:'Selected capture evidence'});
  await expect(capture).toContainText('procurement-ledger');
  await expect(capture).toContainText('beneficiary.update');
  await expect(capture.getByRole('link',{name:'Export this capture'})).toBeVisible();
  await expect(capture.getByRole('alert')).not.toBeVisible();
  await page.goto('/app/impact');
  await page.getByLabel('Expected candidate identity',{exact:true}).fill(JSON.stringify(fixture.candidate));
  await page.getByRole('combobox',{name:'Verified baseline 1',exact:true}).selectOption(fixture.baseline_id);
  await page.getByRole('combobox',{name:'Candidate run 1',exact:true}).selectOption(fixture.candidate_run_id);
  await page.getByRole('button',{name:'Evaluate security canary',exact:true}).click();
  const assessment=page.getByRole('region',{name:'Current assurance assessment'});
  await expect(assessment).toContainText('PRESERVED');
  await expect(assessment.locator('.card-heading').first()).toContainText('ALLOW');
  await page.getByLabel('Impact analysis record ID').fill(fixture.impact_id);
  await page.getByRole('checkbox',{name:new RegExp(fixture.candidate_run_id.slice(0,8))}).check();
  await page.getByRole('button',{name:'Audit test selection',exact:true}).click();
  await expect(assessment.getByRole('heading',{name:'Test selection audit',exact:true})).toBeVisible();
  await expect(assessment).toContainText('PRESERVED');
  await page.getByRole('button',{name:'Recheck current applicability',exact:true}).click();
  await expect(assessment.locator('.card-heading').first()).toContainText('ALLOW');
});

test('a reviewed tool contract installs six drafts without approving or executing them',async({page})=>{
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Tool contract owner');
  await page.getByLabel('Email',{exact:true}).fill(`tool-contract-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization',{exact:true}).fill('Tool contract acceptance');
  await page.getByRole('button',{name:'Open local workspace'}).click();
  await page.waitForURL('**/app');
  await page.goto('/app/demo');
  await page.getByRole('button',{name:'Prepare demo fixtures'}).click();
  await expect(page.getByRole('button',{name:/01 · Vulnerable/})).toBeVisible();
  await page.goto('/app/properties');
  await page.locator('.tool-contract-installer>summary').click();
  await page.getByLabel('Tool contract binding (JSON)',{exact:false}).fill(JSON.stringify({
    tool:'erp.beneficiary',tool_version:'v1',operation:'beneficiary.update',boundary:'beneficiary-approval',witness_id:'erp-ledger',
    principal:{id:'procurement-agent',tenant_id:'fixture-tenant',authority:['beneficiary.update']},
    resource:{type:'payment_beneficiary',id:'vendor-1',tenant_id:'fixture-tenant'},approver_id:'finance-reviewer',
    initial_state:{account:'SYNTHETIC-OLD'},allowed_state:{account:'SYNTHETIC-APPROVED'}
  }));
  await page.getByLabel('I reviewed the identities, resource, tool version, and permitted transition in this binding.').check();
  await page.getByRole('button',{name:'Install six property drafts',exact:true}).click();
  await expect(page.locator('.tool-contract-result')).toContainText('6 drafts installed');
  await expect(page.getByRole('row').filter({hasText:'DRAFT'})).toHaveCount(6);
  const state=await(await page.request.get('/api/backend/v1/dashboard')).json();
  expect(state.summary.properties).toBe(1);
  expect(state.summary.runs).toBe(0);
});
