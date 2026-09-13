import { test, expect } from '@playwright/test';

test.beforeEach(async ({page}) => {
  // Optional isolated API while the shared workspace preview stays running.
  if (process.env.TV_TEST_API_URL) await page.route('**/api/backend/v1/**', async route => {
    const incoming = route.request();
    const source = new URL(incoming.url());
    const target = new URL(source.pathname.replace('/api/backend/', '/') + source.search, process.env.TV_TEST_API_URL);
    const headers = {...incoming.headers()};
    delete headers.host;
    const response = await page.request.fetch(target.toString(), {method:incoming.method(),headers,data:incoming.postDataBuffer() ?? undefined});
    await route.fulfill({response});
  });
});

test('Free to Pro commercial lifecycle preserves limits and explains billing honestly', async ({page}) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('/login');
  await page.getByLabel('Your name').fill('Commercial Acceptance');
  await page.getByLabel('Email', {exact:true}).fill(`commercial-${Date.now()}@local.invalid`);
  await page.getByLabel('Organization', {exact:true}).fill('Commercial local acceptance');
  await page.getByRole('button', {name:'Open local workspace'}).click();
  await page.waitForURL('**/app');
  await page.goto('/app/billing');
  await expect(page.getByRole('heading', {name:/^FREE/})).toBeVisible();
  await expect(page.getByRole('button', {name:'Choose Pro', exact:true})).toBeEnabled();
  await page.getByRole('button', {name:'Choose Pro', exact:true}).click();
  await expect(page.getByRole('heading', {name:/^PRO/})).toBeVisible();
  await expect(page.getByText('Local billing simulation · No payment collected')).toBeVisible();
  await page.getByText('Local billing sandbox', {exact:true}).click();
  await page.getByRole('button', {name:'Simulate payment failure'}).click();
  await expect(page.getByText(/Payment grace ends/)).toBeVisible();
  await page.getByRole('button', {name:'Simulate payment recovery'}).click();
  await expect(page.getByText(/Payment grace ends/)).toHaveCount(0);
  await page.getByRole('button', {name:'Choose Free', exact:true}).click();
  await expect(page.getByText(/^Scheduled: FREE/)).toBeVisible();
  await expect(page.getByRole('heading', {name:/^PRO/})).toBeVisible();
  await page.screenshot({path:'../../.local/browser-tests/commercial-billing-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.screenshot({path:'../../.local/browser-tests/commercial-billing-mobile.png',fullPage:true});
  expect(errors).toEqual([]);
});

test('versioned public pricing exposes all five plans on mobile', async ({page}) => {
  await page.goto('/pricing');
  await expect(page.getByRole('heading', {name:'$99/ month'})).toBeVisible();
  await expect(page.getByRole('link', {name:'Start free', exact:true}).first()).toBeVisible();
  await expect(page.getByRole('link', {name:'Talk to us about Enterprise', exact:true})).toBeVisible();
  await expect(page.getByRole('heading', {name:'Contact us'}).first()).toBeVisible();
  await page.screenshot({path:'../../.local/browser-tests/commercial-pricing-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.screenshot({path:'../../.local/browser-tests/commercial-pricing-mobile.png',fullPage:true});
});
