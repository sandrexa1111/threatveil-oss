import { test } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

// Builds the contact sheet (mandate §25) from a directory of screenshots: every screen at the
// same scale, labelled, so "does this look like one product?" can be judged without reading.
test('contact sheet', async ({page}) => {
  const dir = process.env.SHEET_DIR || '/work/.local/final-shots';
  const out = process.env.SHEET_OUT || `${dir}/contact-sheet.png`;
  const title = process.env.SHEET_TITLE || 'ThreatVeil — redesigned product';
  const metrics = fs.existsSync(`${dir}/metrics.json`)
    ? JSON.parse(fs.readFileSync(`${dir}/metrics.json`, 'utf8')).metrics as {name: string; label: string}[] : [];
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.png') && !f.startsWith('contact')).sort();
  const tiles = files.map(file => {
    const name = path.basename(file, '.png');
    const label = metrics.find(m => m.name === name)?.label || name;
    const data = fs.readFileSync(path.join(dir, file)).toString('base64');
    return `<figure><div class="frame"><img src="data:image/png;base64,${data}"></div><figcaption>${label}</figcaption></figure>`;
  }).join('');
  await page.setViewportSize({width: 2400, height: 1200});
  await page.setContent(`<!doctype html><html><head><style>
    body{margin:0;padding:40px;background:#e9ebe8;font:14px -apple-system,'Segoe UI',sans-serif;color:#15302c}
    h1{font-size:22px;margin:0 0 24px;letter-spacing:-.02em}
    .grid{display:grid;grid-template-columns:repeat(5,1fr);gap:22px}
    figure{margin:0}
    .frame{height:520px;overflow:hidden;border-radius:8px;border:1px solid #d5dad3;background:#fff}
    img{width:100%;display:block}
    figcaption{margin-top:8px;font-size:13px;color:#52615a}
  </style></head><body><h1>${title}</h1><div class="grid">${tiles}</div></body></html>`);
  await page.waitForTimeout(800);
  await page.screenshot({path: out, fullPage: true});
  console.log(`SHEET ${out} tiles=${files.length}`);
});
