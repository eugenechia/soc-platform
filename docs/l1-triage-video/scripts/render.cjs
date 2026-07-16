/**
 * Headless render driver (adapted from SOC-Copilot detection-engineer-video).
 * Prereq: `npm run serve` running on :9000. Playwright is borrowed from the
 * SOC-Copilot video project's node_modules:
 *
 *   NODE_PATH="../../../SOC-Copilot/docs/detection-engineer-video/node_modules" \
 *     node scripts/render.cjs <project>            # e.g. prodarch
 *
 * Opens the <project>.project editor, clicks RENDER, and polls
 * output/<project>.project.mp4 until its size stabilises.
 */
const {chromium} = require('playwright');
const fs = require('fs'), path = require('path');

const project = process.argv[2];
if (!project) { console.error('usage: node scripts/render.cjs <project>'); process.exit(1); }

const OUT = path.resolve(__dirname, '..', 'output', `${project}.project.mp4`);
const URL = `http://localhost:9000/src/${project}.project`;

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport: {width: 1600, height: 900}});
  p.on('pageerror', e => console.log('PAGEERR', e.message.slice(0, 160)));
  await p.goto(URL, {waitUntil: 'networkidle', timeout: 60000});
  await p.waitForTimeout(6000);

  await p.locator("button:has-text('RENDER')").first().click();
  console.log('RENDER clicked', new Date().toISOString());

  const start = Date.now();
  let lastSize = -1, stable = 0;
  while (Date.now() - start < 60 * 60 * 1000) {
    await p.waitForTimeout(5000);
    const size = fs.existsSync(OUT) ? fs.statSync(OUT).size : 0;
    console.log(`[${Math.round((Date.now() - start) / 1000)}s] bytes=${size}`);
    if (size > 0) {
      if (size === lastSize) { if (++stable >= 5) break; }
      else { stable = 0; lastSize = size; }
    }
  }
  if (fs.existsSync(OUT)) console.log('output:', OUT, fs.statSync(OUT).size, 'bytes');
  else { console.error('FAIL: no output produced'); process.exit(1); }
  await b.close();
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
