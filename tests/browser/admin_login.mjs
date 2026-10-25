// The admin login form in real browsers (Playwright's Chromium and
// Firefox): a browser decides a form post's Origin from the page's
// Referrer-Policy, which a scripted request does not show. Under
// no-referrer both sent Origin: null, which SameOrigin refused, so nobody
// could log in.
//
//     OPENCE_MASTER_BIN=<a built opence-master> node tests/browser/admin_login.mjs
//
// (with Playwright where Node finds it, NODE_PATH)

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const require = createRequire(import.meta.url);
const playwright = require('playwright');

const binary = process.env.OPENCE_MASTER_BIN || 'opence-master';
const work = mkdtempSync(path.join(tmpdir(), 'opence-master-browser-'));
const token = 'browser-test-admin-token-0123456789abcdef';
const port = 18000 + Math.floor(Math.random() * 1000);
let failed = 0;

await new Promise((resolve, reject) => {
  const keygen = spawn(binary, ['keygen', '--out', path.join(work, 'master.key')], { stdio: 'ignore' });
  keygen.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`keygen exited ${code}`))));
});
const master = spawn(binary, ['serve'], {
  stdio: 'ignore',
  env: { ...process.env, MASTER_NAME: 'Browser Test', MASTER_CONTACT: 'test@example.org',
    MASTER_DB: path.join(work, 'master.db'), MASTER_KEY: path.join(work, 'master.key'), MASTER_ADMIN_TOKEN: token,
    MASTER_LISTEN: `127.0.0.1:${port}` },
});
try {
  const base = `http://127.0.0.1:${port}`;
  for (let waited = 0; waited < 50; waited++) {
    if (await fetch(base + '/healthz').then((answer) => answer.ok, () => false)) break;
    await sleep(100);
  }
  for (const kind of ['chromium', 'firefox']) {
    const browser = await playwright[kind].launch({ headless: true });
    try {
      const page = await browser.newPage();
      await page.goto(base + '/admin/');
      await page.fill('#token', token);
      await Promise.all([page.waitForNavigation(), page.click('button[type=submit]')]);
      const ok = new URL(page.url()).pathname === '/admin/applications' &&
        !/form was refused/.test(await page.textContent('body'));
      console.log(`${kind}: ${ok ? 'logged in' : 'REFUSED'} (${page.url()})`);
      if (!ok) failed++;
    } finally {
      await browser.close();
    }
  }
} finally {
  master.kill();
  rmSync(work, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
