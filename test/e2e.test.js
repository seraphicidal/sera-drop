const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sera-drop-e2e-'));
const testUploadsDir = path.join(tmpRoot, 'uploads');
const testDataDir = path.join(tmpRoot, 'data');

process.env.NODE_ENV = 'test';
process.env.UPLOADS_DIR = testUploadsDir;
process.env.DATA_DIR = testDataDir;
process.env.ADMIN_TOKEN = 'test-e2e-admin-token-999';
process.env.SERA_DROP_SECRET = 'test-e2e-secret-key-12345678901234567890';
process.env.DISABLE_TUNNEL = 'true';

const { app } = require('../server.js');

let server;
let baseUrl;
let browser;

before(async () => {
  await new Promise((resolve) => {
    server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });

  browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
});

after(async () => {
  if (browser) {
    await browser.close();
  }
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

describe('sera-drop End-to-End Signed URL Flow (Playwright)', () => {
  it('allows recipient to preview and download signed file via shared URL in fresh context', async () => {
    const fileContent = 'Sensitive document content for E2E verification';
    const form = new FormData();
    form.append('file', new Blob([fileContent], { type: 'text/plain' }), 'confidential-notes.txt');
    form.append('requireSignedUrl', 'true');

    const uploadRes = await fetch(`${baseUrl}/api/upload`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'sera.drop' },
      body: form
    });
    assert.equal(uploadRes.status, 201);
    const uploadData = await uploadRes.json();
    assert.ok(uploadData.shortUrl.includes('sig='));
    assert.ok(uploadData.shortUrl.includes('expires='));

    const context = await browser.newContext();
    const page = await context.newPage();

    await page.goto(uploadData.shortUrl, { waitUntil: 'domcontentloaded' });

    const titleEl = await page.waitForSelector('.share-file-title', { timeout: 5000 });
    const titleText = await titleEl.textContent();
    assert.equal(titleText.trim(), 'confidential-notes.txt');

    const downloadBtn = await page.waitForSelector('#downloadBtn', { timeout: 5000 });
    const dlHref = await downloadBtn.getAttribute('href');
    assert.ok(dlHref.includes('/d/'));
    assert.ok(dlHref.includes('sig='));
    assert.ok(dlHref.includes('expires='));

    const previewEl = await page.waitForSelector('.preview-text', { timeout: 5000 });
    const previewText = await previewEl.textContent();
    assert.ok(previewText.includes('Sensitive document content for E2E verification'));

    const downloadResponse = await page.request.get(dlHref);
    assert.equal(downloadResponse.status(), 200);
    const downloadedBody = await downloadResponse.text();
    assert.equal(downloadedBody, fileContent);

    await context.close();
  });

  it('rejects access and displays error when signed URL expiration has passed', async () => {
    const fileContent = 'Data that will expire soon';
    const form = new FormData();
    form.append('file', new Blob([fileContent], { type: 'text/plain' }), 'expiring-file.txt');
    form.append('requireSignedUrl', 'true');

    const uploadRes = await fetch(`${baseUrl}/api/upload`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'sera.drop' },
      body: form
    });
    assert.equal(uploadRes.status, 201);
    const uploadData = await uploadRes.json();

    const expiredUrl = new URL(uploadData.shortUrl);
    const pastExpires = Math.floor(Date.now() / 1000) - 300;
    expiredUrl.searchParams.set('expires', String(pastExpires));

    const directApiRes = await fetch(`${baseUrl}/api/files/${uploadData.code}${expiredUrl.search}`);
    assert.equal(directApiRes.status, 403);

    const context = await browser.newContext();
    const page = await context.newPage();

    await page.goto(expiredUrl.href, { waitUntil: 'domcontentloaded' });

    const errorEl = await page.waitForSelector('.empty-card-panel, #inlineErrorText', { timeout: 5000 });
    const errorText = await errorEl.textContent();
    assert.ok(errorText.includes('does not exist or has expired') || errorText.includes('Not Found'));

    await context.close();
  });
});
