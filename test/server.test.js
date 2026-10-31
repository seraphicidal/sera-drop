const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sera-drop-test-'));
const testUploadsDir = path.join(tmpRoot, 'uploads');
const testDataDir = path.join(tmpRoot, 'data');

process.env.UPLOADS_DIR = testUploadsDir;
process.env.DATA_DIR = testDataDir;
process.env.ADMIN_TOKEN = 'test-super-secret-admin-token-999';
process.env.SERA_DROP_SECRET = 'test-hmac-secret-key-for-signed-links-123456';
process.env.DISABLE_TUNNEL = 'true';
process.env.OPERATOR_NAME = 'SERA Compliance Test GmbH';
process.env.OPERATOR_ADDRESS = 'Friedrichstraße 100, 10117 Berlin, Germany';
process.env.OPERATOR_EMAIL = 'compliance@sera-drop.test';

const { app } = require('../server.js');

let server;
let baseUrl;

before(async () => {
  await new Promise((resolve) => {
    server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

async function uploadMultipartFile({ filename, contentType, buffer, fields = {} }) {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) {
    form.append(k, String(v));
  }
  const blob = new Blob([buffer], { type: contentType });
  form.append('file', blob, filename);

  return fetch(`${baseUrl}/api/upload`, {
    method: 'POST',
    headers: {
      'X-Requested-With': 'sera.drop'
    },
    body: form
  });
}

describe('sera-drop Security & Legal Compliance Suite', () => {
  it('enforces strict Content-Security-Policy without unsafe-inline in script-src or Google Fonts', async () => {
    const res = await fetch(`${baseUrl}/api/status`);
    assert.equal(res.status, 200);
    const csp = res.headers.get('content-security-policy') || '';
    assert.ok(csp.includes("script-src 'self'"), `Expected script-src 'self' in CSP: ${csp}`);
    assert.ok(!csp.includes("script-src 'self' 'unsafe-inline'"), 'script-src must not allow unsafe-inline');
    assert.ok(!csp.includes('fonts.googleapis.com'), 'CSP must not reference fonts.googleapis.com');
    assert.ok(!csp.includes('fonts.gstatic.com'), 'CSP must not reference fonts.gstatic.com');
  });

  it('rejects unauthenticated localhost requests to admin and full file listing endpoints (no localhost privilege escalation)', async () => {
    const listRes = await fetch(`${baseUrl}/api/files`);
    assert.equal(listRes.status, 401);
    const listBody = await listRes.json();
    assert.equal(listBody.error, 'Unauthorized: valid Bearer ADMIN_TOKEN required');

    const adminFilesRes = await fetch(`${baseUrl}/api/admin/files`);
    assert.equal(adminFilesRes.status, 401);

    const wrongTokenRes = await fetch(`${baseUrl}/api/admin/files`, {
      headers: { Authorization: 'Bearer wrong-token' }
    });
    assert.equal(wrongTokenRes.status, 401);

    const validAdminRes = await fetch(`${baseUrl}/api/admin/files`, {
      headers: { Authorization: `Bearer ${process.env.ADMIN_TOKEN}` }
    });
    assert.equal(validAdminRes.status, 200);
    const validAdminBody = await validAdminRes.json();
    assert.ok(Array.isArray(validAdminBody.files));
  });

  it('rejects Windows PE, Linux ELF, and macOS Mach-O binaries disguised with .png or .txt extensions via magic-byte inspection', async () => {
    const peBuffer = Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), Buffer.alloc(128, 0x00)]);
    const peRes = await uploadMultipartFile({
      filename: 'innocent-image.png',
      contentType: 'image/png',
      buffer: peBuffer
    });
    assert.equal(peRes.status, 415);
    const peData = await peRes.json();
    assert.match(peData.error, /Executable binaries \(PE\/ELF\/Mach-O\) are not permitted/);

    const elfBuffer = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01]), Buffer.alloc(128, 0x00)]);
    const elfRes = await uploadMultipartFile({
      filename: 'readme.txt',
      contentType: 'text/plain',
      buffer: elfBuffer
    });
    assert.equal(elfRes.status, 415);
    const elfData = await elfRes.json();
    assert.match(elfData.error, /Executable binaries \(PE\/ELF\/Mach-O\) are not permitted/);

    const machoBuffer = Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.alloc(128, 0x00)]);
    const machoRes = await uploadMultipartFile({
      filename: 'avatar.png',
      contentType: 'image/png',
      buffer: machoBuffer
    });
    assert.equal(machoRes.status, 415);
    const machoData = await machoRes.json();
    assert.match(machoData.error, /Executable binaries \(PE\/ELF\/Mach-O\) are not permitted/);
  });

  it('signs protected URLs with HMAC-SHA256 and enforces constant-time signature verification', async () => {
    const validPng = Buffer.from(
      '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082',
      'hex'
    );
    const upRes = await uploadMultipartFile({
      filename: 'pixel.png',
      contentType: 'image/png',
      buffer: validPng,
      fields: { requireSignedUrl: 'true', ttl: '1h' }
    });
    assert.equal(upRes.status, 201);
    const payload = await upRes.json();
    assert.equal(payload.requireSignedUrl, true);
    assert.ok(payload.rawUrl.includes('?sig='), `Expected HMAC-SHA256 ?sig= parameter in ${payload.rawUrl}`);
    assert.ok(!payload.rawUrl.includes('?md5='), 'Signed URL must not use legacy ?md5= query parameter');

    const unsignedRes = await fetch(`${baseUrl}/raw/${payload.code}`);
    assert.equal(unsignedRes.status, 403);

    const parsedRaw = new URL(payload.rawUrl);
    const validSig = parsedRaw.searchParams.get('sig');
    const expires = parsedRaw.searchParams.get('expires');
    assert.equal(validSig.length, 43);

    const tamperedRes = await fetch(`${baseUrl}/raw/${payload.code}?sig=${validSig.slice(0, -2)}aa&expires=${expires}`);
    assert.equal(tamperedRes.status, 403);

    const validSignedRes = await fetch(`${baseUrl}${parsedRaw.pathname}${parsedRaw.search}`);
    assert.equal(validSignedRes.status, 200);

    const unauthDeleteRes = await fetch(`${baseUrl}/api/files/${payload.code}`, {
      method: 'DELETE',
      headers: { 'X-Requested-With': 'sera.drop' }
    });
    assert.equal(unauthDeleteRes.status, 401);

    const ownerDeleteRes = await fetch(`${baseUrl}/api/files/${payload.code}`, {
      method: 'DELETE',
      headers: {
        'X-Requested-With': 'sera.drop',
        'X-Delete-Token': payload.deleteToken
      }
    });
    assert.equal(ownerDeleteRes.status, 200);
  });

  it('serves /impressum (DDG § 5) and /privacy (GDPR Art. 13) without inline scripts or external fonts', async () => {
    const impRes = await fetch(`${baseUrl}/impressum`);
    assert.equal(impRes.status, 200);
    const impHtml = await impRes.text();
    assert.ok(impHtml.includes('SERA Compliance Test GmbH'));
    assert.ok(impHtml.includes('Friedrichstraße 100, 10117 Berlin, Germany'));
    assert.ok(impHtml.includes('compliance@sera-drop.test'));
    assert.ok(impHtml.includes('DDG'));
    assert.ok(!impHtml.includes('<script'));
    assert.ok(!impHtml.includes('fonts.googleapis.com'));

    const privRes = await fetch(`${baseUrl}/privacy`);
    assert.equal(privRes.status, 200);
    const privHtml = await privRes.text();
    assert.ok(privHtml.includes('Art. 13 GDPR'));
    assert.ok(privHtml.includes('Art. 6(1)(b)'));
    assert.ok(privHtml.includes('Art. 6(1)(f)'));
    assert.ok(privHtml.includes('Art. 6(1)(c)'));
    assert.ok(privHtml.includes('localStorage'));
    assert.ok(privHtml.includes('72h'));
    assert.ok(privHtml.includes('Art. 77 GDPR'));
    assert.ok(!privHtml.includes('<script'));
  });

  it('processes DSA Art. 16 notices via POST /api/report, hashes client IP, and mitigates reported files', async () => {
    const textBuf = Buffer.from('Sample reported content for DSA takedown test', 'utf8');
    const upRes = await uploadMultipartFile({
      filename: 'infringing-doc.txt',
      contentType: 'text/plain',
      buffer: textBuf,
      fields: { ttl: '1h' }
    });
    assert.equal(upRes.status, 201);
    const uploaded = await upRes.json();

    const invalidReportRes = await fetch(`${baseUrl}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetCode: uploaded.code,
        category: 'copyright',
        explanation: 'Unauthorized distribution of copyrighted literary work.',
        notifierName: 'Jane Doe',
        notifierEmail: 'jane@example.com',
        goodFaithConfirmed: false
      })
    });
    assert.equal(invalidReportRes.status, 400);

    const validReportRes = await fetch(`${baseUrl}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetCode: uploaded.code,
        category: 'copyright',
        explanation: 'Unauthorized distribution of copyrighted literary work.',
        notifierName: 'Jane Doe',
        notifierEmail: 'jane@example.com',
        goodFaithConfirmed: true
      })
    });
    assert.equal(validReportRes.status, 201);
    const reportBody = await validReportRes.json();
    assert.match(reportBody.reportId, /^rep_/);
    assert.equal(reportBody.status, 'action_taken');
    assert.equal(reportBody.mitigated, true);

    const checkDeleted = await fetch(`${baseUrl}/api/files/${uploaded.code}`);
    assert.equal(checkDeleted.status, 404);

    const reportsDiskRaw = fs.readFileSync(path.join(testDataDir, 'reports.json'), 'utf8');
    const reportsList = JSON.parse(reportsDiskRaw);
    assert.equal(reportsList.length, 1);
    assert.equal(reportsList[0].reportId, reportBody.reportId);
    assert.ok(
      typeof reportsList[0].clientIpHash === 'string' && /^[a-f0-9]{64}$/.test(reportsList[0].clientIpHash),
      'Stored report must contain 64-char hex HMAC-SHA256 clientIpHash'
    );
    assert.ok(!reportsDiskRaw.includes('127.0.0.1'), 'Raw client IP must never be written to reports.json');
  });
});
