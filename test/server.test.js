const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sera-drop-test-'));
const testUploadsDir = path.join(tmpRoot, 'uploads');
const testDataDir = path.join(tmpRoot, 'data');

process.env.NODE_ENV = 'test';
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
        notifierEmail: 'notifier@sera-compliance.test',
        goodFaithConfirmed: false
      })
    });
    assert.equal(invalidReportRes.status, 400);

    const publicReportRes = await fetch(`${baseUrl}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetCode: uploaded.code,
        category: 'copyright',
        explanation: 'Unauthorized distribution of copyrighted literary work.',
        notifierName: 'Rights Holder Legal',
        notifierEmail: 'notifier@sera-compliance.test',
        goodFaithConfirmed: true
      })
    });
    assert.equal(publicReportRes.status, 201);
    const publicBody = await publicReportRes.json();
    assert.match(publicBody.reportId, /^rep_/);
    assert.equal(publicBody.status, 'received');
    assert.equal(publicBody.mitigated, false);

    const checkStillExists = await fetch(`${baseUrl}/api/files/${uploaded.code}`);
    assert.equal(checkStillExists.status, 200);

    const adminReportRes = await fetch(`${baseUrl}/api/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-super-secret-admin-token-999'
      },
      body: JSON.stringify({
        targetCode: uploaded.code,
        category: 'copyright',
        explanation: 'Administrative takedown confirmed after human review.',
        notifierName: 'Compliance Officer',
        notifierEmail: 'officer@sera-compliance.test',
        goodFaithConfirmed: true
      })
    });
    assert.equal(adminReportRes.status, 201);
    const adminBody = await adminReportRes.json();
    assert.match(adminBody.reportId, /^rep_/);
    assert.equal(adminBody.status, 'action_taken');
    assert.equal(adminBody.mitigated, true);

    const checkDeleted = await fetch(`${baseUrl}/api/files/${uploaded.code}`);
    assert.equal(checkDeleted.status, 404);

    const reportsDiskRaw = fs.readFileSync(path.join(testDataDir, 'reports.json'), 'utf8');
    const reportsList = JSON.parse(reportsDiskRaw);
    assert.equal(reportsList.length, 2);
    assert.equal(reportsList[0].reportId, publicBody.reportId);
    assert.equal(reportsList[1].reportId, adminBody.reportId);
    assert.ok(
      typeof reportsList[0].clientIpHash === 'string' && /^[a-f0-9]{64}$/.test(reportsList[0].clientIpHash),
      'Stored report must contain 64-char hex HMAC-SHA256 clientIpHash'
    );
    assert.ok(!reportsDiskRaw.includes('127.0.0.1'), 'Raw client IP must never be written to reports.json');
  });

  it('preserves UTF-8 multibyte characters in uploaded filenames', async () => {
    const textBuf = Buffer.from('Multibyte filename content', 'utf8');
    const filename = 'привет-мир-äöü-🚀.txt';
    const upRes = await uploadMultipartFile({
      filename,
      contentType: 'text/plain',
      buffer: textBuf,
      fields: { ttl: '1h' }
    });
    assert.equal(upRes.status, 201);
    const uploaded = await upRes.json();
    assert.equal(uploaded.originalName, filename);
  });

  it('rejects uncompressed IPv6 loopback and mapped loopback addresses in URL upload', async () => {
    const res1 = await fetch(`${baseUrl}/api/url-upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'sera.drop'
      },
      body: JSON.stringify({ url: 'http://[0:0:0:0:0:0:0:1]:8080/test' })
    });
    assert.equal(res1.status, 412);

    const res2 = await fetch(`${baseUrl}/api/url-upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'sera.drop'
      },
      body: JSON.stringify({ url: 'http://[::ffff:127.0.0.1]:8080/test' })
    });
    assert.equal(res2.status, 412);
  });

  it('enforces atomic validation on Catbox batch file deletion', async () => {
    const textBuf = Buffer.from('Keep safe', 'utf8');
    const userhash = 'catbox-test-userhash-777';
    const upRes = await uploadMultipartFile({
      filename: 'catbox-doc.txt',
      contentType: 'text/plain',
      buffer: textBuf,
      fields: { userhash }
    });
    assert.equal(upRes.status, 201);
    const uploaded = await upRes.json();

    const delRes = await fetch(`${baseUrl}/user/api.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        reqtype: 'deletefiles',
        userhash,
        files: `${uploaded.code}.txt nonexistent123.txt`
      }).toString()
    });
    assert.equal(delRes.status, 400);

    const checkStillExists = await fetch(`${baseUrl}/api/files/${uploaded.code}`);
    assert.equal(checkStillExists.status, 200);
  });

  it('serves shared videos with Open Graph video and Twitter player tags for Discord unfurl', async () => {
    const mp4Header = Buffer.from('000000186674797069736f6d0000020069736f6d6d703432', 'hex');
    const mp4Body = Buffer.alloc(512, 0x41);
    const mp4Buffer = Buffer.concat([mp4Header, mp4Body]);
    const upRes = await uploadMultipartFile({
      filename: 'gameplay.mp4',
      contentType: 'video/mp4',
      buffer: mp4Buffer
    });
    assert.equal(upRes.status, 201);
    const uploaded = await upRes.json();
    assert.equal(uploaded.previewCategory, 'video');
    assert.equal(uploaded.mimeType, 'video/mp4');

    const discordCrawlerRes = await fetch(`${baseUrl}/s/${uploaded.code}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)'
      }
    });
    assert.equal(discordCrawlerRes.status, 200);
    const html = await discordCrawlerRes.text();

    assert.ok(html.includes('<meta property="og:type" content="video.other" />'));
    assert.ok(html.includes(`content="${baseUrl}/files/${uploaded.code}.mp4"`));
    assert.ok(html.includes('<meta property="og:video:type" content="video/mp4" />'));
    assert.ok(html.includes('<meta property="og:video:width" content="1280" />'));
    assert.ok(html.includes('<meta property="og:video:height" content="720" />'));
    assert.ok(html.includes('<meta name="twitter:card" content="player" />'));
    assert.ok(html.includes('<meta name="twitter:player:width" content="1280" />'));
    assert.ok(html.includes('<meta name="twitter:player:height" content="720" />'));
    assert.ok(html.includes('<meta name="twitter:player:stream:content_type" content="video/mp4" />'));
  });

  it('supports byte range requests, HEAD checks, and CORS for direct video streaming', async () => {
    const mp4Header = Buffer.from('000000186674797069736f6d0000020069736f6d6d703432', 'hex');
    const mp4Body = Buffer.alloc(1000, 0x42);
    const mp4Buffer = Buffer.concat([mp4Header, mp4Body]);
    const upRes = await uploadMultipartFile({
      filename: 'sample-video.mp4',
      contentType: 'application/octet-stream',
      buffer: mp4Buffer
    });
    assert.equal(upRes.status, 201);
    const uploaded = await upRes.json();
    assert.equal(uploaded.mimeType, 'video/mp4');
    assert.equal(uploaded.previewCategory, 'video');

    const optionsRes = await fetch(`${baseUrl}/files/${uploaded.code}.mp4`, {
      method: 'OPTIONS'
    });
    assert.equal(optionsRes.status, 204);
    assert.equal(optionsRes.headers.get('access-control-allow-origin'), '*');

    const headRes = await fetch(`${baseUrl}/files/${uploaded.code}.mp4`, {
      method: 'HEAD'
    });
    assert.equal(headRes.status, 200);
    assert.equal(headRes.headers.get('accept-ranges'), 'bytes');
    assert.equal(headRes.headers.get('content-type'), 'video/mp4');
    assert.equal(headRes.headers.get('access-control-allow-origin'), '*');
    assert.ok(headRes.headers.get('content-disposition')?.includes('inline'));

    const rangeRes = await fetch(`${baseUrl}/files/${uploaded.code}.mp4`, {
      headers: { Range: 'bytes=0-15' }
    });
    assert.equal(rangeRes.status, 206);
    assert.equal(rangeRes.headers.get('accept-ranges'), 'bytes');
    assert.equal(rangeRes.headers.get('content-type'), 'video/mp4');
    assert.match(rangeRes.headers.get('content-range') || '', /^bytes 0-15\/\d+$/);
    const chunk = await rangeRes.arrayBuffer();
    assert.equal(chunk.byteLength, 16);
  });

  it('preserves permanent files and restores database metadata from sidecars if files.json is removed', async () => {
    const pngBuffer = Buffer.from(
      '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2d0000000049454e44ae426082',
      'hex'
    );
    const upRes = await uploadMultipartFile({
      filename: 'permanent-image.png',
      contentType: 'image/png',
      buffer: pngBuffer,
      fields: { ttl: 'permanent' }
    });
    assert.equal(upRes.status, 201);
    const uploaded = await upRes.json();
    assert.equal(uploaded.ttl, 'permanent');
    assert.equal(uploaded.expiresAt, null);

    const dbPath = path.join(testDataDir, 'files.json');
    const dbBakPath = path.join(testDataDir, 'files.json.bak');
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    if (fs.existsSync(dbBakPath)) fs.unlinkSync(dbBakPath);

    const getRes = await fetch(`${baseUrl}/files/${uploaded.code}.png`);
    assert.equal(getRes.status, 200);

    const statusRes = await fetch(`${baseUrl}/api/status`);
    const statusData = await statusRes.json();
    assert.ok(statusData.totalFiles >= 1);
    assert.ok(fs.existsSync(dbPath));
  });

  it('exposes storage configuration and directory locations in /api/status', async () => {
    const unauthRes = await fetch(`${baseUrl}/api/status`);
    assert.equal(unauthRes.status, 200);
    const unauthData = await unauthRes.json();
    assert.equal(unauthData.storageRoot, null);
    assert.equal(unauthData.dataDir, null);
    assert.equal(unauthData.uploadsDir, null);
    assert.ok(typeof unauthData.isPersistentDisk === 'boolean');

    const adminRes = await fetch(`${baseUrl}/api/status`, {
      headers: {
        Authorization: `Bearer ${process.env.ADMIN_TOKEN}`
      }
    });
    assert.equal(adminRes.status, 200);
    const adminData = await adminRes.json();
    assert.ok(typeof adminData.storageRoot === 'string');
    assert.ok(typeof adminData.dataDir === 'string');
    assert.ok(typeof adminData.uploadsDir === 'string');
    assert.ok(typeof adminData.isPersistentDisk === 'boolean');
  });

  it('transparently reverse proxies requests when UPSTREAM_URL is configured', async () => {
    let mockReceivedPath = '';
    const mockUpstream = http.createServer((req, res) => {
      mockReceivedPath = req.url;
      res.writeHead(200, { 'Content-Type': 'application/json', 'X-Custom-Upstream': 'active' });
      res.end(JSON.stringify({ proxied: true, echoPath: req.url }));
    });
    await new Promise((resolve) => mockUpstream.listen(0, '127.0.0.1', resolve));
    const mockPort = mockUpstream.address().port;
    process.env.UPSTREAM_URL = `http://127.0.0.1:${mockPort}`;

    try {
      const res = await fetch(`${baseUrl}/any/sample/path?test=1`);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('x-custom-upstream'), 'active');
      const data = await res.json();
      assert.equal(data.proxied, true);
      assert.equal(mockReceivedPath, '/any/sample/path?test=1');
    } finally {
      delete process.env.UPSTREAM_URL;
      await new Promise((resolve) => mockUpstream.close(resolve));
    }
  });

  it('issues a secure HttpOnly sera_cid cookie and tracks per-client storage usage in /api/status', async () => {
    const res = await fetch(`${baseUrl}/api/status`);
    assert.equal(res.status, 200);
    const setCookie = res.headers.get('set-cookie') || '';
    assert.ok(setCookie.includes('sera_cid='), `Expected sera_cid cookie in set-cookie: ${setCookie}`);
    assert.ok(setCookie.includes('HttpOnly'), 'Cookie must be HttpOnly');
    assert.ok(setCookie.includes('SameSite=Lax'), 'Cookie must be SameSite=Lax');
    assert.ok(setCookie.includes('Path=/'), 'Cookie path must be /');

    const cookieMatch = setCookie.match(/sera_cid=([a-f0-9]{64})/i);
    assert.ok(cookieMatch, `Expected 64-character hex client id: ${setCookie}`);
    const clientCookie = `sera_cid=${cookieMatch[1]}`;

    const textBuf = Buffer.from('Cookie tracked payload data 12345', 'utf8');
    const form = new FormData();
    form.append('file', new Blob([textBuf], { type: 'text/plain' }), 'cookie-doc.txt');
    const upRes = await fetch(`${baseUrl}/api/upload`, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'sera.drop',
        Cookie: clientCookie
      },
      body: form
    });
    assert.equal(upRes.status, 201);
    const upData = await upRes.json();
    assert.equal(upData.size, textBuf.length);

    const statusWithCookie = await fetch(`${baseUrl}/api/status`, {
      headers: { Cookie: clientCookie }
    });
    assert.equal(statusWithCookie.status, 200);
    const statusData = await statusWithCookie.json();
    assert.equal(statusData.clientStorageUsedBytes, textBuf.length);
    assert.ok(statusData.clientStorageQuotaBytes > 0);
  });

  it('enforces per-client storage quota and rejects uploads exceeding limit', async () => {
    const customClientToken = 'a'.repeat(64);
    const clientCookie = `sera_cid=${customClientToken}`;

    process.env.MAX_CLIENT_STORAGE_BYTES = '1000';
    try {
      const payload1 = Buffer.from('Short allowed data', 'utf8');
      const form1 = new FormData();
      form1.append('file', new Blob([payload1], { type: 'text/plain' }), 'small.txt');
      const upRes1 = await fetch(`${baseUrl}/api/upload`, {
        method: 'POST',
        headers: {
          'X-Requested-With': 'sera.drop',
          Cookie: clientCookie
        },
        body: form1
      });
      assert.equal(upRes1.status, 201);

      const payload2 = Buffer.alloc(2000, 0x43);
      const form2 = new FormData();
      form2.append('file', new Blob([payload2], { type: 'text/plain' }), 'overflow.txt');
      const upRes2 = await fetch(`${baseUrl}/api/upload`, {
        method: 'POST',
        headers: {
          'X-Requested-With': 'sera.drop',
          Cookie: clientCookie
        },
        body: form2
      });
      assert.equal(upRes2.status, 507);
      const errData = await upRes2.json();
      assert.match(errData.error, /Client storage quota/);
    } finally {
      delete process.env.MAX_CLIENT_STORAGE_BYTES;
    }
  });

  it('lists client files via /api/files?mine=1 using cookie identity', async () => {
    const clientTokenA = 'b'.repeat(64);
    const cookieA = `sera_cid=${clientTokenA}`;
    const clientTokenB = 'c'.repeat(64);
    const cookieB = `sera_cid=${clientTokenB}`;

    const textBuf = Buffer.from('Client A unique content', 'utf8');
    const form = new FormData();
    form.append('file', new Blob([textBuf], { type: 'text/plain' }), 'doc-a.txt');
    const upRes = await fetch(`${baseUrl}/api/upload`, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'sera.drop',
        Cookie: cookieA
      },
      body: form
    });
    assert.equal(upRes.status, 201);
    const upData = await upRes.json();

    const listARes = await fetch(`${baseUrl}/api/files?mine=1`, {
      headers: { Cookie: cookieA }
    });
    assert.equal(listARes.status, 200);
    const listA = await listARes.json();
    assert.ok(Array.isArray(listA));
    assert.ok(listA.some((f) => f.code === upData.code));

    const listBRes = await fetch(`${baseUrl}/api/files?mine=1`, {
      headers: { Cookie: cookieB }
    });
    assert.equal(listBRes.status, 200);
    const listB = await listBRes.json();
    assert.ok(Array.isArray(listB));
    assert.ok(!listB.some((f) => f.code === upData.code));
  });

  it('allows deletion of files owned by the client via cookie identity without explicit delete token', async () => {
    const clientToken = 'd'.repeat(64);
    const cookie = `sera_cid=${clientToken}`;

    const textBuf = Buffer.from('To be deleted by cookie owner', 'utf8');
    const form = new FormData();
    form.append('file', new Blob([textBuf], { type: 'text/plain' }), 'deleteme.txt');
    const upRes = await fetch(`${baseUrl}/api/upload`, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'sera.drop',
        Cookie: cookie
      },
      body: form
    });
    assert.equal(upRes.status, 201);
    const upData = await upRes.json();

    const strangerCookie = `sera_cid=${'e'.repeat(64)}`;
    const strangerDelRes = await fetch(`${baseUrl}/api/files/${upData.code}`, {
      method: 'DELETE',
      headers: {
        'X-Requested-With': 'sera.drop',
        Cookie: strangerCookie
      }
    });
    assert.equal(strangerDelRes.status, 401);

    const ownerDelRes = await fetch(`${baseUrl}/api/files/${upData.code}`, {
      method: 'DELETE',
      headers: {
        'X-Requested-With': 'sera.drop',
        Cookie: cookie
      }
    });
    assert.equal(ownerDelRes.status, 200);
    const delData = await ownerDelRes.json();
    assert.equal(delData.success, true);

    const checkRes = await fetch(`${baseUrl}/api/files/${upData.code}`);
    assert.equal(checkRes.status, 404);
  });

  it('rejects remote URL uploads targeting non-standard web ports', async () => {
    const sshRes = await fetch(`${baseUrl}/api/url-upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'sera.drop'
      },
      body: JSON.stringify({ url: 'http://1.1.1.1:22/payload.bin' })
    });
    assert.equal(sshRes.status, 412);
    const sshData = await sshRes.json();
    assert.match(sshData.error, /Remote URL port is restricted/);

    const redisRes = await fetch(`${baseUrl}/api/url-upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'sera.drop'
      },
      body: JSON.stringify({ url: 'http://1.1.1.1:6379/redis' })
    });
    assert.equal(redisRes.status, 412);
    const redisData = await redisRes.json();
    assert.match(redisData.error, /Remote URL port is restricted/);
  });

  it('parses every report category from index.html and verifies acceptance in /api/report', async () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
    const selectMatch = html.match(/<select id="reportCategory"[^>]*>([\s\S]*?)<\/select>/);
    assert.ok(selectMatch, 'Expected #reportCategory select in index.html');
    const options = Array.from(selectMatch[1].matchAll(/<option value="([^"]+)"/g)).map((m) => m[1]);
    assert.ok(options.length >= 4);

    const testFile = await uploadMultipartFile({
      filename: 'report-target.txt',
      contentType: 'text/plain',
      buffer: Buffer.from('file for report testing', 'utf8')
    });
    const fileData = await testFile.json();

    for (const cat of options) {
      const res = await fetch(`${baseUrl}/api/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'sera.drop'
        },
        body: JSON.stringify({
          targetUrl: fileData.shortUrl,
          category: cat,
          explanation: `Testing report category: ${cat} with sufficient text length.`,
          notifierName: 'Compliance Test Inspector',
          notifierEmail: 'inspector@test.gov',
          goodFaithConfirmed: true
        })
      });
      assert.equal(res.status, 201, `Failed to submit report for category: ${cat}`);
      const body = await res.json();
      assert.ok(body.reportId);
    }
  });

  it('rejects adding signed files to shared albums and omits signature minting in album resolution (FINDING-01)', async () => {
    const signedUpRes = await uploadMultipartFile({
      filename: 'confidential.txt',
      contentType: 'text/plain',
      buffer: Buffer.from('top-secret-content', 'utf8'),
      fields: { requireSignedUrl: '1' }
    });
    assert.equal(signedUpRes.status, 201);
    const signedData = await signedUpRes.json();
    assert.equal(signedData.requireSignedUrl, true);

    const normalUpRes = await uploadMultipartFile({
      filename: 'public-doc.txt',
      contentType: 'text/plain',
      buffer: Buffer.from('public-content', 'utf8')
    });
    assert.equal(normalUpRes.status, 201);
    const normalData = await normalUpRes.json();

    const postAlbumRes = await fetch(`${baseUrl}/api/albums`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'sera.drop'
      },
      body: JSON.stringify({
        title: 'Secret Album',
        files: [signedData.code, normalData.code]
      })
    });
    assert.equal(postAlbumRes.status, 400);
    const postAlbumBody = await postAlbumRes.json();
    assert.equal(postAlbumBody.error, 'Files requiring signed URLs cannot be added to albums');

    const catboxAlbumForm = new FormData();
    catboxAlbumForm.append('reqtype', 'createalbum');
    catboxAlbumForm.append('files', `${signedData.code} ${normalData.code}`);
    const catboxAlbumRes = await fetch(`${baseUrl}/user/api.php`, {
      method: 'POST',
      body: catboxAlbumForm
    });
    assert.equal(catboxAlbumRes.status, 400);
    const catboxAlbumText = await catboxAlbumRes.text();
    assert.equal(catboxAlbumText, 'Files requiring signed URLs cannot be added to albums.');

    const validAlbumForm = new FormData();
    validAlbumForm.append('reqtype', 'createalbum');
    validAlbumForm.append('userhash', 'user-test-hash-1234');
    validAlbumForm.append('files', normalData.code);
    const validAlbumRes = await fetch(`${baseUrl}/user/api.php`, {
      method: 'POST',
      body: validAlbumForm
    });
    assert.equal(validAlbumRes.status, 200);
    const albumUrl = await validAlbumRes.text();
    const albumCode = albumUrl.split('/').pop();

    const editAlbumForm = new FormData();
    editAlbumForm.append('reqtype', 'editalbum');
    editAlbumForm.append('userhash', 'user-test-hash-1234');
    editAlbumForm.append('short', albumCode);
    editAlbumForm.append('files', `${normalData.code} ${signedData.code}`);
    const editAlbumRes = await fetch(`${baseUrl}/user/api.php`, {
      method: 'POST',
      body: editAlbumForm
    });
    assert.equal(editAlbumRes.status, 400);

    const getAlbumRes = await fetch(`${baseUrl}/api/albums/${albumCode}`);
    assert.equal(getAlbumRes.status, 200);
    const getAlbumData = await getAlbumRes.json();
    assert.equal(getAlbumData.files.length, 1);
    assert.ok(!getAlbumData.files[0].shortUrl.includes('sig='));
    assert.equal(getAlbumData.files[0].signedExpires, null);
  });

  it('ignores spoofed X-Real-IP headers in client IP resolution (FINDING-02)', async () => {
    const resSpoofed = await fetch(`${baseUrl}/api/status`, {
      headers: {
        'X-Real-IP': '198.51.100.99'
      }
    });
    assert.equal(resSpoofed.status, 200);

    const resCf = await fetch(`${baseUrl}/api/status`, {
      headers: {
        'CF-Connecting-IP': '203.0.113.88'
      }
    });
    assert.equal(resCf.status, 200);
  });

  it('prevents OpenGraph template pattern replacement injection for files with dollar syntax (FINDING-03)', async () => {
    const upRes = await uploadMultipartFile({
      filename: "proof$'injection$&template.txt",
      contentType: 'text/plain',
      buffer: Buffer.from('hello dollar syntax', 'utf8')
    });
    assert.equal(upRes.status, 201);
    const upData = await upRes.json();

    const sharePageRes = await fetch(`${baseUrl}/s/${upData.code}`);
    assert.equal(sharePageRes.status, 200);
    const html = await sharePageRes.text();

    assert.ok(!html.includes("proof\n</head>"));
    assert.equal(html.indexOf('<head>'), html.lastIndexOf('<head>'));
    assert.equal(html.indexOf('<body>'), html.lastIndexOf('<body>'));
    assert.ok(html.includes('&#39;injection'));
  });

  it('ensures signed share links include HMAC signature parameters (FINDING-05)', async () => {
    const upRes = await uploadMultipartFile({
      filename: 'signed-secret.txt',
      contentType: 'text/plain',
      buffer: Buffer.from('content inside signed file', 'utf8'),
      fields: { requireSignedUrl: '1' }
    });
    assert.equal(upRes.status, 201);
    const upData = await upRes.json();

    assert.ok(upData.shortUrl.includes('sig='));
    assert.ok(upData.shortUrl.includes('expires='));

    const parsedUrl = new URL(upData.shortUrl);
    const sig = parsedUrl.searchParams.get('sig');
    const expires = parsedUrl.searchParams.get('expires');

    const metaRes = await fetch(`${baseUrl}/api/files/${upData.code}?sig=${sig}&expires=${expires}`);
    assert.equal(metaRes.status, 200);
    const metaData = await metaRes.json();
    assert.equal(metaData.code, upData.code);
    assert.ok(metaData.downloadUrl.includes('sig='));
    assert.ok(metaData.rawUrl.includes('sig='));

    const unauthMetaRes = await fetch(`${baseUrl}/api/files/${upData.code}`);
    assert.equal(unauthMetaRes.status, 403);
  });

  it('hides deduplication metadata from public unauthenticated callers (FINDING-11)', async () => {
    const ownerCookie = `sera_cid=${'f'.repeat(64)}`;
    const textBuffer = Buffer.from('dedup oracle test string payload 1234567890', 'utf8');

    const firstUp = await fetch(`${baseUrl}/api/upload`, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'sera.drop',
        Cookie: ownerCookie
      },
      body: (() => {
        const f = new FormData();
        f.append('file', new Blob([textBuffer], { type: 'text/plain' }), 'dedup1.txt');
        return f;
      })()
    });
    assert.equal(firstUp.status, 201);
    const firstData = await firstUp.json();
    assert.equal(firstData.deduplicated, false);

    const secondUp = await fetch(`${baseUrl}/api/upload`, {
      method: 'POST',
      headers: {
        'X-Requested-With': 'sera.drop',
        Cookie: ownerCookie
      },
      body: (() => {
        const f = new FormData();
        f.append('file', new Blob([textBuffer], { type: 'text/plain' }), 'dedup2.txt');
        return f;
      })()
    });
    assert.equal(secondUp.status, 201);
    const secondData = await secondUp.json();
    assert.equal(secondData.deduplicated, true);

    const strangerRes = await fetch(`${baseUrl}/api/files/${secondData.code}`, {
      headers: {
        Cookie: `sera_cid=${'1'.repeat(64)}`
      }
    });
    assert.equal(strangerRes.status, 200);
    const strangerData = await strangerRes.json();
    assert.equal(strangerData.deduplicated, false);
  });

  it('enforces strict Cache-Control and HSTS security headers (FINDING-10 & Item A3)', async () => {
    const permUp = await uploadMultipartFile({
      filename: 'permanent-cache.txt',
      contentType: 'text/plain',
      buffer: Buffer.from('permanent cache data', 'utf8')
    });
    const permData = await permUp.json();

    const rawPermRes = await fetch(`${baseUrl}/raw/${permData.code}`);
    assert.equal(rawPermRes.status, 200);
    assert.equal(rawPermRes.headers.get('cache-control'), 'public, max-age=86400, immutable');

    const signedUp = await uploadMultipartFile({
      filename: 'ephemeral-signed.txt',
      contentType: 'text/plain',
      buffer: Buffer.from('signed cache data', 'utf8'),
      fields: { requireSignedUrl: '1' }
    });
    const signedData = await signedUp.json();
    const rawSignedUrl = new URL(signedData.rawUrl);

    const rawSignedRes = await fetch(signedData.rawUrl);
    assert.equal(rawSignedRes.status, 200);
    assert.equal(rawSignedRes.headers.get('cache-control'), 'private, no-cache, no-store, must-revalidate');
    assert.equal(rawSignedRes.headers.get('pragma'), 'no-cache');

    const raw404Res = await fetch(`${baseUrl}/raw/notfound123`);
    assert.equal(raw404Res.status, 404);
    assert.equal(raw404Res.headers.get('cache-control'), 'no-store, no-cache, must-revalidate, proxy-revalidate');

    const hstsRes = await fetch(`${baseUrl}/api/status`, {
      headers: {
        'X-Forwarded-Proto': 'https'
      }
    });
    assert.equal(hstsRes.status, 200);
    assert.equal(
      hstsRes.headers.get('strict-transport-security'),
      'max-age=63072000; includeSubDomains; preload'
    );
  });

  it('rejects extended SSRF payloads across both URL upload endpoints (Item A2)', async () => {
    const ssrfTargets = [
      'http://0.0.0.0/test',
      'http://100.64.0.1/test',
      'http://198.18.0.1/test',
      'http://224.0.0.1/test',
      'http://[::ffff:127.0.0.1]/test',
      'http://[::ffff:7f00:1]/test'
    ];

    for (const target of ssrfTargets) {
      const apiRes = await fetch(`${baseUrl}/api/url-upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'sera.drop'
        },
        body: JSON.stringify({ url: target })
      });
      assert.equal(apiRes.status, 412, `Expected 412 for /api/url-upload targeting ${target}`);

      const catboxForm = new FormData();
      catboxForm.append('reqtype', 'urlupload');
      catboxForm.append('url', target);
      const catboxRes = await fetch(`${baseUrl}/user/api.php`, {
        method: 'POST',
        body: catboxForm
      });
      assert.equal(catboxRes.status, 412, `Expected 412 for /user/api.php targeting ${target}`);
    }
  });

  it('enforces CSRF sec-fetch-site protection on Litterbox and Catbox endpoints', async () => {
    const litterForm = new FormData();
    litterForm.append('reqtype', 'fileupload');
    litterForm.append('time', '1h');
    litterForm.append('fileToUpload', new Blob(['sample'], { type: 'text/plain' }), 'test.txt');

    const litterRes = await fetch(`${baseUrl}/resources/internals/api.php`, {
      method: 'POST',
      headers: {
        'sec-fetch-site': 'cross-site',
        origin: 'https://malicious-origin.com'
      },
      body: litterForm
    });
    assert.equal(litterRes.status, 403);
    const litterText = await litterRes.text();
    assert.equal(litterText, 'Cross-site requests not allowed.');

    const catboxForm = new FormData();
    catboxForm.append('reqtype', 'fileupload');
    catboxForm.append('fileToUpload', new Blob(['sample'], { type: 'text/plain' }), 'test.txt');

    const catboxRes = await fetch(`${baseUrl}/user/api.php`, {
      method: 'POST',
      headers: {
        'sec-fetch-site': 'cross-site',
        origin: 'https://malicious-origin.com'
      },
      body: catboxForm
    });
    assert.equal(catboxRes.status, 403);
    const catboxText = await catboxRes.text();
    assert.equal(catboxText, 'Cross-site requests not allowed.');
  });
});
