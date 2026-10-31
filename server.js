const express = require('express');
const multer = require('multer');
const QRCode = require('qrcode');
const { bin, install, Tunnel } = require('cloudflared');
const FileType = require('file-type');
const crypto = require('crypto');
const dns = require('dns');
const http = require('http');
const https = require('https');
const net = require('net');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.set('trust proxy', 1);

const UPLOADS_DIR = process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : path.join(__dirname, 'uploads');
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'files.json');
const ALBUMS_FILE = path.join(DATA_DIR, 'albums.json');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');
const BLOCKED_HASHES_FILE = path.join(DATA_DIR, 'blocked_hashes.json');
const PID_FILE = path.join(DATA_DIR, 'server.pid');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');

const MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024;
const MAX_GIF_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_TOTAL_STORAGE_BYTES = 5 * 1024 * 1024 * 1024;
const MAX_CONCURRENT_UPLOADS = 5;
const SIGNED_URL_TTL_SECONDS = 240;

const TTL_PRESETS_MS = {
  '1h': 60 * 60 * 1000,
  '12h': 12 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '72h': 72 * 60 * 60 * 1000
};

const BLOCKED_PUBLIC_EXTENSIONS = new Set([
  '.exe', '.scr', '.cpl', '.jar', '.msi', '.msp', '.mst', '.bat', '.cmd', '.com',
  '.vbs', '.vbe', '.wsf', '.wsh', '.hta', '.reg', '.dll', '.sys', '.drv', '.pif',
  '.gadget', '.application', '.lnk', '.htaccess', '.php', '.phtml', '.phar', '.asp', '.aspx', '.jsp',
  '.elf', '.bin', '.run', '.dylib', '.so'
]);

const BLOCKED_PUBLIC_MIMES = new Set([
  'application/x-msdownload',
  'application/exe',
  'application/x-dosexec',
  'application/x-msdos-program',
  'application/x-ms-shortcut',
  'application/x-msi',
  'application/hta',
  'application/x-executable',
  'application/x-elf',
  'application/x-mach-binary'
]);

const BLOCKED_DETECTED_EXTENSIONS = new Set([
  'exe', 'dll', 'elf', 'mach-o', 'msi', 'com', 'scr'
]);

const BLOCKED_DETECTED_MIMES = new Set([
  'application/x-msdownload',
  'application/x-executable',
  'application/x-elf',
  'application/x-mach-binary',
  'application/x-dosexec'
]);

const XSS_SENSITIVE_EXTENSIONS = new Set([
  '.html', '.htm', '.xhtml', '.shtml', '.svg', '.svgz', '.xml', '.xsl', '.xslt',
  '.php', '.phtml', '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.vue',
  '.htaccess', '.mht', '.mhtml', '.swf'
]);

const SAFE_INLINE_MEDIA_MIMES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/avif',
  'image/bmp',
  'image/x-icon',
  'video/mp4',
  'video/webm',
  'video/ogg',
  'video/quicktime',
  'audio/mpeg',
  'audio/mp3',
  'audio/ogg',
  'audio/wav',
  'audio/x-wav',
  'audio/webm',
  'audio/flac',
  'audio/aac',
  'audio/mp4',
  'application/pdf'
]);

const VALID_REPORT_CATEGORIES = new Set([
  'copyright',
  'malware',
  'illegal_content',
  'other'
]);

let activeUploads = 0;
let cloudflareUrl = null;
let publicBaseUrl = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || null;

fs.mkdirSync(UPLOADS_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({}, null, 2), 'utf8');
}
if (!fs.existsSync(ALBUMS_FILE)) {
  fs.writeFileSync(ALBUMS_FILE, JSON.stringify({}, null, 2), 'utf8');
}
if (!fs.existsSync(REPORTS_FILE)) {
  fs.writeFileSync(REPORTS_FILE, JSON.stringify([], null, 2), 'utf8');
}
if (!fs.existsSync(BLOCKED_HASHES_FILE)) {
  fs.writeFileSync(BLOCKED_HASHES_FILE, JSON.stringify({}, null, 2), 'utf8');
}

function loadOrCreateSecret() {
  if (process.env.SERA_DROP_SECRET && String(process.env.SERA_DROP_SECRET).trim().length >= 16) {
    return String(process.env.SERA_DROP_SECRET).trim();
  }
  try {
    if (fs.existsSync(SECRET_FILE)) {
      const existing = fs.readFileSync(SECRET_FILE, 'utf8').trim();
      if (existing.length >= 32) {
        return existing;
      }
    }
    const generated = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(SECRET_FILE, generated, { encoding: 'utf8', mode: 0o600 });
    return generated;
  } catch {
    return crypto.randomBytes(32).toString('hex');
  }
}

const SECURE_LINK_SECRET = loadOrCreateSecret();

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
  );
  next();
});

function getClientIp(req) {
  if (process.env.TRUST_CF_HEADERS === 'true' && typeof req.headers['cf-connecting-ip'] === 'string') {
    return req.headers['cf-connecting-ip'].trim();
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function hashClientIp(req) {
  return crypto
    .createHmac('sha256', SECURE_LINK_SECRET)
    .update(String(getClientIp(req)))
    .digest('hex');
}

function createRateLimiter({ windowMs, maxRequests, message }) {
  const buckets = new Map();
  return (req, res, next) => {
    const ip = getClientIp(req);
    const now = Date.now();

    if (buckets.size > 2000) {
      for (const [k, v] of buckets.entries()) {
        if (now > v.resetAt) buckets.delete(k);
      }
      if (buckets.size > 5000) {
        buckets.clear();
      }
    }

    let bucket = buckets.get(ip);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(ip, bucket);
    }
    bucket.count += 1;
    if (bucket.count > maxRequests) {
      return res.status(429).json({ error: message || 'Too many requests, please try again later.' });
    }
    next();
  };
}

const uploadRateLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  maxRequests: 40,
  message: 'Upload rate limit exceeded. Please wait a few minutes.'
});

const lookupRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 180,
  message: 'Too many requests. Please slow down.'
});

const reportRateLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  maxRequests: 20,
  message: 'Too many abuse reports submitted. Please try again later.'
});

function requireCsrfHeader(req, res, next) {
  if (req.headers['x-requested-with'] !== 'sera.drop') {
    return res.status(403).json({ error: 'Missing required security header (X-Requested-With)' });
  }
  next();
}

function safeTimingEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function hasValidAdminAuth(req) {
  const configuredToken = String(process.env.ADMIN_TOKEN || '').trim();
  if (!configuredToken) return false;
  const authHeader = String(req.headers.authorization || '');
  if (!authHeader.startsWith('Bearer ')) return false;
  const providedToken = authHeader.slice(7).trim();
  if (!providedToken) return false;
  return safeTimingEqualStrings(providedToken, configuredToken);
}

function requireAdminAuth(req, res, next) {
  if (!hasValidAdminAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized: valid Bearer ADMIN_TOKEN required' });
  }
  next();
}

function sanitizeMapObject(parsed) {
  const clean = {};
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return clean;
  }
  for (const [k, v] of Object.entries(parsed)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    clean[k] = v;
  }
  return clean;
}

function loadDatabase() {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return sanitizeMapObject(JSON.parse(raw));
  } catch {
    return {};
  }
}

function saveDatabase(db) {
  const tmpFile = `${DB_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmpFile, DB_FILE);
}

function loadAlbums() {
  try {
    const raw = fs.readFileSync(ALBUMS_FILE, 'utf8');
    return sanitizeMapObject(JSON.parse(raw));
  } catch {
    return {};
  }
}

function saveAlbums(albums) {
  const tmpFile = `${ALBUMS_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(albums, null, 2), 'utf8');
  fs.renameSync(tmpFile, ALBUMS_FILE);
}

function loadReports() {
  try {
    const raw = fs.readFileSync(REPORTS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveReports(reports) {
  const tmpFile = `${REPORTS_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(reports, null, 2), 'utf8');
  fs.renameSync(tmpFile, REPORTS_FILE);
}

function loadBlockedHashes() {
  try {
    const raw = fs.readFileSync(BLOCKED_HASHES_FILE, 'utf8');
    return sanitizeMapObject(JSON.parse(raw));
  } catch {
    return {};
  }
}

function saveBlockedHashes(blocked) {
  const tmpFile = `${BLOCKED_HASHES_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(blocked, null, 2), 'utf8');
  fs.renameSync(tmpFile, BLOCKED_HASHES_FILE);
}

function safeUnlink(filePath) {
  if (!filePath) return;
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch {}
}

function isStoredFileReferenced(db, storedName, excludeCode = null) {
  for (const [code, rec] of Object.entries(db)) {
    if (code !== excludeCode && rec && rec.storedName === storedName) {
      return true;
    }
  }
  return false;
}

function reapExpiredFiles() {
  try {
    const db = loadDatabase();
    const now = Date.now();
    let changed = false;

    for (const [code, rec] of Object.entries(db)) {
      if (rec && rec.expiresAt && new Date(rec.expiresAt).getTime() <= now) {
        const storedName = rec.storedName;
        delete db[code];
        changed = true;
        if (storedName && !isStoredFileReferenced(db, storedName, code)) {
          safeUnlink(path.join(UPLOADS_DIR, path.basename(storedName)));
        }
      }
    }

    if (changed) {
      saveDatabase(db);
    }
  } catch (err) {
    console.error('TTL reaper error:', err.message);
  }
}

setInterval(reapExpiredFiles, 30 * 1000).unref();

function getRecordByCode(db, rawCode) {
  if (typeof rawCode !== 'string') return null;

  const code = rawCode.split('.')[0];
  if (!/^[a-zA-Z0-9]{6,16}$/.test(code)) {
    return null;
  }
  if (!Object.prototype.hasOwnProperty.call(db, code)) {
    return null;
  }
  const record = db[code];
  if (!record || typeof record !== 'object' || typeof record.storedName !== 'string') {
    return null;
  }

  if (record.expiresAt && new Date(record.expiresAt).getTime() <= Date.now()) {
    reapExpiredFiles();
    return null;
  }
  return record;
}

function getAlbumByCode(albums, rawCode) {
  if (typeof rawCode !== 'string') return null;
  const code = rawCode.trim();
  if (!/^[a-zA-Z0-9]{6,12}$/.test(code)) {
    return null;
  }
  if (!Object.prototype.hasOwnProperty.call(albums, code)) {
    return null;
  }
  const album = albums[code];
  if (!album || typeof album !== 'object' || !Array.isArray(album.files)) {
    return null;
  }
  return album;
}

const BASE62 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const BASE36_LOWER = '0123456789abcdefghijklmnopqrstuvwxyz';

function generateShortCode(db, length = 8, lowercaseOnly = false) {
  const alphabet = lowercaseOnly ? BASE36_LOWER : BASE62;
  const safeLen = [6, 8, 12, 16].includes(Number(length)) ? Number(length) : 8;
  let code = '';
  do {
    code = '';
    for (let i = 0; i < safeLen; i++) {
      code += alphabet[crypto.randomInt(0, alphabet.length)];
    }
  } while (Object.prototype.hasOwnProperty.call(db, code));
  return code;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function computeFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

function computeSecureLinkSignature(uriPath, expires) {
  return crypto
    .createHmac('sha256', SECURE_LINK_SECRET)
    .update(`${expires}:${uriPath}`, 'utf8')
    .digest('base64url');
}

function verifySecureLink(uriPath, sigParam, expiresParam) {
  if (!sigParam || !expiresParam) {
    return { ok: false, reason: 'Missing signature or expires query parameter' };
  }
  const expires = parseInt(String(expiresParam), 10);
  if (!Number.isFinite(expires)) {
    return { ok: false, reason: 'Invalid expires timestamp' };
  }
  if (expires < Math.floor(Date.now() / 1000)) {
    return { ok: false, reason: 'Signed link has expired' };
  }
  const expected = computeSecureLinkSignature(uriPath, expires);
  if (!safeTimingEqualStrings(expected, String(sigParam))) {
    return { ok: false, reason: 'Invalid HMAC-SHA256 signature' };
  }
  return { ok: true, reason: 'OK' };
}

function getTotalStorageUsed(db) {
  const seenStoredNames = new Set();
  let total = 0;
  for (const r of Object.values(db)) {
    if (r && r.storedName && !seenStoredNames.has(r.storedName)) {
      seenStoredNames.add(r.storedName);
      total += Number(r.size) || 0;
    }
  }
  return total;
}

function getSafeExtension(filename) {
  const ext = path.extname(filename || '').toLowerCase().trim();
  if (/^\.[a-z0-9]{1,10}$/.test(ext)) {
    return ext;
  }
  return '';
}

function buildContentDisposition(dispositionType, filename) {
  const clean = String(filename || 'file').replace(/[\r\n"\\]/g, '_');
  const asciiFallback = clean.replace(/[^\x20-\x7e]/g, '_') || 'file';
  const encoded = encodeURIComponent(clean);
  return `${dispositionType}; filename="${asciiFallback}"; filename*=UTF-8''${encoded}`;
}

function hasExecutableMagicHeader(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 2) return false;
  if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
    return true;
  }
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x7f &&
    buffer[1] === 0x45 &&
    buffer[2] === 0x4c &&
    buffer[3] === 0x46
  ) {
    return true;
  }
  if (buffer.length >= 4) {
    const magic32 = buffer.readUInt32BE(0);
    if (
      magic32 === 0xfeedface ||
      magic32 === 0xfeedfacf ||
      magic32 === 0xcefaedfe ||
      magic32 === 0xcffaedfe ||
      magic32 === 0xcafebabe
    ) {
      return true;
    }
  }
  return false;
}

async function isExecutableBinaryFile(filePath) {
  const fd = await fs.promises.open(filePath, 'r');
  let headerBuf;
  try {
    headerBuf = Buffer.alloc(4100);
    const { bytesRead } = await fd.read(headerBuf, 0, headerBuf.length, 0);
    headerBuf = headerBuf.subarray(0, bytesRead);
  } finally {
    await fd.close();
  }

  if (hasExecutableMagicHeader(headerBuf)) {
    return true;
  }

  try {
    const detected = await FileType.fromBuffer(headerBuf);
    if (detected) {
      const ext = String(detected.ext || '').toLowerCase();
      const mime = String(detected.mime || '').toLowerCase();
      if (BLOCKED_DETECTED_EXTENSIONS.has(ext) || BLOCKED_DETECTED_MIMES.has(mime)) {
        return true;
      }
    }
  } catch {}

  return false;
}

function validateUploadPolicy({ originalName, mimeType, size }) {
  if (!Number.isFinite(size) || size <= 0) {
    return 'File is empty.';
  }
  const ext = getSafeExtension(originalName);
  const lowerName = (originalName || '').toLowerCase();
  const lowerMime = (mimeType || '').toLowerCase();

  if (BLOCKED_PUBLIC_EXTENSIONS.has(ext) || lowerName.startsWith('.ht')) {
    return `File extension "${ext || lowerName}" is blocked for security reasons.`;
  }
  if (BLOCKED_PUBLIC_MIMES.has(lowerMime)) {
    return `MIME type "${lowerMime}" is blocked for security reasons.`;
  }
  if (ext === '.gif' && size > MAX_GIF_SIZE_BYTES) {
    return 'GIF uploads are limited to 50 MB.';
  }
  if (size > MAX_FILE_SIZE_BYTES) {
    return 'File exceeds the 500 MB limit.';
  }
  return null;
}

function detectPreviewCategory(mimeType, filename) {
  const mime = (mimeType || '').toLowerCase();
  const ext = path.extname(filename || '').toLowerCase();

  if (XSS_SENSITIVE_EXTENSIONS.has(ext) || mime.includes('svg') || mime.includes('html') || mime.includes('xml')) {
    return 'text';
  }
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'audio';
  if (mime === 'application/pdf' || ext === '.pdf') return 'pdf';

  const textExts = new Set([
    '.txt', '.md', '.json', '.js', '.ts', '.jsx', '.tsx', '.py',
    '.html', '.css', '.csv', '.xml', '.yml', '.yaml', '.sh',
    '.ps1', '.log', '.ini', '.conf', '.sql', '.c', '.cpp', '.rs', '.go'
  ]);
  if (
    mime.startsWith('text/') ||
    mime === 'application/json' ||
    mime === 'application/javascript' ||
    mime === 'application/xml' ||
    textExts.has(ext)
  ) {
    return 'text';
  }

  return 'other';
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const safeName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.bin`;
    cb(null, safeName);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_SIZE_BYTES,
    files: 1
  }
});

function preUploadGuard(req, res, next) {
  if (activeUploads >= MAX_CONCURRENT_UPLOADS) {
    return res.status(429).json({ error: 'Server is busy processing other uploads. Please try again shortly.' });
  }

  const declaredLength = parseInt(req.headers['content-length'] || '0', 10);
  if (declaredLength > MAX_FILE_SIZE_BYTES + 1024 * 1024) {
    return res.status(413).json({ error: 'File exceeds the 500 MB limit.' });
  }

  const db = loadDatabase();
  if (getTotalStorageUsed(db) + Math.max(0, declaredLength) > MAX_TOTAL_STORAGE_BYTES) {
    return res.status(507).json({ error: 'Server storage quota reached.' });
  }

  activeUploads += 1;
  let decremented = false;
  const decrement = () => {
    if (!decremented) {
      decremented = true;
      activeUploads = Math.max(0, activeUploads - 1);
    }
  };
  res.on('finish', decrement);
  res.on('close', decrement);
  next();
}

app.use(express.json({ limit: '128kb' }));
app.use(express.urlencoded({ extended: false, limit: '128kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ALLOWED_HOST_REGEX = /^(localhost(:\d+)?|127\.0\.0\.1(:\d+)?|[a-z0-9-]+\.trycloudflare\.com|[a-z0-9-]+\.onrender\.com)$/i;

function resolveBaseUrl(req) {
  const host = (req.get('host') || '').trim();
  if (
    host &&
    !host.startsWith('localhost') &&
    !host.startsWith('127.0.0.1') &&
    ALLOWED_HOST_REGEX.test(host)
  ) {
    return `https://${host}`;
  }
  if (publicBaseUrl) {
    return publicBaseUrl.replace(/\/$/, '');
  }
  if (ALLOWED_HOST_REGEX.test(host)) {
    return `${req.protocol}://${host}`;
  }
  return `http://localhost:${PORT}`;
}

async function buildFileResponse(req, record) {
  const baseUrl = resolveBaseUrl(req);
  const ext = getSafeExtension(record.originalName);
  const shortUrl = `${baseUrl}/s/${record.code}`;
  let rawPath = `/raw/${record.code}`;
  let downloadPath = `/d/${record.code}`;
  let directFilePath = `/files/${record.code}${ext}`;

  let signedExpires = null;
  if (record.requireSignedUrl) {
    signedExpires = Math.floor(Date.now() / 1000) + SIGNED_URL_TTL_SECONDS;
    const rawSig = computeSecureLinkSignature(rawPath, signedExpires);
    const dlSig = computeSecureLinkSignature(downloadPath, signedExpires);
    const dfSig = computeSecureLinkSignature(directFilePath, signedExpires);
    rawPath += `?sig=${rawSig}&expires=${signedExpires}`;
    downloadPath += `?sig=${dlSig}&expires=${signedExpires}`;
    directFilePath += `?sig=${dfSig}&expires=${signedExpires}`;
  }

  const downloadUrl = `${baseUrl}${downloadPath}`;
  const rawUrl = `${baseUrl}${rawPath}`;
  const directUrl = `${baseUrl}${directFilePath}`;

  const qrCodeDataUrl = await QRCode.toDataURL(shortUrl, {
    width: 280,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff'
    }
  });

  return {
    code: record.code,
    originalName: record.originalName,
    mimeType: record.mimeType,
    size: record.size,
    sha256: record.sha256 || null,
    deduplicated: Boolean(record.deduplicated),
    ttl: record.ttl || 'permanent',
    expiresAt: record.expiresAt || null,
    requireSignedUrl: Boolean(record.requireSignedUrl),
    signedExpires,
    createdAt: record.createdAt,
    downloads: record.downloads || 0,
    uploadedFrom: record.uploadedFrom || 'public',
    previewCategory: detectPreviewCategory(record.mimeType, record.originalName),
    shortUrl,
    downloadUrl,
    rawUrl,
    directUrl,
    qrCodeDataUrl
  };
}

async function registerUploadedFile({
  tempFilePath,
  rawOriginalName,
  mimeType,
  size,
  ttl = 'permanent',
  codeLength = 8,
  requireSignedUrl = false,
  userhash = null,
  lowercaseCode = false
}) {
  const cleanName =
    path
      .basename(rawOriginalName || 'file')
      .replace(/[\x00-\x1f\x7f]/g, '')
      .slice(0, 240) || 'file';

  if (!Number.isFinite(size) || size <= 0) {
    safeUnlink(tempFilePath);
    const err = new Error('File is empty.');
    err.statusCode = 400;
    throw err;
  }

  if (await isExecutableBinaryFile(tempFilePath)) {
    safeUnlink(tempFilePath);
    const err = new Error('Executable binaries (PE/ELF/Mach-O) are not permitted.');
    err.statusCode = 415;
    throw err;
  }

  const policyError = validateUploadPolicy({
    originalName: cleanName,
    mimeType,
    size
  });
  if (policyError) {
    safeUnlink(tempFilePath);
    const err = new Error(policyError);
    err.statusCode = size <= 0 ? 400 : 415;
    throw err;
  }

  const sha256 = await computeFileSha256(tempFilePath);
  const blockedHashes = loadBlockedHashes();
  if (Object.prototype.hasOwnProperty.call(blockedHashes, sha256)) {
    safeUnlink(tempFilePath);
    const err = new Error('This file has been blocked due to a policy or legal violation.');
    err.statusCode = 451;
    throw err;
  }

  reapExpiredFiles();
  const db = loadDatabase();

  let storedName = path.basename(tempFilePath);
  let deduplicated = false;
  for (const existing of Object.values(db)) {
    if (
      existing &&
      existing.sha256 === sha256 &&
      existing.size === size &&
      existing.storedName &&
      fs.existsSync(path.join(UPLOADS_DIR, path.basename(existing.storedName)))
    ) {
      if (path.basename(existing.storedName) !== storedName) {
        safeUnlink(tempFilePath);
      }
      storedName = path.basename(existing.storedName);
      deduplicated = true;
      break;
    }
  }

  if (!deduplicated && getTotalStorageUsed(db) + size > MAX_TOTAL_STORAGE_BYTES) {
    safeUnlink(tempFilePath);
    const err = new Error('Server storage quota reached');
    err.statusCode = 507;
    throw err;
  }

  const normalizedTtl = TTL_PRESETS_MS[ttl] ? ttl : 'permanent';
  const expiresAt = TTL_PRESETS_MS[normalizedTtl]
    ? new Date(Date.now() + TTL_PRESETS_MS[normalizedTtl]).toISOString()
    : null;

  const code = generateShortCode(db, codeLength, lowercaseCode);
  const deleteToken = crypto.randomBytes(16).toString('hex');

  const record = {
    code,
    originalName: cleanName,
    storedName,
    mimeType: mimeType || 'application/octet-stream',
    size,
    sha256,
    deduplicated,
    ttl: normalizedTtl,
    expiresAt,
    requireSignedUrl: Boolean(requireSignedUrl),
    userhash: userhash ? hashToken(userhash) : null,
    createdAt: new Date().toISOString(),
    downloads: 0,
    uploadedFrom: 'public',
    deleteTokenHash: hashToken(deleteToken)
  };

  db[code] = record;
  saveDatabase(db);

  return { record, deleteToken };
}

function isPrivateOrReservedIp(ip) {
  if (typeof ip !== 'string' || !net.isIP(ip)) return true;
  const lower = ip.toLowerCase().trim();
  if (lower === '127.0.0.1' || lower === '0.0.0.0' || lower === '::1' || lower === '::') return true;

  if (lower.startsWith('::ffff:')) {
    const tail = lower.slice(7);
    if (net.isIPv4(tail)) {
      return isPrivateOrReservedIp(tail);
    }
    const hexMatch = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMatch) {
      const hi = parseInt(hexMatch[1], 16);
      const lo = parseInt(hexMatch[2], 16);
      const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateOrReservedIp(v4);
    }
    return true;
  }

  if (net.isIPv4(lower)) {
    const parts = lower.split('.').map(Number);
    if (parts[0] === 0 || parts[0] === 10 || parts[0] === 127) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 0 && (parts[2] === 0 || parts[2] === 2)) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true;
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true;
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true;
    if (parts[0] >= 224) return true;
    return false;
  }

  if (
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.startsWith('fe8') ||
    lower.startsWith('fe9') ||
    lower.startsWith('fea') ||
    lower.startsWith('feb') ||
    lower.startsWith('ff') ||
    lower.startsWith('2001:db8:') ||
    lower.startsWith('64:ff9b:') ||
    lower.startsWith('100::')
  ) {
    return true;
  }
  return false;
}

async function fetchRemoteUrlToTempFile(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl).trim());
  } catch {
    const err = new Error('Invalid URL format');
    err.statusCode = 412;
    throw err;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    const err = new Error('URL must start with http:// or https://');
    err.statusCode = 412;
    throw err;
  }
  if (parsed.username || parsed.password) {
    const err = new Error('URLs with embedded credentials are not allowed');
    err.statusCode = 412;
    throw err;
  }

  let addresses;
  try {
    addresses = await dns.promises.lookup(parsed.hostname, { all: true });
  } catch {
    const err = new Error('Could not resolve remote hostname');
    err.statusCode = 412;
    throw err;
  }
  if (!addresses.length || addresses.some((a) => isPrivateOrReservedIp(a.address))) {
    const err = new Error('Remote URL points to a restricted or private network address');
    err.statusCode = 412;
    throw err;
  }

  const safeAddress = addresses[0];
  const tempFilePath = path.join(
    UPLOADS_DIR,
    `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.bin`
  );

  return new Promise((resolve, reject) => {
    let settled = false;
    const finishReject = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      safeUnlink(tempFilePath);
      reject(err);
    };
    const finishResolve = (val) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      resolve(val);
    };

    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(
      parsed,
      {
        headers: {
          'User-Agent': 'sera.drop-urlupload/1.0'
        },
        timeout: 15000,
        lookup: (hostname, opts, cb) => {
          if (opts && opts.all) {
            return cb(null, [{ address: safeAddress.address, family: safeAddress.family }]);
          }
          return cb(null, safeAddress.address, safeAddress.family);
        }
      },
      (resp) => {
        if (resp.statusCode && resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
          resp.resume();
          const redirectErr = new Error('Remote URL redirects are not followed automatically; use direct media URL');
          redirectErr.statusCode = 412;
          return finishReject(redirectErr);
        }
        if (resp.statusCode !== 200) {
          resp.resume();
          const statusErr = new Error(`Remote server returned HTTP ${resp.statusCode}`);
          statusErr.statusCode = 412;
          return finishReject(statusErr);
        }

        const declaredLen = parseInt(resp.headers['content-length'] || '0', 10);
        if (declaredLen > MAX_FILE_SIZE_BYTES) {
          resp.resume();
          const maxErr = new Error('Remote file exceeds 500 MB limit');
          maxErr.statusCode = 413;
          return finishReject(maxErr);
        }

        const contentType = (resp.headers['content-type'] || 'application/octet-stream')
          .split(';')[0]
          .trim();
        const out = fs.createWriteStream(tempFilePath);
        let receivedBytes = 0;

        resp.on('data', (chunk) => {
          receivedBytes += chunk.length;
          if (receivedBytes > MAX_FILE_SIZE_BYTES) {
            resp.destroy();
            out.destroy();
            const maxErr = new Error('Remote file exceeds 500 MB limit');
            maxErr.statusCode = 413;
            finishReject(maxErr);
          }
        });

        resp.on('error', (err) => {
          out.destroy();
          err.statusCode = 412;
          finishReject(err);
        });

        resp.pipe(out);

        out.on('finish', () => {
          if (settled) return;
          if (receivedBytes <= 0) {
            const emptyErr = new Error('Remote file is empty');
            emptyErr.statusCode = 400;
            return finishReject(emptyErr);
          }
          let urlPathName = 'remote-file';
          try {
            urlPathName = decodeURIComponent(path.basename(parsed.pathname || '') || 'remote-file');
          } catch {
            urlPathName = path.basename(parsed.pathname || '') || 'remote-file';
          }
          let finalName = urlPathName;
          if (!path.extname(finalName)) {
            const mimeExtMap = {
              'image/png': '.png',
              'image/jpeg': '.jpg',
              'image/gif': '.gif',
              'image/webp': '.webp',
              'video/mp4': '.mp4',
              'video/webm': '.webm',
              'audio/mpeg': '.mp3',
              'text/plain': '.txt',
              'application/pdf': '.pdf'
            };
            finalName += mimeExtMap[contentType] || '.bin';
          }
          finishResolve({
            tempFilePath,
            originalName: finalName,
            mimeType: contentType,
            size: receivedBytes
          });
        });

        out.on('error', (err) => {
          finishReject(err);
        });
      }
    );

    const hardTimer = setTimeout(() => {
      req.destroy(new Error('Remote URL transfer timed out'));
    }, 30000);

    req.on('timeout', () => {
      req.destroy(new Error('Remote URL fetch timed out'));
    });
    req.on('error', (err) => {
      err.statusCode = err.statusCode || 412;
      finishReject(err);
    });
  });
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getOperatorConfig() {
  const name = String(process.env.OPERATOR_NAME || '').trim();
  const address = String(process.env.OPERATOR_ADDRESS || '').trim();
  const email = String(process.env.OPERATOR_EMAIL || '').trim();
  const phone = String(process.env.OPERATOR_PHONE || '').trim();
  return {
    name: name || null,
    address: address || null,
    email: email || null,
    phone: phone || null
  };
}

function renderLegalLayout(title, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)} — sera.drop</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <div class="container">
    <header class="navbar">
      <a href="/" class="brand">
        <span>sera<span class="brand-dot">.</span>drop</span>
      </a>
      <nav style="display:flex;gap:0.75rem;">
        <a href="/impressum" class="btn btn-secondary btn-sm">Impressum</a>
        <a href="/privacy" class="btn btn-secondary btn-sm">Privacy</a>
        <a href="/" class="btn btn-primary btn-sm">Home</a>
      </nav>
    </header>
    <main class="card" style="padding:2rem;line-height:1.65;">
      ${bodyHtml}
    </main>
  </div>
</body>
</html>`;
}

app.get('/impressum', (req, res) => {
  const op = getOperatorConfig();
  const addressHtml = op.address
    ? escapeHtml(op.address)
    : '<span style="color:#888;">Not configured. Specify OPERATOR_ADDRESS in environment variables to satisfy statutory service provider identification requirements (DDG § 5).</span>';
  const nameHtml = op.name
    ? escapeHtml(op.name)
    : 'sera.drop Operator';
  const emailHtml = op.email
    ? `<a href="mailto:${escapeHtml(op.email)}">${escapeHtml(op.email)}</a>`
    : '<span style="color:#888;">Not configured. Specify OPERATOR_EMAIL in environment variables.</span>';
  const phoneHtml = op.phone
    ? escapeHtml(op.phone)
    : 'Available upon request via email';

  const html = renderLegalLayout(
    'Impressum & Legal Notice (DDG § 5)',
    `<h1>Impressum (Legal Notice pursuant to § 5 DDG)</h1>
    <section style="margin-top:1.25rem;">
      <h2>Service Provider &amp; Operator (Digitale-Dienste-Gesetz § 5)</h2>
      <p>
        <strong>${nameHtml}</strong><br />
        ${addressHtml}
      </p>
      <p>
        <strong>Electronic Contact:</strong> ${emailHtml}<br />
        <strong>Telephone:</strong> ${phoneHtml}
      </p>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>EU Digital Services Act (DSA) Single Point of Contact (Art. 11 &amp; Art. 12 DSA)</h2>
      <p>
        For member state authorities, the European Commission, the European Board for Digital Services, and service recipients, our designated point of contact is ${emailHtml}. Communications are accepted in German and English.
      </p>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>Notice-and-Action Mechanism (Art. 16 DSA)</h2>
      <p>
        To report suspected illegal content, copyright infringement, or malware hosted on sera.drop, submit a structured notice via the API endpoint <code>POST /api/report</code> or contact ${emailHtml}.
      </p>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>Consumer Dispute Resolution (§ 36 VSBG) &amp; Liability</h2>
      <p>
        We are neither willing nor obligated to participate in dispute resolution proceedings before a consumer arbitration board. As a hosting provider under Articles 6 and 16 of Regulation (EU) 2022/2065 (DSA), we expeditiously remove or disable access to illegal content upon obtaining actual knowledge.
      </p>
    </section>`
  );
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(html);
});

app.get('/privacy', (req, res) => {
  const op = getOperatorConfig();
  const addressHtml = op.address
    ? escapeHtml(op.address)
    : '<span style="color:#888;">Not configured. Specify OPERATOR_ADDRESS in environment variables.</span>';
  const nameHtml = op.name
    ? escapeHtml(op.name)
    : 'sera.drop Operator';
  const emailHtml = op.email
    ? `<a href="mailto:${escapeHtml(op.email)}">${escapeHtml(op.email)}</a>`
    : '<span style="color:#888;">Not configured. Specify OPERATOR_EMAIL in environment variables.</span>';

  const html = renderLegalLayout(
    'Privacy Policy (GDPR Art. 13)',
    `<h1>Privacy Policy (Information pursuant to Art. 13 GDPR)</h1>
    <section style="margin-top:1.25rem;">
      <h2>1. Data Controller Identity &amp; Contact</h2>
      <p>
        <strong>${nameHtml}</strong><br />
        ${addressHtml}<br />
        Email: ${emailHtml}
      </p>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>2. Categories of Personal Data Processed</h2>
      <ul>
        <li><strong>Uploaded Files &amp; Metadata:</strong> File contents, filename, MIME type, file size, SHA-256 cryptographic digest, creation timestamp, and chosen expiration TTL.</li>
        <li><strong>Ephemeral &amp; Hashed Network Identifiers:</strong> Client IP addresses are processed transiently in memory for rate-limiting and HMAC-SHA256 hashed when recording abuse notices; raw client IP addresses are never persisted to disk.</li>
        <li><strong>Notice-and-Action Reports:</strong> Notifier name, email address, target code/URL, and explanation submitted under Art. 16 DSA.</li>
      </ul>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>3. Purposes and Legal Bases of Processing (Art. 6(1) GDPR)</h2>
      <ul>
        <li><strong>Art. 6(1)(b) GDPR (Performance of Service):</strong> Hosting, deduplicating, generating short links, and delivering user-uploaded files and albums.</li>
        <li><strong>Art. 6(1)(f) GDPR (Legitimate Interests in IT Security &amp; Abuse Prevention):</strong> Rate limiting, magic-byte executable filtering (PE/ELF/Mach-O rejection), and HMAC-SHA256 URL signing.</li>
        <li><strong>Art. 6(1)(c) GDPR (Legal Obligations):</strong> Processing and retaining statutory takedown notices pursuant to Regulation (EU) 2022/2065 (Digital Services Act Art. 16).</li>
      </ul>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>4. Local Storage &amp; Cookie Policy (§ 25 TDDDG)</h2>
      <p>
        sera.drop does not use tracking, advertising, or third-party analytics cookies, nor does it load external fonts from third-party CDNs. Functional history of your own uploads and delete tokens is stored strictly locally in your browser's <code>localStorage</code> under your control.
      </p>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>5. Storage Duration &amp; Retention Policy</h2>
      <p>
        Uploaded files support ephemeral retention presets of <strong>1h</strong>, <strong>12h</strong>, <strong>24h</strong>, and <strong>72h</strong> (or until manual deletion via owner delete token). A background reaper automatically purges expired files from disk every 30 seconds.
      </p>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>6. Recipients &amp; Hosting Infrastructure</h2>
      <p>
        The service is hosted on cloud infrastructure (Render / S3-compatible object storage). Data is not sold or transferred to third parties except where required by binding EU or German law.
      </p>
    </section>
    <section style="margin-top:1.25rem;">
      <h2>7. Data Subject Rights (Arts. 15–21 &amp; Art. 77 GDPR)</h2>
      <p>
        Under the GDPR, you have the right of access (Art. 15), rectification (Art. 16), erasure / right to be forgotten (Art. 17), restriction of processing (Art. 18), data portability (Art. 20), and the right to object to processing based on Art. 6(1)(f) (Art. 21). You may delete uploaded files immediately using your delete token or by contacting <a href="mailto:${escapeHtml(op.email)}">${escapeHtml(op.email)}</a>. Furthermore, you have the right to lodge a complaint with a data protection supervisory authority (Art. 77 GDPR), such as the Berlin Commissioner for Data Protection and Freedom of Information (BlnBDI).
      </p>
    </section>`
  );
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(html);
});

function extractCodeFromTarget(targetUrl, targetCode) {
  if (typeof targetCode === 'string' && /^[a-zA-Z0-9]{6,16}$/.test(targetCode.trim().split('.')[0])) {
    return targetCode.trim().split('.')[0];
  }
  if (typeof targetUrl === 'string' && targetUrl.trim()) {
    try {
      const parsed = new URL(targetUrl.trim());
      const parts = parsed.pathname.split('/').filter(Boolean);
      if (parts.length >= 2 && ['s', 'd', 'raw', 'f', 'files'].includes(parts[0])) {
        const candidate = parts[1].split('.')[0];
        if (/^[a-zA-Z0-9]{6,16}$/.test(candidate)) {
          return candidate;
        }
      }
    } catch {}
  }
  return null;
}

app.post('/api/report', reportRateLimiter, (req, res) => {
  try {
    const body = req.body || {};
    const targetUrl = typeof body.targetUrl === 'string' ? body.targetUrl.trim().slice(0, 2048) : '';
    const targetCode = typeof body.targetCode === 'string' ? body.targetCode.trim().slice(0, 64) : '';
    const category = typeof body.category === 'string' ? body.category.trim() : '';
    const explanation = typeof body.explanation === 'string' ? body.explanation.trim().slice(0, 5000) : '';
    const notifierName = typeof body.notifierName === 'string' ? body.notifierName.trim().slice(0, 200) : '';
    const notifierEmail = typeof body.notifierEmail === 'string' ? body.notifierEmail.trim().slice(0, 320) : '';
    const goodFaithConfirmed = body.goodFaithConfirmed === true;

    if (!targetUrl && !targetCode) {
      return res.status(400).json({ error: 'Either targetUrl or targetCode is required.' });
    }
    if (!VALID_REPORT_CATEGORIES.has(category)) {
      return res.status(400).json({ error: 'Invalid category. Must be copyright, malware, illegal_content, or other.' });
    }
    if (explanation.length < 10) {
      return res.status(400).json({ error: 'Explanation must be at least 10 characters.' });
    }
    if (!notifierName) {
      return res.status(400).json({ error: 'notifierName is required.' });
    }
    if (!notifierEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(notifierEmail)) {
      return res.status(400).json({ error: 'A valid notifierEmail is required.' });
    }
    if (!goodFaithConfirmed) {
      return res.status(400).json({ error: 'goodFaithConfirmed must be true pursuant to Art. 16(2)(d) DSA.' });
    }

    const reportId = `rep_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const receivedAt = new Date().toISOString();
    const clientIpHash = hashClientIp(req);

    let mitigated = false;
    const resolvedCode = extractCodeFromTarget(targetUrl, targetCode);
    if (resolvedCode && ['copyright', 'malware', 'illegal_content'].includes(category)) {
      const db = loadDatabase();
      const record = getRecordByCode(db, resolvedCode);
      if (record) {
        if (record.sha256) {
          const blockedHashes = loadBlockedHashes();
          blockedHashes[record.sha256] = {
            sha256: record.sha256,
            reason: `${category} report ${reportId}`,
            blockedAt: receivedAt
          };
          saveBlockedHashes(blockedHashes);
        }
        const storedName = record.storedName;
        delete db[record.code];
        saveDatabase(db);
        if (storedName && !isStoredFileReferenced(db, storedName, record.code)) {
          safeUnlink(path.join(UPLOADS_DIR, path.basename(storedName)));
        }
        mitigated = true;
      }
    }

    const reports = loadReports();
    const entry = {
      reportId,
      receivedAt,
      targetUrl: targetUrl || null,
      targetCode: resolvedCode || targetCode || null,
      category,
      explanation,
      notifierName,
      notifierEmail,
      goodFaithConfirmed: true,
      clientIpHash,
      mitigated,
      status: mitigated ? 'action_taken' : 'received'
    };
    reports.push(entry);
    saveReports(reports);

    return res.status(201).json({
      reportId,
      receivedAt,
      status: entry.status,
      mitigated
    });
  } catch {
    return res.status(500).json({ error: 'Failed to process abuse report.' });
  }
});

app.get('/api/admin/files', requireAdminAuth, async (req, res) => {
  try {
    reapExpiredFiles();
    const db = loadDatabase();
    const query = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
    let records = Object.values(db);
    if (query) {
      records = records.filter(
        (r) =>
          r &&
          (String(r.code || '').toLowerCase().includes(query) ||
            String(r.originalName || '').toLowerCase().includes(query) ||
            String(r.sha256 || '').toLowerCase().includes(query))
      );
    }
    records.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const results = await Promise.all(records.map((r) => buildFileResponse(req, r)));
    res.json({ files: results, total: results.length });
  } catch {
    res.status(500).json({ error: 'Failed to search files' });
  }
});

app.delete('/api/admin/files/:code', requireAdminAuth, (req, res) => {
  try {
    const db = loadDatabase();
    const record = getRecordByCode(db, req.params.code);
    if (!record) {
      return res.status(404).json({ error: 'File not found' });
    }
    const storedName = record.storedName;
    delete db[record.code];
    saveDatabase(db);
    if (storedName && !isStoredFileReferenced(db, storedName, record.code)) {
      safeUnlink(path.join(UPLOADS_DIR, path.basename(storedName)));
    }
    return res.json({ deleted: true, code: record.code });
  } catch {
    return res.status(500).json({ error: 'Failed to delete file' });
  }
});

app.post('/api/admin/block-hash', requireAdminAuth, (req, res) => {
  try {
    const sha256 = String(req.body?.sha256 || '').trim().toLowerCase();
    const reason = String(req.body?.reason || 'Administrative hash block').trim().slice(0, 500);
    if (!/^[a-f0-9]{64}$/.test(sha256)) {
      return res.status(400).json({ error: 'Valid 64-character hex SHA-256 hash required' });
    }
    const blockedHashes = loadBlockedHashes();
    blockedHashes[sha256] = {
      sha256,
      reason,
      blockedAt: new Date().toISOString()
    };
    saveBlockedHashes(blockedHashes);

    const db = loadDatabase();
    let removedCount = 0;
    for (const [code, rec] of Object.entries(db)) {
      if (rec && rec.sha256 === sha256) {
        const storedName = rec.storedName;
        delete db[code];
        removedCount += 1;
        if (storedName && !isStoredFileReferenced(db, storedName, code)) {
          safeUnlink(path.join(UPLOADS_DIR, path.basename(storedName)));
        }
      }
    }
    if (removedCount > 0) {
      saveDatabase(db);
    }
    return res.status(201).json({ blocked: true, sha256, removedFiles: removedCount });
  } catch {
    return res.status(500).json({ error: 'Failed to block hash' });
  }
});

app.get('/api/admin/reports', requireAdminAuth, (req, res) => {
  try {
    const reports = loadReports();
    res.json({ reports, total: reports.length });
  } catch {
    res.status(500).json({ error: 'Failed to load reports' });
  }
});

app.get('/api/status', (req, res) => {
  reapExpiredFiles();
  const db = loadDatabase();
  const albums = loadAlbums();
  const tunnelDisabled = Boolean(
    process.env.DISABLE_TUNNEL === 'true' || process.env.PUBLIC_URL || process.env.RENDER
  );
  res.json({
    publicUrl: publicBaseUrl,
    cloudflareUrl,
    tunnelEnabled: !tunnelDisabled,
    localUrl: `http://localhost:${PORT}`,
    storageUsedBytes: getTotalStorageUsed(db),
    storageQuotaBytes: MAX_TOTAL_STORAGE_BYTES,
    totalFiles: Object.keys(db).length,
    totalAlbums: Object.keys(albums).length
  });
});

app.get('/api/sharex.sxcu', (req, res) => {
  const baseUrl = resolveBaseUrl(req);
  const sxcu = {
    Version: '15.0.0',
    Name: 'sera.drop',
    DestinationType: 'ImageUploader, TextUploader, FileUploader',
    RequestMethod: 'POST',
    RequestURL: `${baseUrl}/user/api.php`,
    Body: 'MultipartFormData',
    Arguments: {
      reqtype: 'fileupload'
    },
    FileFormName: 'fileToUpload',
    URL: '{response}'
  };
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="sera.drop.sxcu"');
  res.send(JSON.stringify(sxcu, null, 2));
});

app.post(
  '/api/upload',
  uploadRateLimiter,
  requireCsrfHeader,
  preUploadGuard,
  upload.single('file'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
      }

      const rawOriginalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
      const ttl = String(req.body?.ttl || 'permanent').trim();
      const codeLength = parseInt(req.body?.codeLength || '8', 10);
      const requireSignedUrl =
        req.body?.requireSignedUrl === 'true' || req.body?.requireSignedUrl === true;

      const { record, deleteToken } = await registerUploadedFile({
        tempFilePath: req.file.path,
        rawOriginalName,
        mimeType: req.file.mimetype,
        size: req.file.size,
        ttl,
        codeLength,
        requireSignedUrl
      });

      const payload = await buildFileResponse(req, record);
      payload.deleteToken = deleteToken;
      res.status(201).json(payload);
    } catch (err) {
      if (req.file?.path) {
        safeUnlink(req.file.path);
      }
      console.error('Upload error:', err.message);
      res.status(err.statusCode || 500).json({ error: err.message || 'Failed to upload file' });
    }
  }
);

app.post('/api/url-upload', uploadRateLimiter, requireCsrfHeader, preUploadGuard, async (req, res) => {
  try {
    const targetUrl = String(req.body?.url || '').trim();
    if (!targetUrl) {
      return res.status(400).json({ error: 'No remote URL provided' });
    }

    const ttl = String(req.body?.ttl || 'permanent').trim();
    const codeLength = parseInt(req.body?.codeLength || '8', 10);
    const requireSignedUrl =
      req.body?.requireSignedUrl === 'true' || req.body?.requireSignedUrl === true;

    const fetched = await fetchRemoteUrlToTempFile(targetUrl);
    const { record, deleteToken } = await registerUploadedFile({
      tempFilePath: fetched.tempFilePath,
      rawOriginalName: fetched.originalName,
      mimeType: fetched.mimeType,
      size: fetched.size,
      ttl,
      codeLength,
      requireSignedUrl
    });

    const payload = await buildFileResponse(req, record);
    payload.deleteToken = deleteToken;
    res.status(201).json(payload);
  } catch (err) {
    console.error('URL upload error:', err.message);
    res.status(err.statusCode || 500).json({ error: err.message || 'Failed to fetch remote URL' });
  }
});

const catboxUploadMiddleware = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE_BYTES, files: 1 }
}).single('fileToUpload');

app.post('/user/api.php', uploadRateLimiter, preUploadGuard, (req, res) => {
  catboxUploadMiddleware(req, res, async (multerErr) => {
    if (multerErr) {
      return res.status(413).type('text/plain').send(multerErr.message);
    }
    try {
      const reqtype = String(req.body?.reqtype || '').trim();
      const userhash = String(req.body?.userhash || '').trim() || null;
      const baseUrl = resolveBaseUrl(req);
      const isAdmin = hasValidAdminAuth(req);

      if (reqtype !== 'fileupload' && req.file?.path) {
        safeUnlink(req.file.path);
      }

      if (reqtype === 'fileupload') {
        if (!req.file) {
          return res.status(400).type('text/plain').send('No fileToUpload provided.');
        }
        const rawOriginalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
        const { record } = await registerUploadedFile({
          tempFilePath: req.file.path,
          rawOriginalName,
          mimeType: req.file.mimetype,
          size: req.file.size,
          ttl: 'permanent',
          codeLength: 6,
          lowercaseCode: true,
          userhash
        });
        const ext = getSafeExtension(record.originalName);
        return res.status(200).type('text/plain').send(`${baseUrl}/files/${record.code}${ext}`);
      }

      if (reqtype === 'urlupload') {
        const targetUrl = String(req.body?.url || '').trim();
        if (!targetUrl) {
          return res.status(412).type('text/plain').send('No url provided.');
        }
        const fetched = await fetchRemoteUrlToTempFile(targetUrl);
        const { record } = await registerUploadedFile({
          tempFilePath: fetched.tempFilePath,
          rawOriginalName: fetched.originalName,
          mimeType: fetched.mimeType,
          size: fetched.size,
          ttl: 'permanent',
          codeLength: 6,
          lowercaseCode: true,
          userhash
        });
        const ext = getSafeExtension(record.originalName);
        return res.status(200).type('text/plain').send(`${baseUrl}/files/${record.code}${ext}`);
      }

      if (reqtype === 'deletefiles') {
        if (!userhash && !isAdmin) {
          return res.status(401).type('text/plain').send('Unauthorized: userhash or valid Bearer ADMIN_TOKEN required.');
        }
        const filesList = String(req.body?.files || '')
          .split(/\s+/)
          .filter(Boolean);
        if (!filesList.length) {
          return res.status(400).type('text/plain').send('No files specified.');
        }
        const db = loadDatabase();
        const expectedHash = userhash ? hashToken(userhash) : null;
        for (const f of filesList) {
          const code = path.basename(f).split('.')[0];
          const rec = getRecordByCode(db, code);
          if (!rec || (!isAdmin && (!rec.userhash || !expectedHash || !safeTimingEqualStrings(rec.userhash, expectedHash)))) {
            return res.status(400).type('text/plain').send(`File ${f} doesn't exist or unauthorized.`);
          }
          const storedName = rec.storedName;
          delete db[code];
          if (!isStoredFileReferenced(db, storedName, code)) {
            safeUnlink(path.join(UPLOADS_DIR, path.basename(storedName)));
          }
        }
        saveDatabase(db);
        return res.status(200).type('text/plain').send('Files successfully deleted.');
      }

      if (reqtype === 'createalbum') {
        const title = String(req.body?.title || 'Untitled Album').trim().slice(0, 140);
        const desc = String(req.body?.desc || '').trim().slice(0, 1000);
        const filesList = String(req.body?.files || '')
          .split(/\s+/)
          .map((f) => path.basename(f).split('.')[0])
          .filter((c) => /^[a-zA-Z0-9]{6,16}$/.test(c))
          .slice(0, 500);

        const albums = loadAlbums();
        const short = generateShortCode(albums, 6, true);
        albums[short] = {
          short,
          title,
          description: desc,
          files: filesList,
          userhash: userhash ? hashToken(userhash) : null,
          createdAt: new Date().toISOString()
        };
        saveAlbums(albums);
        return res.status(200).type('text/plain').send(`${baseUrl}/c/${short}`);
      }

      if (['editalbum', 'addtoalbum', 'removefromalbum', 'deletealbum'].includes(reqtype)) {
        const short = String(req.body?.short || '').trim();
        const albums = loadAlbums();
        const album = getAlbumByCode(albums, short);
        if (!album) {
          return res.status(404).type('text/plain').send("Album doesn't exist.");
        }
        if (!album.userhash && !isAdmin) {
          return res.status(403).type('text/plain').send('Anonymous albums cannot be edited or deleted.');
        }
        if (!isAdmin && (!userhash || !safeTimingEqualStrings(hashToken(userhash), album.userhash))) {
          return res.status(403).type('text/plain').send('Unauthorized userhash for this album.');
        }

        if (reqtype === 'deletealbum') {
          delete albums[short];
          saveAlbums(albums);
          return res.status(200).type('text/plain').send('');
        }

        const incomingFiles = String(req.body?.files || '')
          .split(/\s+/)
          .map((f) => path.basename(f).split('.')[0])
          .filter((c) => /^[a-zA-Z0-9]{6,16}$/.test(c));

        if (reqtype === 'editalbum') {
          album.title = String(req.body?.title || album.title).trim().slice(0, 140);
          album.description = String(req.body?.desc || '').trim().slice(0, 1000);
          album.files = incomingFiles.slice(0, 500);
        } else if (reqtype === 'addtoalbum') {
          const merged = [...album.files, ...incomingFiles];
          album.files = Array.from(new Set(merged)).slice(0, 500);
        } else if (reqtype === 'removefromalbum') {
          const removeSet = new Set(incomingFiles);
          album.files = album.files.filter((c) => !removeSet.has(c));
        }
        saveAlbums(albums);
        return res.status(200).type('text/plain').send(`${baseUrl}/c/${short}`);
      }

      return res.status(400).type('text/plain').send(`Unsupported reqtype: ${reqtype}`);
    } catch (err) {
      if (req.file?.path) {
        safeUnlink(req.file.path);
      }
      return res.status(err.statusCode || 500).type('text/plain').send(err.message || 'API error');
    }
  });
});

app.post('/resources/internals/api.php', uploadRateLimiter, preUploadGuard, (req, res) => {
  catboxUploadMiddleware(req, res, async (multerErr) => {
    if (multerErr) {
      return res.status(413).type('text/plain').send(multerErr.message);
    }
    try {
      const reqtype = String(req.body?.reqtype || '').trim();
      if (reqtype !== 'fileupload' || !req.file) {
        if (req.file?.path) safeUnlink(req.file.path);
        return res.status(400).type('text/plain').send('Invalid Litterbox upload request.');
      }
      const timeKey = String(req.body?.time || '1h').trim();
      if (!TTL_PRESETS_MS[timeKey]) {
        safeUnlink(req.file.path);
        return res.status(400).type('text/plain').send('Invalid time parameter (1h, 12h, 24h, 72h).');
      }
      const fileNameLength = parseInt(req.body?.fileNameLength || '6', 10) === 16 ? 16 : 6;
      const rawOriginalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');

      const { record } = await registerUploadedFile({
        tempFilePath: req.file.path,
        rawOriginalName,
        mimeType: req.file.mimetype,
        size: req.file.size,
        ttl: timeKey,
        codeLength: fileNameLength,
        lowercaseCode: true
      });
      const ext = getSafeExtension(record.originalName);
      const baseUrl = resolveBaseUrl(req);
      return res.status(200).type('text/plain').send(`${baseUrl}/files/${record.code}${ext}`);
    } catch (err) {
      if (req.file?.path) safeUnlink(req.file.path);
      return res.status(err.statusCode || 500).type('text/plain').send(err.message || 'Litterbox error');
    }
  });
});

app.post('/api/albums', uploadRateLimiter, requireCsrfHeader, async (req, res) => {
  try {
    const title = String(req.body?.title || 'Shared Album').trim().slice(0, 140) || 'Shared Album';
    const description = String(req.body?.description || '').trim().slice(0, 1000);
    const rawFiles = Array.isArray(req.body?.files) ? req.body.files : [];
    const db = loadDatabase();
    const validFiles = rawFiles
      .map((c) => String(c).trim().split('.')[0])
      .filter((c) => getRecordByCode(db, c))
      .slice(0, 500);

    if (!validFiles.length) {
      return res.status(400).json({ error: 'Select at least one valid file to create an album' });
    }

    const albums = loadAlbums();
    const short = generateShortCode(albums, 6, true);
    const deleteToken = crypto.randomBytes(16).toString('hex');

    albums[short] = {
      short,
      title,
      description,
      files: Array.from(new Set(validFiles)),
      userhash: hashToken(deleteToken),
      createdAt: new Date().toISOString()
    };
    saveAlbums(albums);

    const baseUrl = resolveBaseUrl(req);
    const albumUrl = `${baseUrl}/c/${short}`;
    const qrCodeDataUrl = await QRCode.toDataURL(albumUrl, {
      width: 280,
      margin: 2,
      color: { dark: '#000000', light: '#ffffff' }
    });

    res.status(201).json({
      short,
      title,
      description,
      files: albums[short].files,
      albumUrl,
      qrCodeDataUrl,
      deleteToken
    });
  } catch {
    res.status(500).json({ error: 'Failed to create album' });
  }
});

app.get('/api/albums/:short', lookupRateLimiter, async (req, res) => {
  try {
    reapExpiredFiles();
    const albums = loadAlbums();
    const album = getAlbumByCode(albums, req.params.short);
    if (!album) {
      return res.status(404).json({ error: 'Album not found' });
    }
    const db = loadDatabase();
    const resolvedRecords = album.files.map((c) => getRecordByCode(db, c)).filter(Boolean);
    const filesPayload = await Promise.all(resolvedRecords.map((r) => buildFileResponse(req, r)));

    const baseUrl = resolveBaseUrl(req);
    const albumUrl = `${baseUrl}/c/${album.short}`;
    const qrCodeDataUrl = await QRCode.toDataURL(albumUrl, {
      width: 280,
      margin: 2,
      color: { dark: '#000000', light: '#ffffff' }
    });

    res.json({
      short: album.short,
      title: album.title,
      description: album.description,
      createdAt: album.createdAt,
      albumUrl,
      qrCodeDataUrl,
      files: filesPayload
    });
  } catch {
    res.status(500).json({ error: 'Failed to load album' });
  }
});

app.get('/api/files', lookupRateLimiter, async (req, res) => {
  try {
    reapExpiredFiles();
    const db = loadDatabase();
    let records = [];

    if (typeof req.query.codes === 'string' && req.query.codes.trim()) {
      const requestedCodes = req.query.codes
        .split(',')
        .map((c) => c.trim())
        .filter((c) => /^[a-zA-Z0-9]{6,16}$/.test(c))
        .slice(0, 50);
      records = requestedCodes.map((c) => getRecordByCode(db, c)).filter(Boolean);
    } else {
      if (!hasValidAdminAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized: valid Bearer ADMIN_TOKEN required' });
      }
      records = Object.values(db);
    }

    records.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const results = await Promise.all(records.map((r) => buildFileResponse(req, r)));
    res.json(results);
  } catch (err) {
    console.error('List error:', err);
    res.status(500).json({ error: 'Failed to list files' });
  }
});

app.get('/api/files/:code', lookupRateLimiter, async (req, res) => {
  try {
    reapExpiredFiles();
    const db = loadDatabase();
    const record = getRecordByCode(db, req.params.code);
    if (!record) {
      return res.status(404).json({ error: 'Shared file not found or has expired' });
    }

    const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File no longer exists on server' });
    }

    const payload = await buildFileResponse(req, record);
    res.json(payload);
  } catch (err) {
    console.error('Metadata error:', err);
    res.status(500).json({ error: 'Failed to retrieve file metadata' });
  }
});

app.delete('/api/files/:code', lookupRateLimiter, requireCsrfHeader, (req, res) => {
  try {
    const db = loadDatabase();
    const record = getRecordByCode(db, req.params.code);
    if (!record) {
      return res.status(404).json({ error: 'File not found' });
    }

    const providedToken = String(req.headers['x-delete-token'] || '');
    const hasOwnerToken = Boolean(
      record.deleteTokenHash &&
        providedToken &&
        safeTimingEqualStrings(hashToken(providedToken), record.deleteTokenHash)
    );

    if (!hasOwnerToken && !hasValidAdminAuth(req)) {
      return res.status(401).json({ error: 'Unauthorized: valid Bearer ADMIN_TOKEN required' });
    }

    const storedName = record.storedName;
    delete db[record.code];
    saveDatabase(db);

    if (!isStoredFileReferenced(db, storedName, record.code)) {
      safeUnlink(path.join(UPLOADS_DIR, path.basename(storedName)));
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

function resolveRawMediaDelivery(record) {
  const ext = getSafeExtension(record.originalName);
  const lowerMime = (record.mimeType || '').toLowerCase().trim();
  const category = detectPreviewCategory(lowerMime, record.originalName);

  if (category === 'text' || XSS_SENSITIVE_EXTENSIONS.has(ext)) {
    return {
      contentType: 'text/plain; charset=utf-8',
      disposition: 'inline',
      isPdf: false
    };
  }
  if (SAFE_INLINE_MEDIA_MIMES.has(lowerMime)) {
    return {
      contentType: lowerMime,
      disposition: 'inline',
      isPdf: lowerMime === 'application/pdf' || ext === '.pdf'
    };
  }
  return {
    contentType: 'application/octet-stream',
    disposition: 'attachment',
    isPdf: false
  };
}

app.head(['/raw/:code', '/files/:codeWithExt', '/f/:code'], lookupRateLimiter, (req, res, next) => {
  if (req.query.stat === '1') {
    return next();
  }
  const rawParam = req.params.code || req.params.codeWithExt || '';
  const db = loadDatabase();
  const record = getRecordByCode(db, rawParam);
  if (!record) {
    return res.status(404).end();
  }
  if (record.requireSignedUrl) {
    const sigParam = req.query.sig || req.query.md5;
    const check = verifySecureLink(req.path, sigParam, req.query.expires);
    if (!check.ok) {
      return res.status(403).end();
    }
  }
  const delivery = resolveRawMediaDelivery(record);
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', delivery.contentType);
  res.setHeader('Content-Length', String(record.size || 0));
  return res.status(200).end();
});

function serveRawMedia(req, res, rawCodeParam) {
  try {
    const db = loadDatabase();
    const record = getRecordByCode(db, rawCodeParam);
    if (!record) {
      return res.status(404).send('File not found or expired');
    }

    if (record.requireSignedUrl) {
      const sigParam = req.query.sig || req.query.md5;
      const check = verifySecureLink(req.path, sigParam, req.query.expires);
      if (!check.ok) {
        return res.status(403).send(`403 Forbidden (${check.reason})`);
      }
    }

    const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
    if (!fs.existsSync(filePath)) {
      return res.status(404).send('File missing from disk');
    }

    const delivery = resolveRawMediaDelivery(record);
    const cspValue = delivery.isPdf
      ? "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'"
      : "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'";

    res.setHeader('Content-Security-Policy', cspValue);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD');
    res.setHeader('Content-Type', delivery.contentType);
    res.setHeader(
      'Content-Disposition',
      buildContentDisposition(delivery.disposition, record.originalName)
    );
    res.sendFile(filePath);
  } catch {
    res.status(500).send('Error serving file');
  }
}

app.get('/raw/:code', lookupRateLimiter, (req, res) => {
  serveRawMedia(req, res, req.params.code);
});

app.get('/files/:codeWithExt', lookupRateLimiter, (req, res) => {
  serveRawMedia(req, res, req.params.codeWithExt);
});

app.get('/f/:code', lookupRateLimiter, (req, res) => {
  serveRawMedia(req, res, req.params.code);
});

app.get('/d/:code', lookupRateLimiter, (req, res) => {
  try {
    const db = loadDatabase();
    const record = getRecordByCode(db, req.params.code);
    if (!record) {
      return res.status(404).send('File not found or expired');
    }

    if (record.requireSignedUrl) {
      const sigParam = req.query.sig || req.query.md5;
      const check = verifySecureLink(req.path, sigParam, req.query.expires);
      if (!check.ok) {
        return res.status(403).send(`403 Forbidden (${check.reason})`);
      }
    }

    const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
    if (!fs.existsSync(filePath)) {
      return res.status(404).send('File missing from disk');
    }

    record.downloads = (record.downloads || 0) + 1;
    saveDatabase(db);

    res.download(filePath, record.originalName);
  } catch {
    res.status(500).send('Error downloading file');
  }
});

app.get('/s/:code', lookupRateLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'share.html'));
});

app.get('/c/:short', lookupRateLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'album.html'));
});

async function startPublicTunnel() {
  if (process.env.DISABLE_TUNNEL === 'true' || process.env.PUBLIC_URL || process.env.RENDER) {
    return;
  }

  try {
    if (!fs.existsSync(bin)) {
      await install(bin);
    }
    const cfTunnel = Tunnel.quick(`http://localhost:${PORT}`);
    cfTunnel.on('url', (url) => {
      cloudflareUrl = url;
      publicBaseUrl = url;
      console.log(`Cloudflare Public HTTPS URL active: ${cloudflareUrl}`);
    });
    cfTunnel.on('error', (err) => {
      console.error('Cloudflare tunnel error:', err.message);
    });
    process.on('SIGINT', () => {
      cfTunnel.stop();
      process.exit(0);
    });
    process.on('SIGTERM', () => {
      cfTunnel.stop();
      process.exit(0);
    });
  } catch (err) {
    console.error('Failed to start Cloudflare tunnel:', err.message);
  }
}

if (require.main === module) {
  try {
    fs.writeFileSync(PID_FILE, String(process.pid), 'utf8');
  } catch {}
  app.listen(PORT, () => {
    console.log(`sera.drop local server running at http://localhost:${PORT}`);
    startPublicTunnel();
  });
}

module.exports = { app, computeSecureLinkSignature, verifySecureLink };
