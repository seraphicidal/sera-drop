const express = require('express');
const multer = require('multer');
const QRCode = require('qrcode');
const { bin, install, Tunnel } = require('cloudflared');
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

const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'files.json');
const ALBUMS_FILE = path.join(DATA_DIR, 'albums.json');
const PID_FILE = path.join(DATA_DIR, 'server.pid');

const MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024;
const MAX_GIF_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_TOTAL_STORAGE_BYTES = 5 * 1024 * 1024 * 1024;
const MAX_CONCURRENT_UPLOADS = 5;

const SECURE_LINK_SECRET =
  process.env.SERA_DROP_SECRET ||
  crypto.createHash('sha256').update(__dirname + '-sera-drop-secure-link').digest('hex');
const SIGNED_URL_TTL_SECONDS = 240;

const TTL_PRESETS_MS = {
  '1h': 60 * 60 * 1000,
  '12h': 12 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '72h': 72 * 60 * 60 * 1000
};

const BLOCKED_PUBLIC_EXTENSIONS = new Set([
  '.exe', '.scr', '.cpl', '.jar', '.msi', '.bat', '.cmd', '.com', '.vbs', '.lnk', '.htaccess'
]);
const BLOCKED_PUBLIC_MIMES = new Set([
  'application/x-msdownload',
  'application/exe',
  'application/x-dosexec',
  'application/x-msdos-program'
]);

const XSS_SENSITIVE_EXTENSIONS = new Set([
  '.html', '.htm', '.svg', '.xml', '.xhtml', '.php', '.phtml', '.js', '.mjs', '.cjs', '.htaccess'
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

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

function createRateLimiter({ windowMs, maxRequests, message }) {
  const buckets = new Map();
  return (req, res, next) => {
    const ip = req.headers['cf-connecting-ip'] || req.ip || 'unknown';
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

function requireCsrfHeader(req, res, next) {
  if (req.headers['x-requested-with'] !== 'sera.drop') {
    return res.status(403).json({ error: 'Missing required security header (X-Requested-With)' });
  }
  next();
}

function loadDatabase() {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (err) {
    return {};
  }
}

function saveDatabase(db) {
  const tmpFile = `${DB_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmpFile, DB_FILE);
}

function loadAlbums() {
  try {
    const raw = fs.readFileSync(ALBUMS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (err) {
    return {};
  }
}

function saveAlbums(albums) {
  const tmpFile = `${ALBUMS_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(albums, null, 2), 'utf8');
  fs.renameSync(tmpFile, ALBUMS_FILE);
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
          const filePath = path.join(UPLOADS_DIR, path.basename(storedName));
          if (fs.existsSync(filePath)) {
            try {
              fs.unlinkSync(filePath);
            } catch {}
          }
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

function computeSecureLinkMd5(uriPath, expires) {
  const raw = `${expires}${uriPath} ${SECURE_LINK_SECRET}`;
  return crypto.createHash('md5').update(raw, 'utf8').digest('base64url');
}

function verifySecureLink(uriPath, md5Param, expiresParam) {
  if (!md5Param || !expiresParam) {
    return { ok: false, reason: 'Missing md5 or expires query parameter' };
  }
  const expires = parseInt(String(expiresParam), 10);
  if (!Number.isFinite(expires)) {
    return { ok: false, reason: 'Invalid expires timestamp' };
  }
  if (expires < Math.floor(Date.now() / 1000)) {
    return { ok: false, reason: 'Signed link has expired' };
  }
  const expected = computeSecureLinkMd5(uriPath, expires);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(md5Param));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'Invalid secure_link MD5 signature' };
  }
  return { ok: true, reason: 'OK' };
}

function isDirectLocalhost(req) {
  if (req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']) {
    return false;
  }
  const host = (req.get('host') || '').toLowerCase();
  if (!/^localhost(:\d+)?$|^127\.0\.0\.1(:\d+)?$/.test(host)) {
    return false;
  }
  const remote = req.socket?.remoteAddress || '';
  return remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
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

function validateUploadPolicy({ originalName, mimeType, size, isLocal }) {
  const ext = getSafeExtension(originalName);
  const lowerName = (originalName || '').toLowerCase();
  const lowerMime = (mimeType || '').toLowerCase();

  if (!isLocal) {
    if (BLOCKED_PUBLIC_EXTENSIONS.has(ext) || lowerName.startsWith('.ht')) {
      return `File extension "${ext || lowerName}" is blocked for security reasons.`;
    }
    if (BLOCKED_PUBLIC_MIMES.has(lowerMime)) {
      return `MIME type "${lowerMime}" is blocked for security reasons.`;
    }
    if (ext === '.gif' && size > MAX_GIF_SIZE_BYTES) {
      return 'GIF uploads are limited to 50 MB.';
    }
  }
  if (size > MAX_FILE_SIZE_BYTES) {
    return 'File exceeds the 500 MB limit.';
  }
  return null;
}

function detectPreviewCategory(mimeType, filename) {
  const mime = (mimeType || '').toLowerCase();
  const ext = path.extname(filename || '').toLowerCase();

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
    const rawSig = computeSecureLinkMd5(rawPath, signedExpires);
    const dlSig = computeSecureLinkMd5(downloadPath, signedExpires);
    const dfSig = computeSecureLinkMd5(directFilePath, signedExpires);
    rawPath += `?md5=${rawSig}&expires=${signedExpires}`;
    downloadPath += `?md5=${dlSig}&expires=${signedExpires}`;
    directFilePath += `?md5=${dfSig}&expires=${signedExpires}`;
  }

  const downloadUrl = `${baseUrl}${downloadPath}`;
  const rawUrl = `${baseUrl}${rawPath}`;
  const directUrl = `${baseUrl}${directFilePath}`;

  const qrCodeDataUrl = await QRCode.toDataURL(shortUrl, {
    width: 280,
    margin: 2,
    color: {
      dark: '#0f172a',
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
  isLocal,
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

  const policyError = validateUploadPolicy({
    originalName: cleanName,
    mimeType,
    size,
    isLocal
  });
  if (policyError) {
    if (fs.existsSync(tempFilePath)) {
      try {
        fs.unlinkSync(tempFilePath);
      } catch {}
    }
    const err = new Error(policyError);
    err.statusCode = 415;
    throw err;
  }

  reapExpiredFiles();
  const db = loadDatabase();
  const sha256 = await computeFileSha256(tempFilePath);

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
        try {
          fs.unlinkSync(tempFilePath);
        } catch {}
      }
      storedName = path.basename(existing.storedName);
      deduplicated = true;
      break;
    }
  }

  if (!deduplicated && getTotalStorageUsed(db) + size > MAX_TOTAL_STORAGE_BYTES) {
    if (fs.existsSync(tempFilePath)) {
      try {
        fs.unlinkSync(tempFilePath);
      } catch {}
    }
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
    uploadedFrom: isLocal ? 'local' : 'public',
    deleteTokenHash: hashToken(deleteToken)
  };

  db[code] = record;
  saveDatabase(db);

  return { record, deleteToken };
}

function isPrivateOrReservedIp(ip) {
  if (!net.isIP(ip)) return true;
  if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === '::1' || ip === '::') return true;
  const lower = ip.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    return isPrivateOrReservedIp(lower.slice(7));
  }
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] >= 224) return true;
    return false;
  }
  if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80')) {
    return true;
  }
  return false;
}

async function fetchRemoteUrlToTempFile(rawUrl, allowLocalhost = false) {
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

  if (!allowLocalhost) {
    const addresses = await dns.promises.lookup(parsed.hostname, { all: true });
    if (!addresses.length || addresses.some((a) => isPrivateOrReservedIp(a.address))) {
      const err = new Error('Remote URL points to a restricted or private network address');
      err.statusCode = 412;
      throw err;
    }
  }

  const tempFilePath = path.join(
    UPLOADS_DIR,
    `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.bin`
  );

  return new Promise((resolve, reject) => {
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(
      parsed,
      {
        headers: {
          'User-Agent': 'sera.drop-urlupload/1.0'
        },
        timeout: 15000
      },
      (resp) => {
        if (resp.statusCode && resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
          resp.resume();
          const redirectErr = new Error('Remote URL redirects are not followed automatically; use direct media URL');
          redirectErr.statusCode = 412;
          return reject(redirectErr);
        }
        if (resp.statusCode !== 200) {
          resp.resume();
          const statusErr = new Error(`Remote server returned HTTP ${resp.statusCode}`);
          statusErr.statusCode = 412;
          return reject(statusErr);
        }

        const contentType = (resp.headers['content-type'] || 'application/octet-stream')
          .split(';')[0]
          .trim();
        const out = fs.createWriteStream(tempFilePath);
        let receivedBytes = 0;
        let aborted = false;

        resp.on('data', (chunk) => {
          receivedBytes += chunk.length;
          if (receivedBytes > MAX_FILE_SIZE_BYTES) {
            aborted = true;
            resp.destroy();
            out.destroy();
            try {
              fs.unlinkSync(tempFilePath);
            } catch {}
            const maxErr = new Error('Remote file exceeds 500 MB limit');
            maxErr.statusCode = 413;
            reject(maxErr);
          }
        });

        resp.pipe(out);

        out.on('finish', () => {
          if (aborted) return;
          const urlPathName = decodeURIComponent(path.basename(parsed.pathname || '') || 'remote-file');
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
          resolve({
            tempFilePath,
            originalName: finalName,
            mimeType: contentType,
            size: receivedBytes
          });
        });

        out.on('error', (err) => {
          try {
            fs.unlinkSync(tempFilePath);
          } catch {}
          reject(err);
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('Remote URL fetch timed out'));
    });
    req.on('error', (err) => {
      try {
        if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      } catch {}
      err.statusCode = 412;
      reject(err);
    });
  });
}

app.get('/api/status', (req, res) => {
  reapExpiredFiles();
  const db = loadDatabase();
  const albums = loadAlbums();
  res.json({
    publicUrl: publicBaseUrl,
    cloudflareUrl,
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
    Name: 'sera.drop (Catbox API Compatible)',
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
        isLocal: isDirectLocalhost(req),
        ttl,
        codeLength,
        requireSignedUrl
      });

      const payload = await buildFileResponse(req, record);
      payload.deleteToken = deleteToken;
      res.status(201).json(payload);
    } catch (err) {
      if (req.file?.path && fs.existsSync(req.file.path)) {
        try {
          fs.unlinkSync(req.file.path);
        } catch {}
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
    const isLocal = isDirectLocalhost(req);

    const fetched = await fetchRemoteUrlToTempFile(targetUrl, isLocal);
    const { record, deleteToken } = await registerUploadedFile({
      tempFilePath: fetched.tempFilePath,
      rawOriginalName: fetched.originalName,
      mimeType: fetched.mimeType,
      size: fetched.size,
      isLocal,
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

app.post('/user/api.php', uploadRateLimiter, (req, res) => {
  catboxUploadMiddleware(req, res, async (multerErr) => {
    if (multerErr) {
      return res.status(413).type('text/plain').send(multerErr.message);
    }
    try {
      const reqtype = String(req.body?.reqtype || '').trim();
      const userhash = String(req.body?.userhash || '').trim() || null;
      const baseUrl = resolveBaseUrl(req);
      const isLocal = isDirectLocalhost(req);

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
          isLocal,
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
        const fetched = await fetchRemoteUrlToTempFile(targetUrl, isLocal);
        const { record } = await registerUploadedFile({
          tempFilePath: fetched.tempFilePath,
          rawOriginalName: fetched.originalName,
          mimeType: fetched.mimeType,
          size: fetched.size,
          isLocal,
          ttl: 'permanent',
          codeLength: 6,
          lowercaseCode: true,
          userhash
        });
        const ext = getSafeExtension(record.originalName);
        return res.status(200).type('text/plain').send(`${baseUrl}/files/${record.code}${ext}`);
      }

      if (reqtype === 'deletefiles') {
        if (!userhash && !isLocal) {
          return res.status(400).type('text/plain').send('userhash is required.');
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
          if (!rec || (!isLocal && rec.userhash !== expectedHash)) {
            return res.status(400).type('text/plain').send(`File ${f} doesn't exist or unauthorized.`);
          }
          const storedName = rec.storedName;
          delete db[code];
          if (!isStoredFileReferenced(db, storedName, code)) {
            const fp = path.join(UPLOADS_DIR, path.basename(storedName));
            if (fs.existsSync(fp)) {
              try {
                fs.unlinkSync(fp);
              } catch {}
            }
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
        if (!album.userhash && !isLocal) {
          return res.status(403).type('text/plain').send('Anonymous albums cannot be edited or deleted.');
        }
        if (!isLocal && (!userhash || hashToken(userhash) !== album.userhash)) {
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
      return res.status(err.statusCode || 500).type('text/plain').send(err.message || 'API error');
    }
  });
});

app.post('/resources/internals/api.php', uploadRateLimiter, (req, res) => {
  catboxUploadMiddleware(req, res, async (multerErr) => {
    if (multerErr) {
      return res.status(413).type('text/plain').send(multerErr.message);
    }
    try {
      const reqtype = String(req.body?.reqtype || '').trim();
      if (reqtype !== 'fileupload' || !req.file) {
        return res.status(400).type('text/plain').send('Invalid Litterbox upload request.');
      }
      const timeKey = String(req.body?.time || '1h').trim();
      if (!TTL_PRESETS_MS[timeKey]) {
        return res.status(400).type('text/plain').send('Invalid time parameter (1h, 12h, 24h, 72h).');
      }
      const fileNameLength = parseInt(req.body?.fileNameLength || '6', 10) === 16 ? 16 : 6;
      const rawOriginalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');

      const { record } = await registerUploadedFile({
        tempFilePath: req.file.path,
        rawOriginalName,
        mimeType: req.file.mimetype,
        size: req.file.size,
        isLocal: isDirectLocalhost(req),
        ttl: timeKey,
        codeLength: fileNameLength,
        lowercaseCode: true
      });
      const ext = getSafeExtension(record.originalName);
      const baseUrl = resolveBaseUrl(req);
      return res.status(200).type('text/plain').send(`${baseUrl}/files/${record.code}${ext}`);
    } catch (err) {
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
      color: { dark: '#0f172a', light: '#ffffff' }
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
  } catch (err) {
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
      color: { dark: '#0f172a', light: '#ffffff' }
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
  } catch (err) {
    res.status(500).json({ error: 'Failed to load album' });
  }
});

app.get('/api/files', lookupRateLimiter, async (req, res) => {
  try {
    reapExpiredFiles();
    const db = loadDatabase();
    let records = [];

    if (isDirectLocalhost(req)) {
      records = Object.values(db);
    } else if (typeof req.query.codes === 'string' && req.query.codes.trim()) {
      const requestedCodes = req.query.codes
        .split(',')
        .map((c) => c.trim())
        .filter((c) => /^[a-zA-Z0-9]{6,16}$/.test(c))
        .slice(0, 50);
      records = requestedCodes.map((c) => getRecordByCode(db, c)).filter(Boolean);
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

    const providedToken = req.headers['x-delete-token'] || '';
    const isAuthorized =
      isDirectLocalhost(req) ||
      (record.deleteTokenHash &&
        providedToken &&
        hashToken(providedToken) === record.deleteTokenHash);

    if (!isAuthorized) {
      return res.status(403).json({ error: 'Unauthorized to delete this file' });
    }

    const storedName = record.storedName;
    delete db[record.code];
    saveDatabase(db);

    if (!isStoredFileReferenced(db, storedName, record.code)) {
      const filePath = path.join(UPLOADS_DIR, path.basename(storedName));
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

app.head(['/raw/:code', '/files/:codeWithExt', '/f/:code'], (req, res, next) => {
  if (req.query.stat === '1') {
    return next();
  }
  const rawParam = req.params.code || req.params.codeWithExt || '';
  const db = loadDatabase();
  const record = getRecordByCode(db, rawParam);
  if (!record) {
    return res.status(404).end();
  }
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', record.mimeType || 'application/octet-stream');
  res.setHeader('Content-Length', '0');
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
      const check = verifySecureLink(req.path, req.query.md5, req.query.expires);
      if (!check.ok) {
        return res.status(403).send(`403 Forbidden (${check.reason})`);
      }
    }

    const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
    if (!fs.existsSync(filePath)) {
      return res.status(404).send('File missing from disk');
    }

    res.setHeader(
      'Content-Security-Policy',
      "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD');

    const ext = getSafeExtension(record.originalName);
    const category = detectPreviewCategory(record.mimeType, record.originalName);
    if (category === 'text' || XSS_SENSITIVE_EXTENSIONS.has(ext)) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    } else {
      res.setHeader('Content-Type', record.mimeType || 'application/octet-stream');
    }
    res.setHeader(
      'Content-Disposition',
      `inline; filename="${encodeURIComponent(record.originalName)}"`
    );
    res.sendFile(filePath);
  } catch (err) {
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
      const check = verifySecureLink(req.path, req.query.md5, req.query.expires);
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
  } catch (err) {
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
  } catch (err) {}
  app.listen(PORT, () => {
    console.log(`sera.drop local server running at http://localhost:${PORT}`);
    startPublicTunnel();
  });
}

module.exports = { app };
