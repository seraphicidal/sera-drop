const express = require('express');
const multer = require('multer');
const QRCode = require('qrcode');
const { bin, install, Tunnel } = require('cloudflared');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.set('trust proxy', 1);

const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'files.json');
const PID_FILE = path.join(DATA_DIR, 'server.pid');

const MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024;
const MAX_TOTAL_STORAGE_BYTES = 5 * 1024 * 1024 * 1024;
const MAX_CONCURRENT_UPLOADS = 4;

let activeUploads = 0;
let cloudflareUrl = null;
let publicBaseUrl = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || null;

fs.mkdirSync(UPLOADS_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

try {
  fs.writeFileSync(PID_FILE, String(process.pid), 'utf8');
} catch (err) {}

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({}, null, 2), 'utf8');
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
  maxRequests: 25,
  message: 'Upload rate limit exceeded. Please wait a few minutes.'
});

const lookupRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 120,
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

function getRecordByCode(db, code) {
  if (typeof code !== 'string' || !/^[a-zA-Z0-9]{6,12}$/.test(code)) {
    return null;
  }
  if (!Object.prototype.hasOwnProperty.call(db, code)) {
    return null;
  }
  const record = db[code];
  if (!record || typeof record !== 'object' || typeof record.storedName !== 'string') {
    return null;
  }
  return record;
}

function saveDatabase(db) {
  const tmpFile = `${DB_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmpFile, DB_FILE);
}

const BASE62 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

function generateShortCode(db, length = 8) {
  let code = '';
  do {
    code = '';
    for (let i = 0; i < length; i++) {
      code += BASE62[crypto.randomInt(0, BASE62.length)];
    }
  } while (Object.prototype.hasOwnProperty.call(db, code));
  return code;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function safeTokenEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
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
  return Object.values(db).reduce((sum, r) => sum + (Number(r.size) || 0), 0);
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

app.use(express.json({ limit: '64kb' }));
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
  const shortUrl = `${baseUrl}/s/${record.code}`;
  const downloadUrl = `${baseUrl}/d/${record.code}`;
  const rawUrl = `${baseUrl}/raw/${record.code}`;
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
    createdAt: record.createdAt,
    downloads: record.downloads || 0,
    uploadedFrom: record.uploadedFrom || 'public',
    previewCategory: detectPreviewCategory(record.mimeType, record.originalName),
    shortUrl,
    downloadUrl,
    rawUrl,
    qrCodeDataUrl
  };
}

app.get('/api/status', (req, res) => {
  res.json({
    publicUrl: publicBaseUrl,
    cloudflareUrl,
    localUrl: `http://localhost:${PORT}`
  });
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

      const db = loadDatabase();
      if (getTotalStorageUsed(db) + req.file.size > MAX_TOTAL_STORAGE_BYTES) {
        fs.unlinkSync(req.file.path);
        return res.status(507).json({ error: 'Server storage quota reached' });
      }

      const code = generateShortCode(db, 8);
      const deleteToken = crypto.randomBytes(16).toString('hex');

      const rawOriginalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
      const originalName = path.basename(rawOriginalName).replace(/[\x00-\x1f\x7f]/g, '').slice(0, 240) || 'file';

      const record = {
        code,
        originalName,
        storedName: path.basename(req.file.filename),
        mimeType: req.file.mimetype || 'application/octet-stream',
        size: req.file.size,
        createdAt: new Date().toISOString(),
        downloads: 0,
        uploadedFrom: isDirectLocalhost(req) ? 'local' : 'public',
        deleteTokenHash: hashToken(deleteToken)
      };

      db[code] = record;
      saveDatabase(db);

      const payload = await buildFileResponse(req, record);
      payload.deleteToken = deleteToken;
      res.status(201).json(payload);
    } catch (err) {
      if (req.file?.path && fs.existsSync(req.file.path)) {
        try {
          fs.unlinkSync(req.file.path);
        } catch {}
      }
      console.error('Upload error:', err);
      res.status(500).json({ error: 'Failed to upload file' });
    }
  }
);

app.get('/api/files', lookupRateLimiter, async (req, res) => {
  try {
    const db = loadDatabase();
    let records = [];

    if (isDirectLocalhost(req)) {
      records = Object.values(db);
    } else if (typeof req.query.codes === 'string' && req.query.codes.trim()) {
      const requestedCodes = req.query.codes
        .split(',')
        .map((c) => c.trim())
        .filter((c) => /^[a-zA-Z0-9]{6,12}$/.test(c))
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
    const db = loadDatabase();
    const record = getRecordByCode(db, req.params.code);
    if (!record) {
      return res.status(404).json({ error: 'Shared file not found' });
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
        safeTokenEqual(hashToken(providedToken), record.deleteTokenHash));

    if (!isAuthorized) {
      return res.status(403).json({ error: 'Unauthorized to delete this file' });
    }

    const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    delete db[record.code];
    saveDatabase(db);

    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

app.get('/raw/:code', lookupRateLimiter, (req, res) => {
  try {
    const db = loadDatabase();
    const record = getRecordByCode(db, req.params.code);
    if (!record) {
      return res.status(404).send('File not found');
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

    const category = detectPreviewCategory(record.mimeType, record.originalName);
    if (category === 'text') {
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
});

app.get('/d/:code', lookupRateLimiter, (req, res) => {
  try {
    const db = loadDatabase();
    const record = getRecordByCode(db, req.params.code);
    if (!record) {
      return res.status(404).send('File not found');
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

app.listen(PORT, () => {
  console.log(`sera.drop local server running at http://localhost:${PORT}`);
  startPublicTunnel();
});
