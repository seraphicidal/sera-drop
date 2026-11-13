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
const { normalizeIp, parseIpv6Words, isPrivateOrReservedIp } = require('./src/ip-safety');
const { createRateLimiter } = require('./src/rate-limiter');
const { createUpstreamProxyMiddleware } = require('./src/upstream-proxy');
const {
  MAX_FILE_SIZE_BYTES,
  MAX_TOTAL_STORAGE_BYTES,
  MIME_BY_EXT,
  decodeOriginalName,
  getSafeExtension,
  sanitizeUploadFilename,
  buildContentDisposition,
  isExecutableBinaryFile,
  validateUploadPolicy,
  formatBytes,
  detectPreviewCategory,
  resolveRawMediaDelivery,
  getDirectFileExt
} = require('./src/upload-policy');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
const rawTrustProxy = process.env.TRUST_PROXY;
app.set(
  'trust proxy',
  rawTrustProxy !== undefined
    ? rawTrustProxy === 'true'
      ? true
      : rawTrustProxy === 'false'
        ? false
        : /^\d+$/.test(rawTrustProxy)
          ? Number(rawTrustProxy)
          : rawTrustProxy
    : process.env.RENDER
      ? 1
      : 'loopback, linklocal, uniquelocal'
);

const defaultStorageRoot =
  fs.existsSync('/var/data') && fs.statSync('/var/data').isDirectory()
    ? '/var/data'
    : __dirname;

const UPLOADS_DIR = process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : path.join(defaultStorageRoot, 'uploads');
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(defaultStorageRoot, 'data');
const DB_FILE = path.join(DATA_DIR, 'files.json');
const DB_BACKUP_FILE = path.join(DATA_DIR, 'files.json.bak');
const ALBUMS_FILE = path.join(DATA_DIR, 'albums.json');
const ALBUMS_BACKUP_FILE = path.join(DATA_DIR, 'albums.json.bak');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');
const BLOCKED_HASHES_FILE = path.join(DATA_DIR, 'blocked_hashes.json');
const PID_FILE = path.join(DATA_DIR, 'server.pid');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SHARE_HTML_PATH = path.join(PUBLIC_DIR, 'share.html');
const ALBUM_HTML_PATH = path.join(PUBLIC_DIR, 'album.html');
const SHARE_HTML_TEMPLATE = fs.readFileSync(SHARE_HTML_PATH, 'utf8');
const ALBUM_HTML_TEMPLATE = fs.readFileSync(ALBUM_HTML_PATH, 'utf8');

const CLIENT_COOKIE_NAME = 'sera_cid';
function getClientStorageQuota() {
  return process.env.MAX_CLIENT_STORAGE_BYTES
    ? parseInt(process.env.MAX_CLIENT_STORAGE_BYTES, 10)
    : 2 * 1024 * 1024 * 1024;
}
const MAX_CONCURRENT_UPLOADS = 5;
const MAX_FILES_PER_CLIENT = 1000;
const MAX_STORED_REPORTS = 1000;
const SIGNED_URL_TTL_SECONDS = 240;

const TTL_PRESETS_MS = {
  '1h': 60 * 60 * 1000,
  '12h': 12 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '72h': 72 * 60 * 60 * 1000
};

const VALID_REPORT_CATEGORIES = new Set([
  'copyright',
  'malware',
  'illegal_content',
  'csam',
  'other'
]);

let activeUploads = 0;
let activeUploadBytes = 0;
const clientActiveUploadBytes = new Map();
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
  if (req.secure) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  next();
});

app.use(createUpstreamProxyMiddleware({ getClientIp }));

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return cookies;
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) {
      try {
        cookies[key] = decodeURIComponent(val);
      } catch {
        cookies[key] = val;
      }
    }
  }
  return cookies;
}

app.use((req, res, next) => {
  const cookies = parseCookies(req.headers.cookie);
  let clientId = cookies[CLIENT_COOKIE_NAME];
  let isNew = false;
  if (!clientId || typeof clientId !== 'string' || !/^[a-f0-9]{64}$/i.test(clientId)) {
    clientId = crypto.randomBytes(32).toString('hex');
    isNew = true;
  }

  req.clientId = clientId;
  req.clientIdHash = hashToken(clientId);

  const customHeader = req.headers['x-client-id'] || req.headers['x-user-hash'];
  if (typeof customHeader === 'string' && customHeader.trim()) {
    req.customClientHash = hashToken(customHeader.trim());
  } else {
    req.customClientHash = null;
  }

  if (isNew) {
    const isHttps = req.secure || process.env.NODE_ENV === 'production';
    const secureFlag = isHttps ? '; Secure' : '';
    res.setHeader(
      'Set-Cookie',
      `${CLIENT_COOKIE_NAME}=${clientId}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${secureFlag}`
    );
  }
  next();
});

function getClientIp(req) {
  if (process.env.TRUST_CF_HEADERS === 'true') {
    const peerIp = normalizeIp(req.socket?.remoteAddress || '');
    if (peerIp && isPrivateOrReservedIp(peerIp)) {
      const cfHeader = req.headers['cf-connecting-ip'];
      const cleanCf = normalizeIp(cfHeader);
      if (cleanCf && net.isIP(cleanCf)) {
        return cleanCf;
      }
    }
  }
  const candidate = normalizeIp(req.ip || '');
  if (candidate && net.isIP(candidate)) {
    return candidate;
  }
  const socketIp = normalizeIp(req.socket?.remoteAddress || '');
  return socketIp || 'unknown';
}

function getRateLimitKey(req) {
  const ip = getClientIp(req);
  if (net.isIPv6(ip)) {
    const words = parseIpv6Words(ip);
    if (words) {
      return `v6:${words[0].toString(16)}:${words[1].toString(16)}:${words[2].toString(16)}:${words[3].toString(16)}::/64`;
    }
  }
  return ip;
}

function hashClientIp(req) {
  return crypto
    .createHmac('sha256', SECURE_LINK_SECRET)
    .update(String(getClientIp(req)))
    .digest('hex');
}

function getEffectiveIpHash(req) {
  const rawIp = getClientIp(req);
  return ['127.0.0.1', '::1', 'unknown'].includes(rawIp) ? null : hashClientIp(req);
}

const uploadRateLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  maxRequests: process.env.NODE_ENV === 'test' ? 2000 : 40,
  message: 'Upload rate limit exceeded. Please wait a few minutes.',
  getKey: getRateLimitKey
});

const lookupRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: process.env.NODE_ENV === 'test' ? 5000 : 180,
  message: 'Too many requests. Please slow down.',
  getKey: getRateLimitKey
});

const reportRateLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  maxRequests: process.env.NODE_ENV === 'test' ? 1000 : 20,
  message: 'Too many abuse reports submitted. Please try again later.',
  getKey: getRateLimitKey
});

function requireCsrfHeader(req, res, next) {
  if (String(req.headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site') {
    return res.status(403).json({ error: 'Cross-site requests are not allowed' });
  }
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

let memoryDbCache = null;
let saveDbTimeout = null;

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

let memoryDbStat = null;
let pendingDbToSave = null;
let dbWriteSeq = 0;
let sidecarIndexMap = null;
let sidecarIndexDirMtimeMs = 0;
let sha256Index = null;

function rebuildSha256Index(db) {
  const next = new Map();
  if (db && typeof db === 'object') {
    for (const [code, rec] of Object.entries(db)) {
      if (rec && typeof rec.sha256 === 'string' && rec.sha256) {
        let bucket = next.get(rec.sha256);
        if (!bucket) {
          bucket = new Set();
          next.set(rec.sha256, bucket);
        }
        bucket.add(code);
      }
    }
  }
  sha256Index = next;
}

function indexDbRecord(rec) {
  if (!rec || !rec.code || !rec.sha256) return;
  if (!sha256Index) {
    sha256Index = new Map();
  }
  let bucket = sha256Index.get(rec.sha256);
  if (!bucket) {
    bucket = new Set();
    sha256Index.set(rec.sha256, bucket);
  }
  bucket.add(rec.code);
}

function unindexDbRecord(rec) {
  if (!sha256Index || !rec || !rec.code || !rec.sha256) return;
  const bucket = sha256Index.get(rec.sha256);
  if (bucket) {
    bucket.delete(rec.code);
    if (bucket.size === 0) {
      sha256Index.delete(rec.sha256);
    }
  }
}

function findReusableRecordBySha256(db, sha256, size) {
  if (!sha256Index) {
    rebuildSha256Index(db);
  }
  const codes = sha256Index.get(sha256);
  if (!codes) return null;
  const now = Date.now();
  for (const code of codes) {
    const existing = db[code];
    if (
      existing &&
      !isExpired(existing, now) &&
      existing.sha256 === sha256 &&
      existing.size === size &&
      existing.storedName &&
      fs.existsSync(path.join(UPLOADS_DIR, path.basename(existing.storedName)))
    ) {
      return existing;
    }
    if (!existing || isExpired(existing, now) || existing.sha256 !== sha256) {
      codes.delete(code);
    }
  }
  if (codes.size === 0) {
    sha256Index.delete(sha256);
  }
  return null;
}

function readFileStatSafe(filePath) {
  try {
    const st = fs.statSync(filePath);
    return { size: st.size, mtimeMs: st.mtimeMs, ino: st.ino };
  } catch {
    return null;
  }
}

function statsMatch(a, b) {
  return Boolean(a && b && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ino === b.ino);
}

function flushPendingDatabaseSave() {
  if (saveDbTimeout) {
    clearTimeout(saveDbTimeout);
    saveDbTimeout = null;
  }
  if (pendingDbToSave) {
    const target = pendingDbToSave;
    pendingDbToSave = null;
    saveDatabase(target, { syncSidecars: false });
  }
}

function saveRecordSidecar(record) {
  if (!record || !record.storedName || !record.code) return;
  try {
    const base = path.basename(record.storedName);
    const metaFilename = `${base}.${record.code}.meta.json`;
    const metaPath = path.join(UPLOADS_DIR, metaFilename);
    const tmpFile = `${metaPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(record, null, 2), 'utf8');
    fs.renameSync(tmpFile, metaPath);
    if (sidecarIndexMap) {
      sidecarIndexMap.set(record.code, metaFilename);
      const dirStat = readFileStatSafe(UPLOADS_DIR);
      if (dirStat) sidecarIndexDirMtimeMs = dirStat.mtimeMs;
    }
  } catch {}
}

function deleteRecordSidecar(storedName, code) {
  if (code && sidecarIndexMap) {
    sidecarIndexMap.delete(code);
  }
  if (!storedName) return;
  const base = path.basename(storedName);
  if (code) {
    safeUnlink(path.join(UPLOADS_DIR, `${base}.${code}.meta.json`));
  }
  safeUnlink(path.join(UPLOADS_DIR, `${base}.meta.json`));
  if (sidecarIndexMap) {
    const dirStat = readFileStatSafe(UPLOADS_DIR);
    if (dirStat) sidecarIndexDirMtimeMs = dirStat.mtimeMs;
  }
}

function deleteStoredFile(storedName, code = null) {
  if (!storedName) return;
  const base = path.basename(storedName);
  deleteRecordSidecar(base, code);
  safeUnlink(path.join(UPLOADS_DIR, base));
}

function removeRecordAndOrphanedFile(db, record) {
  if (!db || !record || !record.code) return;
  const code = record.code;
  const storedName = record.storedName;
  delete db[code];
  unindexDbRecord(record);
  deleteRecordSidecar(storedName, code);
  if (storedName && !isStoredFileReferenced(db, storedName, code)) {
    safeUnlink(path.join(UPLOADS_DIR, path.basename(storedName)));
  }
}

function recoverDatabaseFromSidecars(currentDb) {
  const merged = { ...currentDb };
  let restored = false;
  try {
    if (fs.existsSync(UPLOADS_DIR)) {
      const diskFiles = fs.readdirSync(UPLOADS_DIR);
      const nextIndex = new Map();
      for (const diskFile of diskFiles) {
        if (!diskFile.endsWith('.meta.json')) continue;
        const match = diskFile.match(/\.([a-zA-Z0-9]{6,16})\.meta\.json$/);
        if (match) {
          nextIndex.set(match[1], diskFile);
        }
        const metaPath = path.join(UPLOADS_DIR, diskFile);
        try {
          const raw = fs.readFileSync(metaPath, 'utf8');
          const rec = JSON.parse(raw);
          if (rec && rec.code && rec.storedName) {
            const binPath = path.join(UPLOADS_DIR, path.basename(rec.storedName));
            if (fs.existsSync(binPath) && !merged[rec.code]) {
              merged[rec.code] = rec;
              restored = true;
            }
          }
        } catch {}
      }
      sidecarIndexMap = nextIndex;
      const dirStat = readFileStatSafe(UPLOADS_DIR);
      sidecarIndexDirMtimeMs = dirStat ? dirStat.mtimeMs : 0;
    }
  } catch {}
  if (restored) {
    saveDatabase(merged);
  }
  return { merged, restored };
}

function syncMissingSidecars(db) {
  for (const rec of Object.values(db)) {
    if (rec && rec.storedName && rec.code) {
      const base = path.basename(rec.storedName);
      const metaPath = path.join(UPLOADS_DIR, `${base}.${rec.code}.meta.json`);
      if (!fs.existsSync(metaPath)) {
        saveRecordSidecar(rec);
      }
    }
  }
}

function findSidecarByCode(code) {
  if (!code || typeof code !== 'string' || !/^[a-zA-Z0-9]{6,16}$/.test(code)) {
    return null;
  }
  try {
    const dirStat = readFileStatSafe(UPLOADS_DIR);
    const dirMtime = dirStat ? dirStat.mtimeMs : 0;
    if (sidecarIndexMap === null || (!sidecarIndexMap.has(code) && dirMtime !== sidecarIndexDirMtimeMs)) {
      const nextIndex = new Map();
      if (fs.existsSync(UPLOADS_DIR)) {
        const diskFiles = fs.readdirSync(UPLOADS_DIR);
        for (const diskFile of diskFiles) {
          const match = diskFile.match(/\.([a-zA-Z0-9]{6,16})\.meta\.json$/);
          if (match) {
            nextIndex.set(match[1], diskFile);
          }
        }
      }
      sidecarIndexMap = nextIndex;
      sidecarIndexDirMtimeMs = dirMtime;
    }
    const targetFile = sidecarIndexMap.get(code);
    if (!targetFile) {
      return null;
    }
    const metaPath = path.join(UPLOADS_DIR, targetFile);
    if (!fs.existsSync(metaPath)) {
      sidecarIndexMap.delete(code);
      return null;
    }
    const raw = fs.readFileSync(metaPath, 'utf8');
    const rec = JSON.parse(raw);
    if (rec && rec.code === code && rec.storedName) {
      const binPath = path.join(UPLOADS_DIR, path.basename(rec.storedName));
      if (fs.existsSync(binPath)) {
        return rec;
      }
    }
  } catch {}
  return null;
}

function loadDatabase() {
  try {
    if (memoryDbCache !== null) {
      const diskStat = readFileStatSafe(DB_FILE);
      if (statsMatch(diskStat, memoryDbStat)) {
        return memoryDbCache;
      }
    }

    let parsed = null;
    let loadedFromDisk = false;
    if (fs.existsSync(DB_FILE)) {
      try {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        if (raw.trim()) {
          parsed = sanitizeMapObject(JSON.parse(raw));
          loadedFromDisk = true;
        }
      } catch {}
    }
    if ((!parsed || Object.keys(parsed).length === 0) && fs.existsSync(DB_BACKUP_FILE)) {
      try {
        const raw = fs.readFileSync(DB_BACKUP_FILE, 'utf8');
        if (raw.trim()) {
          const backupParsed = sanitizeMapObject(JSON.parse(raw));
          if (Object.keys(backupParsed).length > 0) {
            parsed = backupParsed;
            loadedFromDisk = true;
          }
        }
      } catch {}
    }
    if (!loadedFromDisk || !parsed || Object.keys(parsed).length === 0) {
      if (!parsed) {
        parsed = memoryDbCache ? { ...memoryDbCache } : {};
      }
      const recovery = recoverDatabaseFromSidecars(parsed);
      parsed = recovery.merged;
      syncMissingSidecars(parsed);
      if ((!loadedFromDisk || recovery.restored) && Object.keys(parsed).length > 0) {
        saveDatabase(parsed);
      }
    }
    memoryDbCache = parsed;
    memoryDbStat = readFileStatSafe(DB_FILE);
    rebuildSha256Index(parsed);
    return parsed;
  } catch {
    if (memoryDbCache !== null) {
      return memoryDbCache;
    }
    return {};
  }
}

function saveDatabase(db, options = {}) {
  if (!db || typeof db !== 'object') return;
  const { syncSidecars = false } = options;
  dbWriteSeq += 1;
  pendingDbToSave = null;
  if (saveDbTimeout) {
    clearTimeout(saveDbTimeout);
    saveDbTimeout = null;
  }
  memoryDbCache = db;
  if (!sha256Index) {
    rebuildSha256Index(db);
  }
  try {
    const tmpFile = `${DB_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(db, null, 2), 'utf8');
    fs.renameSync(tmpFile, DB_FILE);
    memoryDbStat = readFileStatSafe(DB_FILE);
    try {
      fs.copyFileSync(DB_FILE, DB_BACKUP_FILE);
    } catch {}
    if (syncSidecars) {
      syncMissingSidecars(db);
    }
  } catch {}
}

function scheduleDatabaseSave(db = memoryDbCache) {
  if (!db || typeof db !== 'object') return;
  memoryDbCache = db;
  pendingDbToSave = db;
  if (saveDbTimeout) return;
  saveDbTimeout = setTimeout(async () => {
    saveDbTimeout = null;
    const target = pendingDbToSave;
    if (!target) return;
    pendingDbToSave = null;
    const mySeq = ++dbWriteSeq;
    const tmpFile = `${DB_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    try {
      await fs.promises.writeFile(tmpFile, JSON.stringify(target, null, 2), 'utf8');
      if (mySeq !== dbWriteSeq) {
        await fs.promises.unlink(tmpFile).catch(() => {});
        return;
      }
      await fs.promises.rename(tmpFile, DB_FILE);
      if (mySeq === dbWriteSeq) {
        memoryDbStat = readFileStatSafe(DB_FILE);
      }
      await fs.promises.copyFile(DB_FILE, DB_BACKUP_FILE).catch(() => {});
    } catch {
      await fs.promises.unlink(tmpFile).catch(() => {});
    }
  }, 1500);
  if (typeof saveDbTimeout.unref === 'function') {
    saveDbTimeout.unref();
  }
}

let memoryAlbumsCache = null;
let memoryAlbumsStat = null;

function loadAlbums() {
  try {
    const diskStat = readFileStatSafe(ALBUMS_FILE);
    if (memoryAlbumsCache !== null && statsMatch(diskStat, memoryAlbumsStat)) {
      return memoryAlbumsCache;
    }

    let parsed = null;
    if (fs.existsSync(ALBUMS_FILE)) {
      try {
        const raw = fs.readFileSync(ALBUMS_FILE, 'utf8');
        if (raw.trim()) {
          parsed = sanitizeMapObject(JSON.parse(raw));
        }
      } catch {}
    }
    if ((!parsed || Object.keys(parsed).length === 0) && fs.existsSync(ALBUMS_BACKUP_FILE)) {
      try {
        const raw = fs.readFileSync(ALBUMS_BACKUP_FILE, 'utf8');
        if (raw.trim()) {
          parsed = sanitizeMapObject(JSON.parse(raw));
        }
      } catch {}
    }
    if (!parsed) {
      parsed = memoryAlbumsCache ? { ...memoryAlbumsCache } : {};
    }
    memoryAlbumsCache = parsed;
    memoryAlbumsStat = readFileStatSafe(ALBUMS_FILE);
    return parsed;
  } catch {
    if (memoryAlbumsCache !== null) {
      return memoryAlbumsCache;
    }
    return {};
  }
}

function saveAlbums(albums) {
  if (!albums || typeof albums !== 'object') return;
  memoryAlbumsCache = albums;
  try {
    const tmpFile = `${ALBUMS_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(albums, null, 2), 'utf8');
    fs.renameSync(tmpFile, ALBUMS_FILE);
    memoryAlbumsStat = readFileStatSafe(ALBUMS_FILE);
    try {
      fs.copyFileSync(ALBUMS_FILE, ALBUMS_BACKUP_FILE);
    } catch {}
  } catch {}
}

let memoryReportsCache = null;
let memoryReportsStat = null;

function loadReports() {
  try {
    const diskStat = readFileStatSafe(REPORTS_FILE);
    if (memoryReportsCache !== null && statsMatch(diskStat, memoryReportsStat)) {
      return memoryReportsCache;
    }
    if (!diskStat) {
      memoryReportsCache = [];
      memoryReportsStat = null;
      return memoryReportsCache;
    }
    const raw = fs.readFileSync(REPORTS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    memoryReportsCache = Array.isArray(parsed) ? parsed : [];
    memoryReportsStat = diskStat;
    return memoryReportsCache;
  } catch {
    if (memoryReportsCache !== null) {
      return memoryReportsCache;
    }
    return [];
  }
}

function saveReports(reports) {
  const bounded = Array.isArray(reports) ? reports.slice(-MAX_STORED_REPORTS) : [];
  memoryReportsCache = bounded;
  const tmpFile = `${REPORTS_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(bounded, null, 2), 'utf8');
  fs.renameSync(tmpFile, REPORTS_FILE);
  memoryReportsStat = readFileStatSafe(REPORTS_FILE);
}

let memoryBlockedCache = null;
let memoryBlockedStat = null;

function loadBlockedHashes() {
  try {
    const diskStat = readFileStatSafe(BLOCKED_HASHES_FILE);
    if (!diskStat) {
      memoryBlockedCache = {};
      memoryBlockedStat = null;
      return memoryBlockedCache;
    }
    if (memoryBlockedCache !== null && statsMatch(diskStat, memoryBlockedStat)) {
      return memoryBlockedCache;
    }
    const raw = fs.readFileSync(BLOCKED_HASHES_FILE, 'utf8');
    const parsed = sanitizeMapObject(JSON.parse(raw));
    memoryBlockedCache = parsed;
    memoryBlockedStat = diskStat;
    return parsed;
  } catch {
    if (memoryBlockedCache !== null) {
      return memoryBlockedCache;
    }
    return {};
  }
}

function saveBlockedHashes(blocked) {
  memoryBlockedCache = blocked;
  const tmpFile = `${BLOCKED_HASHES_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(blocked, null, 2), 'utf8');
  fs.renameSync(tmpFile, BLOCKED_HASHES_FILE);
  memoryBlockedStat = readFileStatSafe(BLOCKED_HASHES_FILE);
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

function isExpired(record, now = Date.now()) {
  if (!record || typeof record !== 'object') return true;
  if (!record.expiresAt) return false;
  const expireTime = new Date(record.expiresAt).getTime();
  return Number.isFinite(expireTime) && expireTime <= now;
}

function cleanupOrphanTempFiles(maxAgeMs = 2 * 60 * 60 * 1000) {
  try {
    const db = loadDatabase();
    const referenced = new Set();
    for (const r of Object.values(db)) {
      if (r && r.storedName) {
        referenced.add(path.basename(r.storedName));
      }
    }
    const cutoff = Date.now() - maxAgeMs;
    const entries = fs.readdirSync(UPLOADS_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const name = entry.name;
      if (referenced.has(name)) continue;
      if (!name.endsWith('.bin') && !name.endsWith('.tmp')) continue;
      const fullPath = path.join(UPLOADS_DIR, name);
      const st = fs.statSync(fullPath);
      if (st.mtimeMs <= cutoff) {
        safeUnlink(fullPath);
      }
    }
  } catch {}
}

let lastOrphanSweepMs = 0;

function reapExpiredFiles() {
  try {
    const db = loadDatabase();
    const now = Date.now();
    let changed = false;

    for (const [code, rec] of Object.entries(db)) {
      if (rec && isExpired(rec, now)) {
        removeRecordAndOrphanedFile(db, rec);
        changed = true;
      }
    }

    if (changed) {
      saveDatabase(db);
    }

    if (now - lastOrphanSweepMs > 30 * 60 * 1000) {
      lastOrphanSweepMs = now;
      cleanupOrphanTempFiles();
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
  let record = Object.prototype.hasOwnProperty.call(db, code) ? db[code] : null;
  if (!record || typeof record !== 'object' || typeof record.storedName !== 'string') {
    const recovered = findSidecarByCode(code);
    if (recovered) {
      db[code] = recovered;
      indexDbRecord(recovered);
      saveDatabase(db);
      record = recovered;
    } else {
      return null;
    }
  }

  if (isExpired(record)) {
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

function isRecordOwner(req, record) {
  if (!req || !record) return false;
  const deleteHeader = String(req.headers?.['x-delete-token'] || '').trim();
  const hasDeleteToken = Boolean(
    deleteHeader &&
      record.deleteTokenHash &&
      safeTimingEqualStrings(record.deleteTokenHash, hashToken(deleteHeader))
  );
  return Boolean(
    hasDeleteToken ||
      (req.clientIdHash && record.clientIdHash && safeTimingEqualStrings(req.clientIdHash, record.clientIdHash)) ||
      (req.customClientHash && record.userhash && safeTimingEqualStrings(req.customClientHash, record.userhash)) ||
      (req.customClientHash && record.clientIdHash && safeTimingEqualStrings(req.customClientHash, record.clientIdHash)) ||
      hasValidAdminAuth(req)
  );
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
  return { ok: true, reason: 'OK', expires };
}

function getTotalStorageUsed(db) {
  const seenStoredNames = new Set();
  const now = Date.now();
  let total = 0;
  for (const r of Object.values(db)) {
    if (r && !isExpired(r, now) && r.storedName && !seenStoredNames.has(r.storedName)) {
      seenStoredNames.add(r.storedName);
      total += Number(r.size) || 0;
    }
  }
  return total;
}

function getClientActiveKey(req, customHashOverride = null) {
  return String(
    customHashOverride ||
      req.customClientHash ||
      req.clientIdHash ||
      getEffectiveIpHash(req) ||
      'anon'
  );
}

function getClientActiveBytes(key) {
  return clientActiveUploadBytes.get(key) || 0;
}

function adjustClientActiveBytes(key, delta) {
  const next = Math.max(0, (clientActiveUploadBytes.get(key) || 0) + delta);
  if (next === 0) {
    clientActiveUploadBytes.delete(key);
  } else {
    clientActiveUploadBytes.set(key, next);
  }
}

function countClientActiveFiles(db, clientIdHash, customClientHash = null, ipHash = null) {
  if (!clientIdHash && !customClientHash && !ipHash) return 0;
  const now = Date.now();
  let count = 0;
  for (const r of Object.values(db)) {
    if (!r || isExpired(r, now)) continue;
    const matchClient = Boolean(clientIdHash && r.clientIdHash === clientIdHash);
    const matchCustom = Boolean(
      customClientHash && (r.userhash === customClientHash || r.clientIdHash === customClientHash)
    );
    const matchIp = Boolean(ipHash && r.ipHash === ipHash);
    if (matchClient || matchCustom || matchIp) {
      count += 1;
    }
  }
  return count;
}

function getClientStorageUsed(db, clientIdHash, customClientHash = null, ipHash = null) {
  if (!clientIdHash && !customClientHash && !ipHash) return 0;
  const seenStoredNames = new Set();
  const now = Date.now();
  let total = 0;
  for (const r of Object.values(db)) {
    if (!r || isExpired(r, now) || !r.storedName) continue;
    const matchClient = Boolean(clientIdHash && r.clientIdHash === clientIdHash);
    const matchCustom = Boolean(
      customClientHash && (r.userhash === customClientHash || r.clientIdHash === customClientHash)
    );
    const matchIp = Boolean(ipHash && r.ipHash === ipHash);
    if (matchClient || matchCustom || matchIp) {
      if (!seenStoredNames.has(r.storedName)) {
        seenStoredNames.add(r.storedName);
        total += Number(r.size) || 0;
      }
    }
  }
  return total;
}

function safeUnlinkStreamTarget(stream, filePath) {
  if (stream && !stream.destroyed) {
    stream.once('close', () => safeUnlink(filePath));
    stream.destroy();
  }
  safeUnlink(filePath);
}

const storage = {
  _handleFile(req, file, cb) {
    const safeName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.bin`;
    const finalPath = path.join(UPLOADS_DIR, safeName);
    const outStream = fs.createWriteStream(finalPath);
    let writtenBytes = 0;
    let settled = false;

    const failQuota = (message) => {
      if (settled) return;
      settled = true;
      file.stream.unpipe(outStream);
      file.stream.resume();
      safeUnlinkStreamTarget(outStream, finalPath);
      const err = new Error(message);
      err.statusCode = 507;
      cb(err);
    };

    file.stream.on('data', (chunk) => {
      if (settled) return;
      writtenBytes += chunk.length;
      if (typeof req.remainingServerQuota === 'number' && writtenBytes > req.remainingServerQuota) {
        failQuota('Server storage quota reached.');
        return;
      }
      if (typeof req.remainingClientQuota === 'number' && writtenBytes > req.remainingClientQuota) {
        failQuota('Client storage quota reached.');
      }
    });

    file.stream.on('error', (err) => {
      if (settled) return;
      settled = true;
      safeUnlinkStreamTarget(outStream, finalPath);
      cb(err);
    });

    outStream.on('error', (err) => {
      if (settled) return;
      settled = true;
      safeUnlink(finalPath);
      cb(err);
    });

    outStream.on('finish', () => {
      if (settled) return;
      settled = true;
      cb(null, {
        destination: UPLOADS_DIR,
        filename: safeName,
        path: finalPath,
        size: writtenBytes
      });
    });

    file.stream.pipe(outStream);
  },
  _removeFile(req, file, cb) {
    const targetPath = file && file.path;
    if (targetPath) {
      safeUnlink(targetPath);
    }
    cb(null);
  }
};

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

  const rawContentLength = req.headers['content-length'];
  let declaredLength = 0;
  if (rawContentLength !== undefined) {
    const trimmedLen = String(rawContentLength).trim();
    if (!/^\d+$/.test(trimmedLen)) {
      return res.status(400).json({ error: 'Invalid Content-Length header.' });
    }
    const parsedLen = Number(trimmedLen);
    if (!Number.isSafeInteger(parsedLen) || parsedLen < 0) {
      return res.status(413).json({ error: 'File exceeds the 500 MB limit.' });
    }
    declaredLength = parsedLen;
  }

  if (declaredLength > MAX_FILE_SIZE_BYTES + 1024 * 1024) {
    return res.status(413).json({ error: 'File exceeds the 500 MB limit.' });
  }

  const db = loadDatabase();
  const effectiveIpHash = getEffectiveIpHash(req);
  const clientActiveKey = getClientActiveKey(req);
  const activeClientBytes = getClientActiveBytes(clientActiveKey);

  const serverUsed = getTotalStorageUsed(db);
  if (serverUsed + activeUploadBytes + declaredLength > MAX_TOTAL_STORAGE_BYTES) {
    return res.status(507).json({ error: 'Server storage quota reached.' });
  }

  const clientQuota = getClientStorageQuota();
  const clientUsed = getClientStorageUsed(db, req.clientIdHash, req.customClientHash, effectiveIpHash);
  const isSmallCatboxControl = req.path === '/user/api.php' && declaredLength > 0 && declaredLength <= 65536;
  const remainingServerQuota = Math.max(0, MAX_TOTAL_STORAGE_BYTES - (serverUsed + activeUploadBytes));
  const remainingClientQuota = Math.max(0, clientQuota - (clientUsed + activeClientBytes));
  req.remainingServerQuota = remainingServerQuota;
  req.remainingClientQuota = remainingClientQuota;

  const isChunkedUploadEndpoint = rawContentLength === undefined && req.path !== '/user/api.php';
  if (
    (!isSmallCatboxControl && clientUsed + activeClientBytes + declaredLength > clientQuota) ||
    (isChunkedUploadEndpoint && remainingClientQuota <= 0)
  ) {
    if (req.path.includes('.php')) {
      return res.status(507).type('text/plain').send('Client storage quota reached.');
    }
    return res.status(507).json({
      error: `Client storage quota of ${formatBytes(clientQuota)} reached.`
    });
  }

  activeUploads += 1;
  activeUploadBytes += declaredLength;
  adjustClientActiveBytes(clientActiveKey, declaredLength);
  let decremented = false;
  const decrement = () => {
    if (!decremented) {
      decremented = true;
      activeUploads = Math.max(0, activeUploads - 1);
      activeUploadBytes = Math.max(0, activeUploadBytes - declaredLength);
      adjustClientActiveBytes(clientActiveKey, -declaredLength);
    }
  };
  res.on('finish', decrement);
  res.on('close', decrement);
  next();
}

app.use(express.json({ limit: '128kb' }));
app.use(express.urlencoded({ extended: false, limit: '128kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ALLOWED_HOST_REGEX = /^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+(:\d{1,5})?$/;

function resolveBaseUrl(req) {
  if (publicBaseUrl) {
    return publicBaseUrl.replace(/\/$/, '');
  }
  const host = (req.get('host') || '').trim();
  if (host && ALLOWED_HOST_REGEX.test(host)) {
    const isLocal = host.startsWith('localhost') || host.startsWith('127.0.0.1');
    const isHttps = req.secure || !isLocal;
    const proto = isHttps ? 'https' : 'http';
    return `${proto}://${host}`;
  }
  return `http://localhost:${PORT}`;
}

async function buildFileResponse(req, record, options = {}) {
  const includeQr = options.includeQr !== false;
  const disableSigning = options.disableSigning === true;
  const baseUrl = resolveBaseUrl(req);
  const delivery = resolveRawMediaDelivery(record);
  const ext = getDirectFileExt(record, delivery);
  let shortUrl = `${baseUrl}/s/${record.code}`;
  let rawPath = `/raw/${record.code}`;
  let downloadPath = `/d/${record.code}`;
  let directFilePath = `/files/${record.code}${ext}`;

  let signedExpires = null;
  if (record.requireSignedUrl && !disableSigning) {
    const defaultExpires = Math.floor(Date.now() / 1000) + SIGNED_URL_TTL_SECONDS;
    signedExpires = Number.isFinite(options.maxExpires)
      ? Math.min(defaultExpires, options.maxExpires)
      : defaultExpires;
    const shareSig = computeSecureLinkSignature(`/s/${record.code}`, signedExpires);
    const rawSig = computeSecureLinkSignature(rawPath, signedExpires);
    const dlSig = computeSecureLinkSignature(downloadPath, signedExpires);
    const dfSig = computeSecureLinkSignature(directFilePath, signedExpires);
    shortUrl += `?sig=${shareSig}&expires=${signedExpires}`;
    rawPath += `?sig=${rawSig}&expires=${signedExpires}`;
    downloadPath += `?sig=${dlSig}&expires=${signedExpires}`;
    directFilePath += `?sig=${dfSig}&expires=${signedExpires}`;
  }

  const downloadUrl = `${baseUrl}${downloadPath}`;
  const rawUrl = `${baseUrl}${rawPath}`;
  const directUrl = `${baseUrl}${directFilePath}`;

  let qrCodeDataUrl = null;
  if (includeQr) {
    qrCodeDataUrl = await QRCode.toDataURL(shortUrl, {
      width: 280,
      margin: 4,
      color: {
        dark: '#000000',
        light: '#ffffff'
      }
    });
  }

  return {
    code: record.code,
    originalName: record.originalName,
    mimeType: delivery.contentType || record.mimeType,
    size: record.size,
    sha256: record.sha256 || null,
    ttl: record.ttl || 'permanent',
    expiresAt: record.expiresAt || null,
    requireSignedUrl: Boolean(record.requireSignedUrl),
    signedExpires,
    createdAt: record.createdAt,
    downloads: record.downloads || 0,
    uploadedFrom: record.uploadedFrom || 'public',
    previewCategory: delivery.category,
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
  clientIdHash = null,
  ipHash = null,
  lowercaseCode = false
}) {
  const { cleanName, rawBaseName } = sanitizeUploadFilename(rawOriginalName, 240);

  if (!Number.isFinite(size) || size <= 0) {
    safeUnlink(tempFilePath);
    const err = new Error('File is empty.');
    err.statusCode = 400;
    throw err;
  }

  const rawPolicyError = validateUploadPolicy({
    originalName: rawBaseName,
    mimeType,
    size
  });
  const policyError =
    rawPolicyError ||
    validateUploadPolicy({
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

  if (await isExecutableBinaryFile(tempFilePath)) {
    safeUnlink(tempFilePath);
    const err = new Error('Executable binaries (PE/ELF/Mach-O) are not permitted.');
    err.statusCode = 415;
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
  const reusable = findReusableRecordBySha256(db, sha256, size);
  if (reusable) {
    if (path.basename(reusable.storedName) !== storedName) {
      safeUnlink(tempFilePath);
    }
    storedName = path.basename(reusable.storedName);
    deduplicated = true;
  }

  if (!deduplicated && getTotalStorageUsed(db) + size > MAX_TOTAL_STORAGE_BYTES) {
    safeUnlink(tempFilePath);
    const err = new Error('Server storage quota reached');
    err.statusCode = 507;
    throw err;
  }

  const clientQuota = getClientStorageQuota();
  const customHash = userhash ? hashToken(userhash) : null;
  const clientUsed = getClientStorageUsed(db, clientIdHash, customHash, ipHash);
  if (clientUsed + size > clientQuota) {
    if (!deduplicated) {
      safeUnlink(tempFilePath);
    }
    const err = new Error(`Client storage quota of ${formatBytes(clientQuota)} reached`);
    err.statusCode = 507;
    throw err;
  }

  if (countClientActiveFiles(db, clientIdHash, customHash, ipHash) >= MAX_FILES_PER_CLIENT) {
    if (!deduplicated) {
      safeUnlink(tempFilePath);
    }
    const err = new Error('Client file count limit reached.');
    err.statusCode = 507;
    throw err;
  }

  const normalizedTtl = TTL_PRESETS_MS[ttl] ? ttl : 'permanent';
  const expiresAt = TTL_PRESETS_MS[normalizedTtl]
    ? new Date(Date.now() + TTL_PRESETS_MS[normalizedTtl]).toISOString()
    : null;

  const code = generateShortCode(db, codeLength, lowercaseCode);
  const deleteToken = crypto.randomBytes(16).toString('hex');
  const cleanExt = getSafeExtension(cleanName);
  let resolvedMime = (mimeType || '').toLowerCase().trim();
  if ((!resolvedMime || resolvedMime === 'application/octet-stream') && MIME_BY_EXT[cleanExt]) {
    resolvedMime = MIME_BY_EXT[cleanExt];
  }
  if (!resolvedMime) {
    resolvedMime = 'application/octet-stream';
  }

  const record = {
    code,
    originalName: cleanName,
    storedName,
    mimeType: resolvedMime,
    size,
    sha256,
    deduplicated,
    ttl: normalizedTtl,
    expiresAt,
    requireSignedUrl: Boolean(requireSignedUrl),
    userhash: userhash ? hashToken(userhash) : null,
    clientIdHash: clientIdHash || null,
    ipHash: ipHash || null,
    createdAt: new Date().toISOString(),
    downloads: 0,
    uploadedFrom: 'public',
    deleteTokenHash: hashToken(deleteToken)
  };

  db[code] = record;
  indexDbRecord(record);
  saveDatabase(db);
  saveRecordSidecar(record);

  return { record, deleteToken };
}

async function fetchRemoteUrlToTempFile(rawUrl, options = {}) {
  const { maxClientRemainingBytes = null } = options;
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

  const ALLOWED_REMOTE_PORTS = new Set([80, 443, 8080, 8443]);
  const remotePort = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
  if (!ALLOWED_REMOTE_PORTS.has(remotePort)) {
    const err = new Error('Remote URL port is restricted (only standard web ports allowed)');
    err.statusCode = 412;
    throw err;
  }

  const lookupHost = parsed.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(lookupHost) && isPrivateOrReservedIp(lookupHost)) {
    const err = new Error('Remote URL points to a restricted or private network address');
    err.statusCode = 412;
    throw err;
  }

  let addresses;
  try {
    addresses = await dns.promises.lookup(lookupHost, { all: true });
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

  const initialDb = loadDatabase();
  if (getTotalStorageUsed(initialDb) + activeUploadBytes >= MAX_TOTAL_STORAGE_BYTES) {
    const err = new Error('Server storage quota reached');
    err.statusCode = 507;
    throw err;
  }
  if (maxClientRemainingBytes !== null && maxClientRemainingBytes <= 0) {
    const err = new Error('Client storage quota reached');
    err.statusCode = 507;
    throw err;
  }

  const safeAddress = addresses[0];
  const tempFilePath = path.join(
    UPLOADS_DIR,
    `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.bin`
  );

  return new Promise((resolve, reject) => {
    let settled = false;
    let trackedActiveBytes = 0;
    let activeResp = null;
    let activeOut = null;
    const releaseTrackedBytes = () => {
      if (trackedActiveBytes > 0) {
        activeUploadBytes = Math.max(0, activeUploadBytes - trackedActiveBytes);
        trackedActiveBytes = 0;
      }
    };
    const cleanupAndUnlink = () => {
      if (activeResp && !activeResp.destroyed) {
        activeResp.destroy();
      }
      safeUnlinkStreamTarget(activeOut, tempFilePath);
    };
    const finishReject = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      releaseTrackedBytes();
      cleanupAndUnlink();
      reject(err);
    };
    const finishResolve = (val) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      releaseTrackedBytes();
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
            return cb(null, addresses.map((a) => ({ address: a.address, family: a.family })));
          }
          return cb(null, safeAddress.address, safeAddress.family);
        }
      },
      (resp) => {
        activeResp = resp;
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

        const rawContentLength = resp.headers['content-length'];
        let declaredLen = 0;
        if (rawContentLength !== undefined) {
          const trimmed = String(rawContentLength).trim();
          if (!/^\d+$/.test(trimmed)) {
            resp.destroy();
            const lenErr = new Error('Remote server returned invalid Content-Length');
            lenErr.statusCode = 412;
            return finishReject(lenErr);
          }
          declaredLen = Number(trimmed);
          if (!Number.isSafeInteger(declaredLen)) {
            resp.destroy();
            const maxErr = new Error('Remote file exceeds 500 MB limit');
            maxErr.statusCode = 413;
            return finishReject(maxErr);
          }
        }
        if (declaredLen > MAX_FILE_SIZE_BYTES) {
          resp.resume();
          const maxErr = new Error('Remote file exceeds 500 MB limit');
          maxErr.statusCode = 413;
          return finishReject(maxErr);
        }
        if (declaredLen > 0 && getTotalStorageUsed(loadDatabase()) + activeUploadBytes + declaredLen > MAX_TOTAL_STORAGE_BYTES) {
          resp.resume();
          const quotaErr = new Error('Server storage quota reached');
          quotaErr.statusCode = 507;
          return finishReject(quotaErr);
        }
        if (maxClientRemainingBytes !== null && declaredLen > maxClientRemainingBytes) {
          resp.resume();
          const clientQuotaErr = new Error('Client storage quota reached');
          clientQuotaErr.statusCode = 507;
          return finishReject(clientQuotaErr);
        }

        const contentType = (resp.headers['content-type'] || 'application/octet-stream')
          .split(';')[0]
          .trim();
        const out = fs.createWriteStream(tempFilePath);
        activeOut = out;
        let receivedBytes = 0;

        resp.on('data', (chunk) => {
          receivedBytes += chunk.length;
          trackedActiveBytes += chunk.length;
          activeUploadBytes += chunk.length;
          if (receivedBytes > MAX_FILE_SIZE_BYTES) {
            const maxErr = new Error('Remote file exceeds 500 MB limit');
            maxErr.statusCode = 413;
            finishReject(maxErr);
            return;
          }
          if (getTotalStorageUsed(loadDatabase()) + activeUploadBytes > MAX_TOTAL_STORAGE_BYTES) {
            const quotaErr = new Error('Server storage quota reached');
            quotaErr.statusCode = 507;
            finishReject(quotaErr);
            return;
          }
          if (maxClientRemainingBytes !== null && receivedBytes > maxClientRemainingBytes) {
            const clientQuotaErr = new Error('Client storage quota reached');
            clientQuotaErr.statusCode = 507;
            finishReject(clientQuotaErr);
            return;
          }
        });

        resp.on('error', (err) => {
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
      if (activeResp && !activeResp.destroyed) {
        activeResp.destroy();
      }
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
  const name = String(process.env.OPERATOR_NAME || '').trim() || 'sera.drop Operator';
  const address = String(process.env.OPERATOR_ADDRESS || '').trim() || 'Online Service Provider, EU / Global';
  const email = String(process.env.OPERATOR_EMAIL || '').trim() || 'taniervlak@gmail.com';
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
        sera.drop uses a strictly necessary, pseudonymous first-party session cookie (<code>sera_cid</code>) solely to calculate storage usage, enforce fair-use disk quotas, and manage your uploads pursuant to § 25(2) No. 2 TDDDG and Art. 6(1)(b) GDPR. No advertising, analytics, or third-party tracking cookies are used. Upload history and delete tokens are additionally retained in your browser's <code>localStorage</code> under your control.
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
      return res.status(400).json({ error: 'Invalid category. Must be copyright, malware, illegal_content, csam, or other.' });
    }
    if (explanation.length < 10) {
      return res.status(400).json({ error: 'Explanation must be at least 10 characters.' });
    }
    if (notifierEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(notifierEmail)) {
      return res.status(400).json({ error: 'Invalid email address format.' });
    }
    if (!goodFaithConfirmed) {
      return res.status(400).json({ error: 'goodFaithConfirmed must be true pursuant to Art. 16(2)(d) DSA.' });
    }

    const reportId = `rep_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const receivedAt = new Date().toISOString();
    const clientIpHash = hashClientIp(req);

    let mitigated = false;
    const resolvedCode = extractCodeFromTarget(targetUrl, targetCode);
    const isAdmin = hasValidAdminAuth(req);
    if (isAdmin && resolvedCode && ['copyright', 'malware', 'illegal_content', 'csam'].includes(category)) {
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
        removeRecordAndOrphanedFile(db, record);
        saveDatabase(db);
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
      notifierName: notifierName || 'Anonymous',
      notifierEmail: notifierEmail || null,
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
    const results = await Promise.all(records.map((r) => buildFileResponse(req, r, { includeQr: false })));
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
    removeRecordAndOrphanedFile(db, record);
    saveDatabase(db);
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
    for (const rec of Object.values(db)) {
      if (rec && rec.sha256 === sha256) {
        removeRecordAndOrphanedFile(db, rec);
        removedCount += 1;
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
    const allReports = loadReports();
    const rawLimit = req.query.limit !== undefined ? parseInt(String(req.query.limit), 10) : null;
    const rawOffset = req.query.offset !== undefined ? parseInt(String(req.query.offset), 10) : 0;
    const offset = Number.isFinite(rawOffset) && rawOffset > 0 ? rawOffset : 0;
    const reports =
      rawLimit !== null && Number.isFinite(rawLimit) && rawLimit > 0
        ? allReports.slice(offset, offset + Math.min(rawLimit, 500))
        : offset > 0
          ? allReports.slice(offset)
          : allReports;
    res.json({ reports, total: allReports.length });
  } catch {
    res.status(500).json({ error: 'Failed to load reports' });
  }
});

app.get('/api/status', (req, res) => {
  const db = loadDatabase();
  const albums = loadAlbums();
  const now = Date.now();
  const activeFilesCount = Object.values(db).filter((r) => r && !isExpired(r, now)).length;
  const tunnelDisabled = Boolean(
    process.env.DISABLE_TUNNEL === 'true' || process.env.PUBLIC_URL || process.env.RENDER
  );
  const isPersistentDisk =
    fs.existsSync('/var/data') ||
    Boolean(process.env.DATA_DIR && !process.env.DATA_DIR.startsWith(__dirname));
  const rawIp = getClientIp(req);
  const effectiveIpHash = ['127.0.0.1', '::1', 'unknown'].includes(rawIp) ? null : hashClientIp(req);
  const isAdmin = hasValidAdminAuth(req);
  res.json({
    publicUrl: publicBaseUrl,
    cloudflareUrl,
    tunnelEnabled: !tunnelDisabled,
    localUrl: `http://localhost:${PORT}`,
    storageUsedBytes: getTotalStorageUsed(db),
    storageQuotaBytes: MAX_TOTAL_STORAGE_BYTES,
    clientStorageUsedBytes: getClientStorageUsed(db, req.clientIdHash, req.customClientHash, effectiveIpHash),
    clientStorageQuotaBytes: getClientStorageQuota(),
    totalFiles: activeFilesCount,
    totalAlbums: Object.keys(albums).length,
    storageRoot: isAdmin ? defaultStorageRoot : null,
    dataDir: isAdmin ? DATA_DIR : null,
    uploadsDir: isAdmin ? UPLOADS_DIR : null,
    isPersistentDisk
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

      const rawOriginalName = decodeOriginalName(req.file.originalname);
      const ttl = String(req.body?.ttl || 'permanent').trim();
      const codeLength = parseInt(req.body?.codeLength || '8', 10);
      const requireSignedUrl =
        req.body?.requireSignedUrl === 'true' ||
        req.body?.requireSignedUrl === '1' ||
        req.body?.requireSignedUrl === true ||
        req.body?.requireSignedUrl === 1;
      const userhash = String(req.body?.userhash || '').trim() || null;

      const rawIp = getClientIp(req);
      const effectiveIpHash = ['127.0.0.1', '::1', 'unknown'].includes(rawIp) ? null : hashClientIp(req);
      const { record, deleteToken } = await registerUploadedFile({
        tempFilePath: req.file.path,
        rawOriginalName,
        mimeType: req.file.mimetype,
        size: req.file.size,
        ttl,
        codeLength,
        requireSignedUrl,
        userhash,
        clientIdHash: req.clientIdHash,
        ipHash: effectiveIpHash
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
      req.body?.requireSignedUrl === 'true' ||
      req.body?.requireSignedUrl === '1' ||
      req.body?.requireSignedUrl === true ||
      req.body?.requireSignedUrl === 1;
    const userhash = String(req.body?.userhash || '').trim() || null;

    const effectiveIpHash = getEffectiveIpHash(req);
    const db = loadDatabase();
    const customHash = userhash ? hashToken(userhash) : req.customClientHash;
    const clientQuota = getClientStorageQuota();
    const clientUsed = getClientStorageUsed(db, req.clientIdHash, customHash, effectiveIpHash);
    const activeForClient = getClientActiveBytes(getClientActiveKey(req, customHash));
    const maxClientRemainingBytes = Math.max(0, clientQuota - (clientUsed + activeForClient));
    if (maxClientRemainingBytes <= 0) {
      return res.status(507).json({
        error: `Client storage quota of ${formatBytes(clientQuota)} reached.`
      });
    }
    const fetched = await fetchRemoteUrlToTempFile(targetUrl, { maxClientRemainingBytes });
    const { record, deleteToken } = await registerUploadedFile({
      tempFilePath: fetched.tempFilePath,
      rawOriginalName: fetched.originalName,
      mimeType: fetched.mimeType,
      size: fetched.size,
      ttl,
      codeLength,
      requireSignedUrl,
      userhash,
      clientIdHash: req.clientIdHash,
      ipHash: effectiveIpHash
    });

    const payload = await buildFileResponse(req, record);
    payload.deleteToken = deleteToken;
    res.status(201).json(payload);
  } catch (err) {
    console.error('URL upload error:', err.message);
    res.status(err.statusCode || 500).json({ error: err.message || 'Failed to fetch remote URL' });
  }
});

function csrfCrossSiteGuard(req, res, next) {
  const secFetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (secFetchSite === 'cross-site') {
    return res.status(403).type('text/plain').send('Cross-site requests not allowed.');
  }
  const origin = req.headers['origin'];
  if (origin) {
    try {
      const originHost = new URL(origin).host;
      const reqHost = req.get('host');
      if (originHost && reqHost && originHost !== reqHost) {
        return res.status(403).type('text/plain').send('Cross-site requests not allowed.');
      }
    } catch {
      return res.status(403).type('text/plain').send('Cross-site requests not allowed.');
    }
  }
  return next();
}

const catboxUploadMiddleware = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE_BYTES, files: 1 }
}).single('fileToUpload');

app.post('/user/api.php', csrfCrossSiteGuard, uploadRateLimiter, preUploadGuard, (req, res) => {
  catboxUploadMiddleware(req, res, async (multerErr) => {
    if (multerErr) {
      const status =
        multerErr.statusCode ||
        (multerErr.code === 'LIMIT_FILE_SIZE' ? 413 : multerErr instanceof multer.MulterError ? 400 : 500);
      return res.status(status).type('text/plain').send(multerErr.message);
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
        const effectiveIpHash = getEffectiveIpHash(req);
        const rawOriginalName = decodeOriginalName(req.file.originalname);
        const { record } = await registerUploadedFile({
          tempFilePath: req.file.path,
          rawOriginalName,
          mimeType: req.file.mimetype,
          size: req.file.size,
          ttl: 'permanent',
          codeLength: 6,
          lowercaseCode: true,
          userhash,
          clientIdHash: req.clientIdHash,
          ipHash: effectiveIpHash
        });
        const ext = getSafeExtension(record.originalName);
        return res.status(200).type('text/plain').send(`${baseUrl}/files/${record.code}${ext}`);
      }

      if (reqtype === 'urlupload') {
        const targetUrl = String(req.body?.url || '').trim();
        if (!targetUrl) {
          return res.status(412).type('text/plain').send('No url provided.');
        }
        const effectiveIpHash = getEffectiveIpHash(req);
        const db = loadDatabase();
        const customHash = userhash ? hashToken(userhash) : req.customClientHash;
        const clientQuota = getClientStorageQuota();
        const clientUsed = getClientStorageUsed(db, req.clientIdHash, customHash, effectiveIpHash);
        const activeForClient = getClientActiveBytes(getClientActiveKey(req, customHash));
        const maxClientRemainingBytes = Math.max(0, clientQuota - (clientUsed + activeForClient));
        if (maxClientRemainingBytes <= 0) {
          return res.status(507).type('text/plain').send('Client storage quota reached.');
        }
        const fetched = await fetchRemoteUrlToTempFile(targetUrl, { maxClientRemainingBytes });
        const { record } = await registerUploadedFile({
          tempFilePath: fetched.tempFilePath,
          rawOriginalName: fetched.originalName,
          mimeType: fetched.mimeType,
          size: fetched.size,
          ttl: 'permanent',
          codeLength: 6,
          lowercaseCode: true,
          userhash,
          clientIdHash: req.clientIdHash,
          ipHash: effectiveIpHash
        });
        const ext = getSafeExtension(record.originalName);
        return res.status(200).type('text/plain').send(`${baseUrl}/files/${record.code}${ext}`);
      }

      if (reqtype === 'deletefiles') {
        const filesList = String(req.body?.files || '')
          .split(/\s+/)
          .filter(Boolean);
        if (!filesList.length) {
          return res.status(400).type('text/plain').send('No files specified.');
        }
        const db = loadDatabase();
        const providedHash = userhash ? hashToken(userhash) : null;
        const targets = [];
        for (const f of filesList) {
          const code = path.basename(f).split('.')[0];
          const record = getRecordByCode(db, code);
          const isAuthorized =
            record &&
            (isAdmin ||
              isRecordOwner(req, record) ||
              Boolean(providedHash && record.userhash && safeTimingEqualStrings(providedHash, record.userhash)));
          if (!record || !isAuthorized) {
            return res.status(400).type('text/plain').send(`File ${f} doesn't exist or unauthorized.`);
          }
          targets.push({ code, rec: record });
        }
        for (const { rec } of targets) {
          removeRecordAndOrphanedFile(db, rec);
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

        const db = loadDatabase();
        for (const c of filesList) {
          const rec = getRecordByCode(db, c);
          if (rec && rec.requireSignedUrl) {
            return res.status(400).type('text/plain').send('Files requiring signed URLs cannot be added to albums.');
          }
        }

        const albums = loadAlbums();
        const short = generateShortCode(albums, 6, true);
        albums[short] = {
          short,
          title,
          description: desc,
          files: filesList,
          userhash: userhash ? hashToken(userhash) : null,
          clientIdHash: req.clientIdHash || null,
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

        if (['editalbum', 'addtoalbum'].includes(reqtype)) {
          const db = loadDatabase();
          for (const c of incomingFiles) {
            const rec = getRecordByCode(db, c);
            if (rec && rec.requireSignedUrl) {
              return res.status(400).type('text/plain').send('Files requiring signed URLs cannot be added to albums.');
            }
          }
        }

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

app.post('/resources/internals/api.php', csrfCrossSiteGuard, uploadRateLimiter, preUploadGuard, (req, res) => {
  catboxUploadMiddleware(req, res, async (multerErr) => {
    if (multerErr) {
      const status =
        multerErr.statusCode ||
        (multerErr.code === 'LIMIT_FILE_SIZE' ? 413 : multerErr instanceof multer.MulterError ? 400 : 500);
      return res.status(status).type('text/plain').send(multerErr.message);
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
      const rawOriginalName = decodeOriginalName(req.file.originalname);
      const rawIp = getClientIp(req);
      const effectiveIpHash = ['127.0.0.1', '::1', 'unknown'].includes(rawIp) ? null : hashClientIp(req);

      const { record } = await registerUploadedFile({
        tempFilePath: req.file.path,
        rawOriginalName,
        mimeType: req.file.mimetype,
        size: req.file.size,
        ttl: timeKey,
        codeLength: fileNameLength,
        lowercaseCode: true,
        clientIdHash: req.clientIdHash,
        ipHash: effectiveIpHash
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
    const inputFiles = Array.isArray(req.body?.files) ? req.body.files : [];
    if (inputFiles.length > 500) {
      return res.status(400).json({ error: 'Albums are limited to at most 500 files' });
    }
    const rawFiles = inputFiles.slice(0, 500);
    const db = loadDatabase();
    for (const rawCode of rawFiles) {
      const c = String(rawCode).trim().split('.')[0];
      const rec = getRecordByCode(db, c);
      if (rec && rec.requireSignedUrl) {
        return res.status(400).json({ error: 'Files requiring signed URLs cannot be added to albums' });
      }
    }
    const validFiles = rawFiles
      .map((c) => String(c).trim().split('.')[0])
      .filter((c) => {
        const rec = getRecordByCode(db, c);
        return rec && !rec.requireSignedUrl;
      });

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
      clientIdHash: req.clientIdHash || null,
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

app.delete('/api/albums/:short', lookupRateLimiter, requireCsrfHeader, (req, res) => {
  try {
    const albums = loadAlbums();
    const short = String(req.params.short || '').trim();
    const album = getAlbumByCode(albums, short);
    if (!album) {
      return res.status(404).json({ error: 'Album not found' });
    }

    const providedToken = String(req.headers['x-delete-token'] || '').trim();
    const hasOwnerToken = Boolean(
      album.userhash &&
        providedToken &&
        safeTimingEqualStrings(hashToken(providedToken), album.userhash)
    );
    const hasCookieOwnership = Boolean(
      album.clientIdHash &&
        req.clientIdHash &&
        safeTimingEqualStrings(album.clientIdHash, req.clientIdHash)
    );

    if (!hasOwnerToken && !hasCookieOwnership && !hasValidAdminAuth(req)) {
      return res.status(401).json({ error: 'Unauthorized: valid album delete token or owner session required' });
    }

    delete albums[short];
    saveAlbums(albums);
    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Failed to delete album' });
  }
});

app.get('/api/albums/:short', lookupRateLimiter, async (req, res) => {
  try {
    const albums = loadAlbums();
    const album = getAlbumByCode(albums, req.params.short);
    if (!album) {
      return res.status(404).json({ error: 'Album not found' });
    }
    const db = loadDatabase();
    const resolvedRecords = album.files
      .map((c) => getRecordByCode(db, c))
      .filter((r) => r && !r.requireSignedUrl);
    const filesPayload = await Promise.all(
      resolvedRecords.map((r) => buildFileResponse(req, r, { includeQr: false, disableSigning: true }))
    );

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
    const db = loadDatabase();
    const now = Date.now();
    let records = [];

    if (typeof req.query.codes === 'string' && req.query.codes.trim()) {
      const requestedCodes = req.query.codes
        .split(',')
        .map((c) => c.trim())
        .filter((c) => /^[a-zA-Z0-9]{6,16}$/.test(c))
        .slice(0, 100);
      const codeSet = new Set(requestedCodes);
      const byCode = requestedCodes
        .map((c) => getRecordByCode(db, c))
        .filter((r) => Boolean(r) && (!r.requireSignedUrl || isRecordOwner(req, r)));
      if (req.query.mine === '1' || req.query.mine === 'true') {
        const byCookie = Object.values(db).filter((r) => {
          if (!r || isExpired(r, now) || codeSet.has(r.code)) return false;
          if (req.clientIdHash && r.clientIdHash === req.clientIdHash) return true;
          if (
            req.customClientHash &&
            (r.userhash === req.customClientHash || r.clientIdHash === req.customClientHash)
          ) {
            return true;
          }
          return false;
        });
        records = [...byCode, ...byCookie];
      } else {
        records = byCode;
      }
    } else if (req.query.mine === '1' || req.query.mine === 'true') {
      records = Object.values(db).filter((r) => {
        if (!r || isExpired(r, now)) return false;
        if (req.clientIdHash && r.clientIdHash === req.clientIdHash) return true;
        if (
          req.customClientHash &&
          (r.userhash === req.customClientHash || r.clientIdHash === req.customClientHash)
        ) {
          return true;
        }
        return false;
      });
    } else {
      if (!hasValidAdminAuth(req)) {
        return res.status(401).json({ error: 'Unauthorized: valid Bearer ADMIN_TOKEN required' });
      }
      records = Object.values(db).filter((r) => r && !isExpired(r, now));
    }

    records.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const results = await Promise.all(records.map((r) => buildFileResponse(req, r, { includeQr: false })));
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
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      return res.status(404).json({ error: 'Shared file not found or has expired' });
    }

    let maxSignedExpires = null;
    if (record.requireSignedUrl) {
      const isOwner = isRecordOwner(req, record);
      const sigShare = verifySecureLink(`/s/${record.code}`, req.query.sig, req.query.expires);
      const sigPath = verifySecureLink(req.path, req.query.sig, req.query.expires);
      const matchedSig = sigShare.ok ? sigShare : sigPath;
      if (!isOwner && !matchedSig.ok) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        return res.status(403).json({ error: 'Valid signature or authorization required for signed file.' });
      }
      if (!isOwner && matchedSig.ok) {
        maxSignedExpires = matchedSig.expires;
      }
    }

    const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
    if (!fs.existsSync(filePath)) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      return res.status(404).json({ error: 'File no longer exists on server' });
    }

    const isEphemeral = Boolean(record.requireSignedUrl || record.expiresAt || record.ttl !== 'permanent');
    res.setHeader(
      'Cache-Control',
      isEphemeral ? 'private, no-cache, no-store, must-revalidate' : 'public, max-age=60'
    );

    const payload = await buildFileResponse(req, record, { maxExpires: maxSignedExpires });
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

    if (!isRecordOwner(req, record)) {
      return res.status(401).json({ error: 'Unauthorized: valid Bearer ADMIN_TOKEN required' });
    }

    removeRecordAndOrphanedFile(db, record);
    saveDatabase(db);

    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

function applyRawMediaHeaders(res, record, delivery, isEphemeral) {
  if (isEphemeral) {
    res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  } else {
    res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
  }

  if (delivery.category === 'text') {
    res.setHeader('Content-Security-Policy', "sandbox; default-src 'none';");
  } else if (delivery.isPdf) {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'"
    );
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type, Accept');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
  res.setHeader('Content-Type', delivery.contentType);
  res.setHeader(
    'Content-Disposition',
    buildContentDisposition(delivery.disposition, record.originalName)
  );
}

app.options(['/raw/:code', '/raw/:code.:ext', '/files/:codeWithExt', '/f/:code', '/d/:code'], lookupRateLimiter, (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type, Accept');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(204).end();
});

app.options('/api/*', lookupRateLimiter, (req, res) => {
  res.setHeader('Vary', 'Origin');
  const origin = String(req.headers.origin || '').trim();
  const reqHost = req.get('host');
  const sameOrigin = reqHost ? `${req.protocol}://${reqHost}` : '';
  const baseUrl = resolveBaseUrl(req);
  if (origin && (origin === sameOrigin || origin === baseUrl)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Requested-With, X-Delete-Token, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  res.status(204).end();
});

app.head(['/raw/:code', '/raw/:code.:ext', '/files/:codeWithExt', '/f/:code'], lookupRateLimiter, (req, res, next) => {
  if (req.query.stat === '1') {
    return next();
  }
  const rawParam = req.params.code || req.params.codeWithExt || '';
  const db = loadDatabase();
  const record = getRecordByCode(db, rawParam);
  if (!record) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    return res.status(404).end();
  }
  if (record.requireSignedUrl && !isRecordOwner(req, record)) {
    const sigParam = req.query.sig || req.query.md5;
    const check = verifySecureLink(req.path, sigParam, req.query.expires);
    if (!check.ok) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      return res.status(403).end();
    }
  }
  const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
  if (!fs.existsSync(filePath)) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    return res.status(404).end();
  }
  const isEphemeral = Boolean(record.requireSignedUrl || record.expiresAt || record.ttl !== 'permanent');
  const delivery = resolveRawMediaDelivery(record);
  applyRawMediaHeaders(res, record, delivery, isEphemeral);
  res.setHeader('Content-Length', String(record.size || 0));
  return res.status(200).end();
});

function serveRawMedia(req, res, rawCodeParam) {
  try {
    const db = loadDatabase();
    const record = getRecordByCode(db, rawCodeParam);
    if (!record) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      return res.status(404).send('File not found or expired');
    }

    if (record.requireSignedUrl && !isRecordOwner(req, record)) {
      const sigParam = req.query.sig || req.query.md5;
      const check = verifySecureLink(req.path, sigParam, req.query.expires);
      if (!check.ok) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        return res.status(403).send(`403 Forbidden (${check.reason})`);
      }
    }

    const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
    if (!fs.existsSync(filePath)) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      return res.status(404).send('File missing from disk');
    }

    const isEphemeral = Boolean(record.requireSignedUrl || record.expiresAt || record.ttl !== 'permanent');
    const delivery = resolveRawMediaDelivery(record);
    applyRawMediaHeaders(res, record, delivery, isEphemeral);
    res.sendFile(filePath, { acceptRanges: true });
  } catch {
    res.status(500).send('Error serving file');
  }
}

app.get(['/raw/:code', '/raw/:code.:ext'], lookupRateLimiter, (req, res) => {
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
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      return res.status(404).send('File not found or expired');
    }

    if (record.requireSignedUrl && !isRecordOwner(req, record)) {
      const sigParam = req.query.sig || req.query.md5;
      const check = verifySecureLink(req.path, sigParam, req.query.expires);
      if (!check.ok) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        return res.status(403).send(`403 Forbidden (${check.reason})`);
      }
    }

    const filePath = path.join(UPLOADS_DIR, path.basename(record.storedName));
    if (!fs.existsSync(filePath)) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      return res.status(404).send('File missing from disk');
    }

    const isEphemeral = Boolean(record.requireSignedUrl || record.expiresAt || record.ttl !== 'permanent');
    if (isEphemeral) {
      res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
    }

    if (req.method !== 'HEAD') {
      record.downloads = (record.downloads || 0) + 1;
      scheduleDatabaseSave(db);
    }

    res.download(filePath, record.originalName);
  } catch {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.status(500).send('Error downloading file');
  }
});

app.get(['/s/:code', '/s/:code.:ext'], lookupRateLimiter, (req, res) => {
  const rawParam = req.params.code || '';
  const db = loadDatabase();
  const record = getRecordByCode(db, rawParam);

  if (!record) {
    return res.sendFile(SHARE_HTML_PATH);
  }

  try {
    const rawTemplate = SHARE_HTML_TEMPLATE;
    const baseUrl = resolveBaseUrl(req);
    const delivery = resolveRawMediaDelivery(record);
    const title = `${record.originalName} — sera.drop`;
    const fileSizeFormatted = formatBytes(record.size);
    const description = `${record.originalName} (${fileSizeFormatted}) — shared on sera.drop`;
    const pageUrl = `${baseUrl}/s/${record.code}`;
    const directFileExt = getDirectFileExt(record, delivery);
    let directFilePath = `/files/${record.code}${directFileExt}`;
    let sigQuery = '';
    if (record.requireSignedUrl) {
      const sigCheck = verifySecureLink(`/s/${record.code}`, req.query.sig, req.query.expires);
      const pathSigCheck = verifySecureLink(req.path, req.query.sig, req.query.expires);
      const activeSig = sigCheck.ok ? sigCheck : pathSigCheck;
      if (!activeSig.ok && !isRecordOwner(req, record)) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        return res.status(403).sendFile(SHARE_HTML_PATH);
      }
      const defaultExpires = Math.floor(Date.now() / 1000) + SIGNED_URL_TTL_SECONDS;
      const expires = activeSig.ok ? Math.min(activeSig.expires, defaultExpires) : defaultExpires;
      const sig = computeSecureLinkSignature(directFilePath, expires);
      sigQuery = `?sig=${sig}&expires=${expires}`;
    }
    const directMediaUrl = `${baseUrl}${directFilePath}${sigQuery}`;
    const iconUrl = `${baseUrl}/icon.png`;

    const metaTags = [
      `<title>${escapeHtml(title)}</title>`,
      `<meta name="description" content="${escapeHtml(description)}" />`,
      `<meta property="og:site_name" content="sera.drop" />`,
      `<meta property="og:title" content="${escapeHtml(record.originalName)}" />`,
      `<meta property="og:description" content="${escapeHtml(description)}" />`,
      `<meta property="og:url" content="${escapeHtml(pageUrl)}" />`,
      `<meta name="theme-color" content="#d43255" />`
    ];

    if (delivery.category === 'video') {
      metaTags.push(
        `<meta property="og:type" content="video.other" />`,
        `<meta property="og:video" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta property="og:video:url" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta property="og:video:secure_url" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta property="og:video:type" content="${escapeHtml(delivery.contentType)}" />`,
        `<meta property="og:video:width" content="1280" />`,
        `<meta property="og:video:height" content="720" />`,
        `<meta name="twitter:card" content="player" />`,
        `<meta name="twitter:title" content="${escapeHtml(record.originalName)}" />`,
        `<meta name="twitter:description" content="${escapeHtml(description)}" />`,
        `<meta name="twitter:image" content="${escapeHtml(iconUrl)}" />`,
        `<meta name="twitter:player" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta name="twitter:player:width" content="1280" />`,
        `<meta name="twitter:player:height" content="720" />`,
        `<meta name="twitter:player:stream" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta name="twitter:player:stream:content_type" content="${escapeHtml(delivery.contentType)}" />`
      );
    } else if (delivery.category === 'image') {
      metaTags.push(
        `<meta property="og:type" content="website" />`,
        `<meta property="og:image" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta property="og:image:secure_url" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta property="og:image:type" content="${escapeHtml(delivery.contentType)}" />`,
        `<meta name="twitter:card" content="summary_large_image" />`,
        `<meta name="twitter:title" content="${escapeHtml(record.originalName)}" />`,
        `<meta name="twitter:description" content="${escapeHtml(description)}" />`,
        `<meta name="twitter:image" content="${escapeHtml(directMediaUrl)}" />`
      );
    } else if (delivery.category === 'audio') {
      metaTags.push(
        `<meta property="og:type" content="music.song" />`,
        `<meta property="og:audio" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta property="og:audio:secure_url" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta property="og:audio:type" content="${escapeHtml(delivery.contentType)}" />`,
        `<meta property="og:image" content="${escapeHtml(iconUrl)}" />`,
        `<meta name="twitter:card" content="player" />`,
        `<meta name="twitter:title" content="${escapeHtml(record.originalName)}" />`,
        `<meta name="twitter:description" content="${escapeHtml(description)}" />`,
        `<meta name="twitter:player" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta name="twitter:player:width" content="600" />`,
        `<meta name="twitter:player:height" content="120" />`,
        `<meta name="twitter:player:stream" content="${escapeHtml(directMediaUrl)}" />`,
        `<meta name="twitter:player:stream:content_type" content="${escapeHtml(delivery.contentType)}" />`
      );
    } else {
      metaTags.push(
        `<meta property="og:type" content="website" />`,
        `<meta property="og:image" content="${escapeHtml(iconUrl)}" />`,
        `<meta name="twitter:card" content="summary" />`,
        `<meta name="twitter:title" content="${escapeHtml(record.originalName)}" />`,
        `<meta name="twitter:description" content="${escapeHtml(description)}" />`
      );
    }

    const renderedHtml = rawTemplate.replace('<title>sera.drop</title>', () => metaTags.join('\n  '));
    const isEphemeral = Boolean(record.requireSignedUrl || record.expiresAt || record.ttl !== 'permanent');
    res.setHeader(
      'Cache-Control',
      isEphemeral ? 'private, no-cache, no-store, must-revalidate' : 'public, max-age=300'
    );
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(renderedHtml);
  } catch {
    return res.sendFile(SHARE_HTML_PATH);
  }
});

app.get('/c/:short', lookupRateLimiter, (req, res) => {
  const albums = loadAlbums();
  const album = getAlbumByCode(albums, req.params.short);

  if (!album) {
    return res.sendFile(ALBUM_HTML_PATH);
  }

  try {
    const rawTemplate = ALBUM_HTML_TEMPLATE;
    const baseUrl = resolveBaseUrl(req);
    const title = `${album.title || 'Album'} — sera.drop`;
    const description = `${album.title || 'Shared Album'} (${album.files.length} files) — sera.drop`;
    const pageUrl = `${baseUrl}/c/${album.short}`;
    const iconUrl = `${baseUrl}/icon.png`;

    const metaTags = [
      `<title>${escapeHtml(title)}</title>`,
      `<meta name="description" content="${escapeHtml(description)}" />`,
      `<meta property="og:site_name" content="sera.drop" />`,
      `<meta property="og:title" content="${escapeHtml(album.title || 'Shared Album')}" />`,
      `<meta property="og:description" content="${escapeHtml(description)}" />`,
      `<meta property="og:type" content="website" />`,
      `<meta property="og:url" content="${escapeHtml(pageUrl)}" />`,
      `<meta property="og:image" content="${escapeHtml(iconUrl)}" />`,
      `<meta name="twitter:card" content="summary" />`,
      `<meta name="twitter:title" content="${escapeHtml(album.title || 'Shared Album')}" />`,
      `<meta name="twitter:description" content="${escapeHtml(description)}" />`
    ];

    const renderedHtml = rawTemplate.replace('<title>sera.drop</title>', () => metaTags.join('\n  '));
    res.setHeader('Cache-Control', 'public, max-age=60');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(renderedHtml);
  } catch {
    return res.sendFile(ALBUM_HTML_PATH);
  }
});

let activeTunnel = null;

async function startPublicTunnel() {
  if (process.env.DISABLE_TUNNEL === 'true' || process.env.PUBLIC_URL || process.env.RENDER) {
    return;
  }

  try {
    if (!fs.existsSync(bin)) {
      await install(bin);
    }
    const cfTunnel = Tunnel.quick(`http://localhost:${PORT}`);
    activeTunnel = cfTunnel;
    cfTunnel.on('url', (url) => {
      cloudflareUrl = url;
      publicBaseUrl = url;
      console.log(`Cloudflare Public HTTPS URL active: ${cloudflareUrl}`);
    });
    cfTunnel.on('error', (err) => {
      console.error('Cloudflare tunnel error:', err.message);
    });
  } catch (err) {
    console.error('Failed to start Cloudflare tunnel:', err.message);
  }
}

app.use((err, req, res, next) => {
  if (req.file?.path) {
    safeUnlink(req.file.path);
  }
  if (res.headersSent) {
    return next(err);
  }
  const status =
    err.statusCode ||
    (err.code === 'LIMIT_FILE_SIZE' ? 413 : err instanceof multer.MulterError ? 400 : 500);
  res.status(status).json({ error: err.message || 'Internal server error' });
});

function handleGracefulShutdown() {
  flushPendingDatabaseSave();
  if (activeTunnel && typeof activeTunnel.stop === 'function') {
    try {
      activeTunnel.stop();
    } catch {}
    activeTunnel = null;
  }
  process.exit(0);
}

if (require.main === module) {
  try {
    fs.writeFileSync(PID_FILE, String(process.pid), 'utf8');
  } catch {}
  process.on('SIGINT', handleGracefulShutdown);
  process.on('SIGTERM', handleGracefulShutdown);
  process.on('beforeExit', flushPendingDatabaseSave);
  loadDatabase();
  cleanupOrphanTempFiles();
  app.listen(PORT, () => {
    console.log(`sera.drop local server running at http://localhost:${PORT}`);
    startPublicTunnel();
  });
}

module.exports = {
  app,
  computeSecureLinkSignature,
  verifySecureLink,
  CLIENT_COOKIE_NAME,
  getClientStorageQuota
};
