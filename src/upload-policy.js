const fs = require('fs');
const path = require('path');

let fileTypeModulePromise = null;

async function detectFileTypeFromBuffer(buffer) {
  if (!fileTypeModulePromise) {
    fileTypeModulePromise = import('file-type');
  }
  const mod = await fileTypeModulePromise;
  return mod.fileTypeFromBuffer(buffer);
}

const MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024;
const MAX_GIF_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_TOTAL_STORAGE_BYTES = 5 * 1024 * 1024 * 1024;

const BLOCKED_PUBLIC_EXTENSIONS = new Set([
  '.exe', '.scr', '.cpl', '.jar', '.msi', '.msp', '.mst', '.bat', '.cmd', '.com',
  '.vbs', '.vbe', '.wsf', '.wsh', '.hta', '.reg', '.dll', '.sys', '.drv', '.pif',
  '.gadget', '.application', '.lnk', '.htaccess', '.php', '.phtml', '.phar', '.asp', '.aspx', '.jsp',
  '.elf', '.bin', '.run', '.dylib', '.so', '.ps1', '.psm1', '.psd1', '.apk', '.appx', '.msix'
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
  'video/x-matroska',
  'video/x-m4v',
  'video/x-msvideo',
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

const MIME_BY_EXT = {
  '.mp4': 'video/mp4',
  '.m4v': 'video/mp4',
  '.webm': 'video/webm',
  '.mov': 'video/quicktime',
  '.ogv': 'video/ogg',
  '.ogg': 'video/ogg',
  '.mkv': 'video/x-matroska',
  '.avi': 'video/x-msvideo',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.flac': 'audio/flac',
  '.aac': 'audio/aac',
  '.m4a': 'audio/mp4',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.bmp': 'image/bmp',
  '.ico': 'image/x-icon',
  '.pdf': 'application/pdf'
};

function decodeOriginalName(rawName) {
  if (typeof rawName !== 'string') return 'unnamed';
  if (/[^\x00-\xFF]/.test(rawName)) return rawName;
  try {
    const decoded = Buffer.from(rawName, 'latin1').toString('utf8');
    if (!decoded.includes('\uFFFD')) return decoded;
  } catch {}
  return rawName;
}

function getSafeExtension(filename) {
  const sanitized = String(filename || '').trim().replace(/[.\s]+$/, '');
  const ext = path.extname(sanitized).toLowerCase().trim();
  if (/^\.[a-z0-9]{1,10}$/.test(ext)) {
    return ext;
  }
  return '';
}

function sanitizeUploadFilename(rawOriginalName, maxLen = 240) {
  const segments = String(rawOriginalName || 'file').split(/[\\/]+/).filter(Boolean);
  const lastSegment = segments.length ? segments[segments.length - 1] : 'file';
  const rawBaseName = lastSegment.replace(/[\x00-\x1f\x7f]/g, '').trim() || 'file';
  if (rawBaseName.length <= maxLen) {
    return { cleanName: rawBaseName, rawBaseName };
  }
  const trailingDotMatch = /\.[a-zA-Z0-9]{1,16}(?=[.\s]*$)/.exec(rawBaseName);
  const extPart = trailingDotMatch ? rawBaseName.slice(trailingDotMatch.index).trim() : '';
  if (extPart && extPart.length < maxLen - 1) {
    const stemMax = maxLen - extPart.length;
    const stem = rawBaseName.slice(0, stemMax) || 'file';
    return { cleanName: `${stem}${extPart}`, rawBaseName };
  }
  return { cleanName: rawBaseName.slice(0, maxLen) || 'file', rawBaseName };
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
    const detected = await detectFileTypeFromBuffer(headerBuf);
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

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function detectPreviewCategory(mimeType, filename) {
  const ext = getSafeExtension(filename);
  const lowerMime = (mimeType || '').toLowerCase().trim();

  if (
    XSS_SENSITIVE_EXTENSIONS.has(ext) ||
    lowerMime.includes('svg') ||
    lowerMime.includes('html') ||
    lowerMime.includes('xml')
  ) {
    return 'text';
  }
  if (
    lowerMime.startsWith('image/') ||
    ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.avif', '.bmp', '.ico'].includes(ext)
  ) {
    return 'image';
  }
  if (
    lowerMime.startsWith('video/') ||
    ['.mp4', '.webm', '.ogg', '.ogv', '.mov', '.m4v', '.mkv', '.avi'].includes(ext)
  ) {
    return 'video';
  }
  if (
    lowerMime.startsWith('audio/') ||
    ['.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a', '.opus'].includes(ext)
  ) {
    return 'audio';
  }
  if (lowerMime === 'application/pdf' || ext === '.pdf') {
    return 'pdf';
  }

  const textExts = new Set([
    '.txt', '.md', '.json', '.js', '.ts', '.jsx', '.tsx', '.py',
    '.html', '.css', '.csv', '.xml', '.yml', '.yaml', '.sh',
    '.ps1', '.log', '.ini', '.conf', '.sql', '.c', '.cpp', '.rs', '.go'
  ]);
  if (
    lowerMime.startsWith('text/') ||
    lowerMime === 'application/json' ||
    lowerMime === 'application/javascript' ||
    lowerMime === 'application/xml' ||
    textExts.has(ext)
  ) {
    return 'text';
  }

  return 'other';
}

function resolveRawMediaDelivery(record) {
  const ext = getSafeExtension(record.originalName);
  let lowerMime = (record.mimeType || '').toLowerCase().trim();
  if ((!lowerMime || lowerMime === 'application/octet-stream') && MIME_BY_EXT[ext]) {
    lowerMime = MIME_BY_EXT[ext];
  }
  const category = detectPreviewCategory(lowerMime, record.originalName);

  if (category === 'text' || XSS_SENSITIVE_EXTENSIONS.has(ext)) {
    return {
      category: 'text',
      contentType: 'text/plain; charset=utf-8',
      disposition: 'inline',
      isPdf: false
    };
  }
  if (
    category === 'video' ||
    category === 'audio' ||
    category === 'image' ||
    SAFE_INLINE_MEDIA_MIMES.has(lowerMime)
  ) {
    const finalMime = lowerMime || (category === 'video' ? 'video/mp4' : 'application/octet-stream');
    return {
      category,
      contentType: finalMime,
      disposition: 'inline',
      isPdf: finalMime === 'application/pdf' || ext === '.pdf'
    };
  }
  return {
    category: 'other',
    contentType: 'application/octet-stream',
    disposition: 'attachment',
    isPdf: false
  };
}

function getDirectFileExt(record, delivery) {
  const ext = getSafeExtension(record.originalName);
  if (ext) return ext;
  if (!delivery) return '';
  if (delivery.category === 'video') {
    return delivery.contentType === 'video/webm' ? '.webm' : '.mp4';
  }
  if (delivery.category === 'audio') {
    return '.mp3';
  }
  if (delivery.category === 'image') {
    return '.png';
  }
  return '';
}

module.exports = {
  MAX_FILE_SIZE_BYTES,
  MAX_GIF_SIZE_BYTES,
  MAX_TOTAL_STORAGE_BYTES,
  BLOCKED_PUBLIC_EXTENSIONS,
  BLOCKED_PUBLIC_MIMES,
  BLOCKED_DETECTED_EXTENSIONS,
  BLOCKED_DETECTED_MIMES,
  XSS_SENSITIVE_EXTENSIONS,
  SAFE_INLINE_MEDIA_MIMES,
  MIME_BY_EXT,
  decodeOriginalName,
  getSafeExtension,
  sanitizeUploadFilename,
  buildContentDisposition,
  hasExecutableMagicHeader,
  isExecutableBinaryFile,
  validateUploadPolicy,
  formatBytes,
  detectPreviewCategory,
  resolveRawMediaDelivery,
  getDirectFileExt
};
