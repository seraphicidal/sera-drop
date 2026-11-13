const net = require('net');

function normalizeIp(rawIp) {
  if (typeof rawIp !== 'string') return '';
  let trimmed = rawIp.trim();
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    trimmed = trimmed.slice(1, -1);
  }
  const zoneIndex = trimmed.indexOf('%');
  if (zoneIndex !== -1) {
    trimmed = trimmed.slice(0, zoneIndex);
  }
  return trimmed.replace(/^::ffff:/i, '');
}

function parseIpv6Words(addr) {
  let lower = String(addr || '').toLowerCase().trim();
  if (lower.startsWith('[') && lower.endsWith(']')) {
    lower = lower.slice(1, -1);
  }
  const zoneIndex = lower.indexOf('%');
  if (zoneIndex !== -1) {
    lower = lower.slice(0, zoneIndex);
  }
  if (!lower) return null;

  const firstDoubleColon = lower.indexOf('::');
  if (firstDoubleColon !== -1 && lower.indexOf('::', firstDoubleColon + 2) !== -1) {
    return null;
  }

  let headParts = [];
  let tailParts = [];
  if (firstDoubleColon !== -1) {
    const head = lower.slice(0, firstDoubleColon);
    const tail = lower.slice(firstDoubleColon + 2);
    headParts = head ? head.split(':') : [];
    tailParts = tail ? tail.split(':') : [];
  } else {
    headParts = lower.split(':');
  }

  const expandParts = (parts, allowTrailingV4) => {
    const words = [];
    for (let i = 0; i < parts.length; i += 1) {
      const part = parts[i];
      if (!part) return null;
      if (part.includes('.')) {
        if (!allowTrailingV4 || i !== parts.length - 1 || !net.isIPv4(part)) {
          return null;
        }
        const octets = part.split('.').map(Number);
        if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
          return null;
        }
        words.push(((octets[0] << 8) | octets[1]) >>> 0, ((octets[2] << 8) | octets[3]) >>> 0);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(part)) {
          return null;
        }
        words.push(parseInt(part, 16));
      }
    }
    return words;
  };

  const headWords = expandParts(headParts, tailParts.length === 0);
  const tailWords = expandParts(tailParts, true);
  if (!headWords || !tailWords) return null;

  if (firstDoubleColon !== -1) {
    const missing = 8 - (headWords.length + tailWords.length);
    if (missing < 1) return null;
    return [...headWords, ...new Array(missing).fill(0), ...tailWords];
  }
  return headWords.length === 8 ? headWords : null;
}

function isPrivateOrReservedIp(ip) {
  if (typeof ip !== 'string') return true;
  let cleanIp = ip.trim().toLowerCase();
  if (cleanIp.startsWith('[') && cleanIp.endsWith(']')) {
    cleanIp = cleanIp.slice(1, -1);
  }
  const zoneIndex = cleanIp.indexOf('%');
  if (zoneIndex !== -1) {
    cleanIp = cleanIp.slice(0, zoneIndex);
  }
  if (!net.isIP(cleanIp)) return true;
  if (cleanIp === '127.0.0.1' || cleanIp === '0.0.0.0' || cleanIp === '::1' || cleanIp === '::') return true;

  if (net.isIPv4(cleanIp)) {
    const parts = cleanIp.split('.').map(Number);
    if (parts[0] === 0 || parts[0] === 10 || parts[0] === 127) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 0 && (parts[2] === 0 || parts[2] === 2)) return true;
    if (parts[0] === 192 && parts[1] === 88 && parts[2] === 99) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true;
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true;
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true;
    if (parts[0] >= 224) return true;
    return false;
  }

  const words = parseIpv6Words(cleanIp);
  if (!words) return true;

  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0 &&
    words[6] === 0 &&
    words[7] === 1
  ) {
    return true;
  }

  if (words.every((w) => w === 0)) {
    return true;
  }

  if (
    (words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0xffff) ||
    (words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0xffff && words[5] === 0)
  ) {
    const v4 = `${(words[6] >> 8) & 0xff}.${words[6] & 0xff}.${(words[7] >> 8) & 0xff}.${words[7] & 0xff}`;
    return isPrivateOrReservedIp(v4);
  }

  if ((words[0] & 0xff00) === 0x0000) return true;
  if ((words[0] & 0xfe00) === 0xfc00) return true;
  if ((words[0] & 0xffc0) === 0xfe80) return true;
  if ((words[0] & 0xffc0) === 0xfec0) return true;
  if ((words[0] & 0xff00) === 0xff00) return true;
  if (words[0] === 0x2001 && (words[1] & 0xfe00) === 0x0000) return true;
  if (words[0] === 0x2001 && words[1] === 0x0db8) return true;
  if (words[0] === 0x3fff && (words[1] & 0xf000) === 0x0000) return true;
  if (words[0] === 0x5f00) return true;
  if (words[0] === 0x0100 && words[1] === 0 && words[2] === 0 && words[3] === 0) return true;
  if (words[0] === 0x0064 && words[1] === 0xff9b && words[2] === 1) return true;
  if (words[0] === 0x0064 && words[1] === 0xff9b) {
    const v4 = `${(words[6] >> 8) & 0xff}.${words[6] & 0xff}.${(words[7] >> 8) & 0xff}.${words[7] & 0xff}`;
    return isPrivateOrReservedIp(v4);
  }
  if (words[0] === 0x2002) {
    const v4 = `${(words[1] >> 8) & 0xff}.${words[1] & 0xff}.${(words[2] >> 8) & 0xff}.${words[2] & 0xff}`;
    return isPrivateOrReservedIp(v4);
  }

  return false;
}

module.exports = {
  normalizeIp,
  parseIpv6Words,
  isPrivateOrReservedIp
};
