const http = require('http');
const https = require('https');
const { normalizeIp } = require('./ip-safety');

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade'
]);

function stripHopByHopHeaders(rawHeaders) {
  const cleaned = {};
  const connectionNominated = new Set();
  const connValue = rawHeaders && rawHeaders.connection;
  if (typeof connValue === 'string') {
    for (const token of connValue.split(',')) {
      const name = token.trim().toLowerCase();
      if (name) connectionNominated.add(name);
    }
  } else if (Array.isArray(connValue)) {
    for (const entry of connValue) {
      for (const token of String(entry).split(',')) {
        const name = token.trim().toLowerCase();
        if (name) connectionNominated.add(name);
      }
    }
  }

  for (const [key, val] of Object.entries(rawHeaders || {})) {
    const lowerKey = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowerKey) || connectionNominated.has(lowerKey)) {
      continue;
    }
    cleaned[key] = val;
  }
  return cleaned;
}

function createUpstreamProxyMiddleware({ getClientIp }) {
  let cachedUpstreamRaw = null;
  let cachedUpstreamBase = null;

  return (req, res, next) => {
    const upstreamTarget = process.env.UPSTREAM_URL
      ? process.env.UPSTREAM_URL.trim().replace(/\/+$/, '')
      : null;
    if (!upstreamTarget) {
      return next();
    }

    if (upstreamTarget !== cachedUpstreamRaw) {
      try {
        const parsedBase = new URL(upstreamTarget);
        if (parsedBase.protocol !== 'http:' && parsedBase.protocol !== 'https:') {
          return res.status(502).json({ error: 'Bad Gateway: invalid upstream configuration.' });
        }
        cachedUpstreamBase = parsedBase;
        cachedUpstreamRaw = upstreamTarget;
      } catch {
        return res.status(502).json({ error: 'Bad Gateway: invalid upstream configuration.' });
      }
    }

    const upstreamBase = cachedUpstreamBase;
    const rawUrl = String(req.url || '/');
    if (rawUrl.startsWith('//') || rawUrl.startsWith('/\\') || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(rawUrl)) {
      return res.status(400).json({ error: 'Invalid request target.' });
    }

    const safePath = '/' + rawUrl.replace(/^[\/\\]+/, '');
    let targetUrl;
    try {
      targetUrl = new URL(safePath, upstreamBase);
    } catch {
      return res.status(400).json({ error: 'Invalid request target.' });
    }
    if (targetUrl.origin !== upstreamBase.origin) {
      return res.status(400).json({ error: 'Invalid request target.' });
    }

    const isHttps = upstreamBase.protocol === 'https:';
    const transport = isHttps ? https : http;

    const socketIp = normalizeIp(req.socket?.remoteAddress || '');
    const resolvedIncomingIp = getClientIp(req);
    const incomingClientIp = resolvedIncomingIp !== 'unknown' ? resolvedIncomingIp : socketIp;

    const headers = stripHopByHopHeaders(req.headers);
    for (const key of Object.keys(headers)) {
      const lower = key.toLowerCase();
      if (
        lower === 'x-forwarded-for' ||
        lower === 'cf-connecting-ip' ||
        lower === 'true-client-ip' ||
        lower === 'forwarded' ||
        lower === 'x-real-ip' ||
        lower === 'x-forwarded-host' ||
        lower === 'x-forwarded-proto'
      ) {
        delete headers[key];
      }
    }
    headers.host = upstreamBase.host;
    if (incomingClientIp) {
      headers['x-real-ip'] = incomingClientIp;
    }
    headers['x-forwarded-host'] = req.headers.host || '';
    headers['x-forwarded-proto'] = req.protocol || 'https';
    if (incomingClientIp || socketIp) {
      headers['x-forwarded-for'] = incomingClientIp || socketIp;
    }

    let activeProxyRes = null;

    const proxyReq = transport.request(
      targetUrl,
      {
        method: req.method,
        headers,
        timeout: 1800000
      },
      (proxyRes) => {
        activeProxyRes = proxyRes;
        const responseHeaders = stripHopByHopHeaders(proxyRes.headers);
        for (const key of Object.keys(responseHeaders)) {
          const lower = key.toLowerCase();
          if (
            lower === 'x-content-type-options' ||
            lower === 'x-frame-options' ||
            lower === 'content-security-policy' ||
            lower === 'strict-transport-security' ||
            lower === 'referrer-policy' ||
            lower === 'permissions-policy' ||
            lower === 'cross-origin-opener-policy'
          ) {
            delete responseHeaders[key];
          }
        }
        res.writeHead(proxyRes.statusCode || 502, responseHeaders);

        proxyRes.on('error', () => {
          if (!res.destroyed) {
            res.destroy();
          }
        });

        proxyRes.pipe(res);
      }
    );

    proxyReq.on('timeout', () => {
      proxyReq.destroy(new Error('Gateway Timeout'));
    });

    proxyReq.on('error', (err) => {
      if (!res.headersSent) {
        const isTimeout = err && err.message === 'Gateway Timeout';
        res.status(isTimeout ? 504 : 502).json({
          error: isTimeout
            ? 'Gateway Timeout: upstream server did not respond in time.'
            : 'Bad Gateway: failed to connect to upstream server.'
        });
      } else if (!res.destroyed) {
        res.destroy();
      }
    });

    res.on('close', () => {
      if (!res.writableEnded) {
        if (!proxyReq.destroyed) {
          proxyReq.destroy();
        }
        if (activeProxyRes && !activeProxyRes.destroyed) {
          activeProxyRes.destroy();
        }
      }
    });

    req.on('error', () => {
      if (!proxyReq.destroyed) {
        proxyReq.destroy();
      }
    });

    req.on('aborted', () => {
      if (!proxyReq.destroyed) {
        proxyReq.destroy();
      }
    });

    req.pipe(proxyReq);
  };
}

module.exports = {
  createUpstreamProxyMiddleware
};
