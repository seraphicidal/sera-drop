function createRateLimiter({ windowMs, maxRequests, message, getKey, maxBuckets = 5000 }) {
  const buckets = new Map();
  let sweepIter = null;

  return (req, res, next) => {
    const key = getKey(req);
    const now = Date.now();

    if (buckets.size > 0) {
      if (!sweepIter) {
        sweepIter = buckets.entries();
      }
      for (let i = 0; i < 16; i += 1) {
        const nextItem = sweepIter.next();
        if (nextItem.done) {
          sweepIter = null;
          break;
        }
        if (now > nextItem.value[1].resetAt) {
          buckets.delete(nextItem.value[0]);
        }
      }
    }

    if (buckets.size >= maxBuckets) {
      for (const [k, v] of buckets.entries()) {
        if (now > v.resetAt) {
          buckets.delete(k);
        }
      }
      sweepIter = null;
      while (buckets.size >= maxBuckets) {
        const oldestKey = buckets.keys().next().value;
        if (oldestKey === undefined) break;
        buckets.delete(oldestKey);
      }
    }

    let bucket = buckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      if (bucket) {
        buckets.delete(key);
      }
      bucket = { count: 0, resetAt: now + windowMs };
    } else {
      buckets.delete(key);
    }
    bucket.count += 1;
    buckets.set(key, bucket);

    if (bucket.count > maxRequests) {
      return res.status(429).json({ error: message || 'Too many requests, please try again later.' });
    }
    next();
  };
}

module.exports = {
  createRateLimiter
};
