const CACHE_NAMESPACE = 'cleanmail-infrastructure-v1';
const CACHE_KEY_ORIGIN = 'https://infrastructure-cache.cleanmail.invalid';
const DNS_SUCCESS_TTL_SECONDS = 60 * 60;
const DNS_NEGATIVE_TTL_SECONDS = 5 * 60;
const RDAP_SUCCESS_TTL_SECONDS = 6 * 60 * 60;
const RDAP_NEGATIVE_TTL_SECONDS = 5 * 60;
const RDAP_BOOTSTRAP_TTL_SECONDS = 24 * 60 * 60;
const IANA_RDAP_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';
const PERMANENT_DNS_ERRORS = new Set(['ENODATA', 'ENOTFOUND', 'ENONAME']);

function normalizeSubject(value) {
  const subject = String(value).trim().toLowerCase().replace(/\.$/, '');
  if (!subject || subject.length > 512) throw new TypeError('invalid infrastructure cache subject');
  return subject;
}

function dnsCacheKey(recordType, subject) {
  const url = new URL(`/v1/dns/${encodeURIComponent(recordType)}/${encodeURIComponent(normalizeSubject(subject))}`, CACHE_KEY_ORIGIN);
  return new Request(url, { method: 'GET' });
}

function cacheError(operation, error) {
  console.error(JSON.stringify({
    message: 'CleanMail Worker infrastructure cache operation failed',
    operation,
    error: error instanceof Error ? error.message : String(error),
  }));
}

function trackWrite(ctx, promise, operation) {
  ctx.waitUntil(Promise.resolve(promise).catch((error) => cacheError(operation, error)));
}

function cacheResponse(payload, ttlSeconds, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': `public, max-age=${ttlSeconds}`,
      'x-content-type-options': 'nosniff',
    },
  });
}

async function readDnsCache(cache, key) {
  const response = await cache.match(key);
  if (!response) return null;
  const payload = await response.json();
  if (!payload || payload.version !== 1 || !['value', 'error'].includes(payload.kind)) return null;
  return payload;
}

function cachedDnsError(recordType, code) {
  const error = new Error(`cached DNS ${recordType} lookup failed with ${code}`);
  error.code = code;
  return error;
}

export function createCachedDnsResolvers(ctx, dns, options = {}) {
  if (!ctx || typeof ctx.waitUntil !== 'function') throw new TypeError('Worker execution context is required');
  const cachePromise = Promise.resolve(options.cache ?? caches.open(CACHE_NAMESPACE));
  const successTtlSeconds = options.successTtlSeconds ?? DNS_SUCCESS_TTL_SECONDS;
  const negativeTtlSeconds = options.negativeTtlSeconds ?? DNS_NEGATIVE_TTL_SECONDS;
  const pending = new Map();

  function wrap(recordType, resolver) {
    if (typeof resolver !== 'function') throw new TypeError(`${recordType} resolver is required`);
    return (subject) => {
      const normalized = normalizeSubject(subject);
      const pendingKey = `${recordType}:${normalized}`;
      if (pending.has(pendingKey)) return pending.get(pendingKey);
      const operation = (async () => {
        const key = dnsCacheKey(recordType, normalized);
        let cache = null;
        try {
          cache = await cachePromise;
          const cached = await readDnsCache(cache, key);
          if (cached?.kind === 'value') return cached.value;
          if (cached?.kind === 'error') throw cachedDnsError(recordType, cached.code);
        } catch (error) {
          if (PERMANENT_DNS_ERRORS.has(error?.code)) throw error;
          cacheError('dns.match', error);
        }

        try {
          const value = await resolver(normalized);
          if (cache) {
            const response = cacheResponse({ version: 1, kind: 'value', value }, successTtlSeconds);
            trackWrite(ctx, cache.put(key, response), 'dns.put');
          }
          return value;
        } catch (error) {
          if (cache && PERMANENT_DNS_ERRORS.has(error?.code)) {
            const response = cacheResponse({ version: 1, kind: 'error', code: error.code }, negativeTtlSeconds);
            trackWrite(ctx, cache.put(key, response), 'dns.put-negative');
          }
          throw error;
        }
      })();
      pending.set(pendingKey, operation);
      return operation;
    };
  }

  return {
    resolveMx: wrap('mx', dns.resolveMx),
    resolve4: wrap('a', dns.resolve4),
    resolve6: wrap('aaaa', dns.resolve6),
    resolveNs: wrap('ns', dns.resolveNs),
    resolveTxt: wrap('txt', dns.resolveTxt),
    reverse: wrap('ptr', dns.reverse),
  };
}

function rdapTtl(url, status) {
  if (status === 404 || status === 410) return RDAP_NEGATIVE_TTL_SECONDS;
  return url.href === IANA_RDAP_BOOTSTRAP ? RDAP_BOOTSTRAP_TTL_SECONDS : RDAP_SUCCESS_TTL_SECONDS;
}

function cacheableRdapUrl(url) {
  return url.href === IANA_RDAP_BOOTSTRAP || (url.protocol === 'https:' && url.pathname.includes('/domain/'));
}

export function createCachedRdapFetch(ctx, options = {}) {
  if (!ctx || typeof ctx.waitUntil !== 'function') throw new TypeError('Worker execution context is required');
  const cachePromise = Promise.resolve(options.cache ?? caches.open(CACHE_NAMESPACE));
  const fetchImpl = options.fetch ?? fetch;

  return async (input, init = {}) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    if (request.method !== 'GET' || !cacheableRdapUrl(url)) return fetchImpl(input, init);

    const cacheKey = new Request(url, { method: 'GET' });
    let cache = null;
    try {
      cache = await cachePromise;
      const cached = await cache.match(cacheKey);
      if (cached) return cached;
    } catch (error) {
      cacheError('rdap.match', error);
    }

    const response = await fetchImpl(input, init);
    if (!response.ok && ![404, 410].includes(response.status)) return response;
    const headers = new Headers(response.headers);
    headers.set('cache-control', `public, max-age=${rdapTtl(url, response.status)}`);
    const cacheable = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
    if (cache) trackWrite(ctx, cache.put(cacheKey, cacheable.clone()), 'rdap.put');
    return cacheable;
  };
}

export function openInfrastructureCache() {
  return caches.open(CACHE_NAMESPACE);
}
