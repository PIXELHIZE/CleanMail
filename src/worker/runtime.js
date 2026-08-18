import dns from 'node:dns/promises';

import { CleanMailAnalyzer } from '../cleanmail/analyzer.js';
import { CleanMailRuntimeDetector } from '../cleanmail/runtime-detector.js';
import { WORKER_DATA } from './data.js';

const IANA_RDAP_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';

function smtpUnsupported() {
  return Promise.resolve({
    status: 'unsupported',
    reason: 'smtp_port_25_unavailable_on_cloudflare_workers',
    catch_all: null,
  });
}

function cachedRdapFetch(ctx) {
  return async (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    if (url !== IANA_RDAP_BOOTSTRAP) return fetch(input, init);

    const cacheKey = new Request(IANA_RDAP_BOOTSTRAP, { method: 'GET' });
    const cached = await caches.default.match(cacheKey);
    if (cached) return cached;

    const response = await fetch(input, init);
    if (!response.ok) return response;
    const headers = new Headers(response.headers);
    headers.set('cache-control', 'public, max-age=86400');
    const cacheable = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
    ctx.waitUntil(caches.default.put(cacheKey, cacheable.clone()));
    return cacheable;
  };
}

export function createWorkerRuntime(ctx) {
  const detector = new CleanMailRuntimeDetector(WORKER_DATA, {
    resolveMx: dns.resolveMx,
    resolve4: dns.resolve4,
    resolve6: dns.resolve6,
  });
  const analyzer = new CleanMailAnalyzer(detector, {
    resolveMx: dns.resolveMx,
    resolve4: dns.resolve4,
    resolve6: dns.resolve6,
    resolveNs: dns.resolveNs,
    resolveTxt: dns.resolveTxt,
    reverse: dns.reverse,
    fetch: cachedRdapFetch(ctx),
    smtpProbe: smtpUnsupported,
  });
  return { detector, analyzer };
}
