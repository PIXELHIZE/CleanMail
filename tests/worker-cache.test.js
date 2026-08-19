import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createCachedDnsResolvers,
  createCachedRdapFetch,
} from '../src/worker/infrastructure-cache.js';

class FakeCache {
  constructor() {
    this.entries = new Map();
  }

  async match(request) {
    return this.entries.get(request.url)?.clone();
  }

  async put(request, response) {
    this.entries.set(request.url, response.clone());
  }
}

function executionContext() {
  const work = [];
  return {
    waitUntil(promise) {
      work.push(promise);
    },
    async flush() {
      await Promise.all(work);
    },
  };
}

function dnsFixture(overrides = {}) {
  const empty = async () => [];
  return {
    resolveMx: empty,
    resolve4: empty,
    resolve6: empty,
    resolveNs: empty,
    resolveTxt: empty,
    reverse: empty,
    ...overrides,
  };
}

test('Worker DNS cache reuses public infrastructure without storing an email address', async () => {
  const cache = new FakeCache();
  const firstContext = executionContext();
  let liveLookups = 0;
  const first = createCachedDnsResolvers(firstContext, dnsFixture({
    resolveMx: async () => {
      liveLookups += 1;
      return [{ exchange: 'mx.example.net', priority: 10 }];
    },
  }), { cache });

  assert.deepEqual(await first.resolveMx('Example.COM.'), [{ exchange: 'mx.example.net', priority: 10 }]);
  assert.deepEqual(await first.resolveMx('example.com'), [{ exchange: 'mx.example.net', priority: 10 }]);
  assert.equal(liveLookups, 1);
  await firstContext.flush();

  const secondContext = executionContext();
  const second = createCachedDnsResolvers(secondContext, dnsFixture({
    resolveMx: async () => {
      throw new Error('live DNS should not be called on a cache hit');
    },
  }), { cache });
  assert.deepEqual(await second.resolveMx('example.com'), [{ exchange: 'mx.example.net', priority: 10 }]);
  assert.equal([...cache.entries.keys()].some((key) => key.includes('user%40') || key.includes('user@')), false);
  assert.equal([...cache.entries.keys()].every((key) => key.startsWith('https://infrastructure-cache.cleanmail.invalid/v1/dns/')), true);
});

test('Worker DNS cache keeps permanent negative answers briefly', async () => {
  const cache = new FakeCache();
  const firstContext = executionContext();
  const first = createCachedDnsResolvers(firstContext, dnsFixture({
    resolveMx: async () => {
      throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
    },
  }), { cache });
  await assert.rejects(first.resolveMx('missing.example'), { code: 'ENOTFOUND' });
  await firstContext.flush();

  let liveLookups = 0;
  const second = createCachedDnsResolvers(executionContext(), dnsFixture({
    resolveMx: async () => {
      liveLookups += 1;
      return [];
    },
  }), { cache });
  await assert.rejects(second.resolveMx('missing.example'), { code: 'ENOTFOUND' });
  assert.equal(liveLookups, 0);
});

test('Worker DNS cache does not retain transient resolver failures', async () => {
  const cache = new FakeCache();
  const first = createCachedDnsResolvers(executionContext(), dnsFixture({
    resolve4: async () => {
      throw Object.assign(new Error('temporary failure'), { code: 'ETIMEOUT' });
    },
  }), { cache });
  await assert.rejects(first.resolve4('example.com'), { code: 'ETIMEOUT' });
  assert.equal(cache.entries.size, 0);

  const second = createCachedDnsResolvers(executionContext(), dnsFixture({
    resolve4: async () => ['203.0.113.7'],
  }), { cache });
  assert.deepEqual(await second.resolve4('example.com'), ['203.0.113.7']);
});

test('Worker infrastructure lookups continue when the Cache API is unavailable', async () => {
  const unavailable = Promise.reject(new Error('cache unavailable'));
  const dns = createCachedDnsResolvers(executionContext(), dnsFixture({
    resolveMx: async () => [{ exchange: 'mx.example.com', priority: 0 }],
  }), { cache: unavailable });
  assert.deepEqual(await dns.resolveMx('example.com'), [{ exchange: 'mx.example.com', priority: 0 }]);

  const rdap = createCachedRdapFetch(executionContext(), {
    cache: Promise.reject(new Error('cache unavailable')),
    fetch: async () => Response.json({ status: 'live' }),
  });
  assert.deepEqual(await (await rdap('https://rdap.example.net/domain/example.com')).json(), { status: 'live' });
});

test('Worker RDAP cache stores public domain responses but bypasses unrelated fetches', async () => {
  const cache = new FakeCache();
  const firstContext = executionContext();
  let liveFetches = 0;
  const first = createCachedRdapFetch(firstContext, {
    cache,
    fetch: async (input) => {
      liveFetches += 1;
      return Response.json({ url: String(input), live: true });
    },
  });
  const rdapUrl = 'https://rdap.example.net/domain/example.com';
  assert.deepEqual(await (await first(rdapUrl)).json(), { url: rdapUrl, live: true });
  await firstContext.flush();

  const second = createCachedRdapFetch(executionContext(), {
    cache,
    fetch: async () => {
      liveFetches += 1;
      return Response.json({ live: false });
    },
  });
  assert.deepEqual(await (await second(rdapUrl)).json(), { url: rdapUrl, live: true });
  assert.deepEqual(await (await second('https://example.net/unrelated')).json(), { live: false });
  assert.equal(liveFetches, 2);
});
