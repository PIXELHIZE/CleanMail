import assert from 'node:assert/strict';
import test from 'node:test';

import { createCleanMailWorker } from '../src/worker/handler.js';

function fixture() {
  const calls = [];
  const runtime = {
    detector: {
      stats: () => ({ total_blocked: 123 }),
      checkOnline: async (email) => ({ email, blocked: email.includes('temp') }),
      checkManyOnline: async (emails) => emails.map((email) => ({ email, blocked: false })),
    },
    analyzer: {
      analyze: async (email, options) => {
        calls.push({ email, options });
        return { email, blocked: false, options };
      },
      analyzeMany: async (emails, options) => {
        calls.push({ emails, options });
        return emails.map((email) => ({ email, blocked: false }));
      },
    },
  };
  return {
    calls,
    worker: createCleanMailWorker(() => runtime),
  };
}

async function body(response) {
  return response.json();
}

test('Worker health and stats endpoints expose runtime status', async () => {
  const { worker } = fixture();
  const health = await worker.fetch(new Request('https://cleanmail.test/health'));
  assert.equal(health.status, 200);
  assert.deepEqual(await body(health), {
    status: 'ok',
    service: 'CleanMail',
    runtime: 'cloudflare-workers',
  });

  const stats = await worker.fetch(new Request('https://cleanmail.test/v1/stats'));
  assert.equal(stats.status, 200);
  assert.deepEqual(await body(stats), { total_blocked: 123 });
});

test('Worker check endpoint supports GET and bounded batch POST requests', async () => {
  const { worker } = fixture();
  const single = await worker.fetch(new Request('https://cleanmail.test/v1/check?email=user%40temp.test'));
  assert.equal(single.status, 200);
  assert.equal((await body(single)).blocked, true);

  const batch = await worker.fetch(new Request('https://cleanmail.test/v1/check', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ emails: ['one@example.com', 'two@example.com'] }),
  }));
  assert.equal(batch.status, 200);
  assert.equal((await body(batch)).count, 2);
});

test('Worker analyze endpoint maps public JSON options to analyzer options', async () => {
  const { calls, worker } = fixture();
  const response = await worker.fetch(new Request('https://cleanmail.test/v1/analyze', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email: 'person@example.com',
      options: {
        rdap: false,
        smtp: true,
        catch_all: true,
        block_role: true,
        block_subaddress: true,
        block_prohibited: true,
        risk_threshold: 6.5,
      },
    }),
  }));
  assert.equal(response.status, 200);
  assert.deepEqual(calls[0].options, {
    rdap: false,
    smtp: true,
    catchAll: true,
    blockRoleAccounts: true,
    blockSubaddresses: true,
    blockProhibited: true,
    riskThreshold: 6.5,
  });
});

test('Worker rejects malformed, oversized, and out-of-range requests', async () => {
  const { worker } = fixture();
  const duplicateQuery = await worker.fetch(new Request(
    'https://cleanmail.test/v1/check?email=one%40example.com&email=two%40example.com',
  ));
  assert.equal(duplicateQuery.status, 400);

  const malformed = await worker.fetch(new Request('https://cleanmail.test/v1/check', {
    method: 'POST',
    body: '{',
  }));
  assert.equal(malformed.status, 400);

  const tooMany = await worker.fetch(new Request('https://cleanmail.test/v1/check', {
    method: 'POST',
    body: JSON.stringify({ emails: Array.from({ length: 101 }, (_, index) => `user${index}@example.com`) }),
  }));
  assert.equal(tooMany.status, 400);

  const badThreshold = await worker.fetch(new Request('https://cleanmail.test/v1/analyze', {
    method: 'POST',
    body: JSON.stringify({ email: 'user@example.com', options: { risk_threshold: 11 } }),
  }));
  assert.equal(badThreshold.status, 400);

  const oversized = await worker.fetch(new Request('https://cleanmail.test/v1/check', {
    method: 'POST',
    headers: { 'content-length': '16385' },
    body: '{}',
  }));
  assert.equal(oversized.status, 413);
});
