import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { createCleanMailServer } from '../src/cleanmail/api.js';
import { CleanMailDetector } from '../src/cleanmail/detector.js';

let server;
let baseUrl;

before(async () => {
  server = createCleanMailServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { address, port } = server.address();
  baseUrl = `http://${address}:${port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('health endpoint', async () => {
  const response = await fetch(`${baseUrl}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok', service: 'CleanMail' });
});

test('GET check endpoint', async () => {
  const response = await fetch(`${baseUrl}/v1/check?email=user%40mailyra.com`);
  const payload = await response.json();
  assert.equal(payload.disposable, true);
  assert.equal(payload.tier, 'verified');
});

test('batch check endpoint', async () => {
  const response = await fetch(`${baseUrl}/v1/check`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ emails: ['a@gmail.com', 'b@moakt.cc'] }),
  });
  const payload = await response.json();
  assert.equal(payload.count, 2);
  assert.equal(payload.results[0].disposable, false);
  assert.equal(payload.results[1].disposable, true);
});

test('missing email is a bad request', async () => {
  const response = await fetch(`${baseUrl}/v1/check`);
  assert.equal(response.status, 400);
});

test('oversized declared body is rejected', async () => {
  const response = await fetch(`${baseUrl}/v1/check`, {
    method: 'POST',
    body: 'x'.repeat(16 * 1024 + 1),
  });
  assert.equal(response.status, 413);
});

test('API blocks a syntactically valid domain with no MX records', async () => {
  const detector = new CleanMailDetector(undefined, {
    resolveMx: async () => { throw Object.assign(new Error('no data'), { code: 'ENODATA' }); },
  });
  const temporaryServer = createCleanMailServer(detector);
  await new Promise((resolve, reject) => {
    temporaryServer.once('error', reject);
    temporaryServer.listen(0, '127.0.0.1', resolve);
  });
  try {
    const { address, port } = temporaryServer.address();
    const response = await fetch(`http://${address}:${port}/v1/check?email=user%40no-mx.test`);
    const payload = await response.json();
    assert.equal(payload.blocked, true);
    assert.equal(payload.disposable, false);
    assert.equal(payload.deliverable, false);
    assert.equal(payload.reason, 'no_mx_records');
  } finally {
    await new Promise((resolve) => temporaryServer.close(resolve));
  }
});

test('deep analysis endpoint is wired to the analyzer', async () => {
  const fakeAnalyzer = {
    analyze: async (email) => ({ email, blocked: true, risk_score: 8, reason: 'high_risk_score' }),
    analyzeMany: async (emails) => emails.map((email) => ({ email, blocked: false, risk_score: 1 })),
  };
  const temporaryServer = createCleanMailServer(new CleanMailDetector(), fakeAnalyzer);
  await new Promise((resolve, reject) => {
    temporaryServer.once('error', reject);
    temporaryServer.listen(0, '127.0.0.1', resolve);
  });
  try {
    const { address, port } = temporaryServer.address();
    const response = await fetch(`http://${address}:${port}/v1/analyze?email=odd%40example.test`);
    const payload = await response.json();
    assert.equal(payload.blocked, true);
    assert.equal(payload.risk_score, 8);
  } finally {
    await new Promise((resolve) => temporaryServer.close(resolve));
  }
});

test('deep analysis endpoint validates the risk threshold', async () => {
  const response = await fetch(`${baseUrl}/v1/analyze`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'user@example.com', options: { risk_threshold: -1 } }),
  });
  assert.equal(response.status, 400);
});
