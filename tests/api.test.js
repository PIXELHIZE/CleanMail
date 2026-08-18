import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { createCleanMailServer } from '../src/cleanmail/api.js';

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
