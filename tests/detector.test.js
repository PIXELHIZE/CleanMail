import assert from 'node:assert/strict';
import test from 'node:test';

import { CleanMailDetector } from '../src/cleanmail/detector.js';

const detector = new CleanMailDetector();

test('verified domain is blocked', () => {
  const result = detector.check('person@playboot.com');
  assert.equal(result.valid, true);
  assert.equal(result.blocked, true);
  assert.equal(result.disposable, true);
  assert.equal(result.tier, 'verified');
});

test('a domain removed from upstream lists remains blocked in an existing tier', () => {
  const result = detector.check('person@668mail.com');
  assert.equal(result.valid, true);
  assert.equal(result.blocked, true);
  assert.equal(result.disposable, true);
  assert.equal(result.tier, 'community');
  assert.equal(result.reason, 'confirmed_by_multiple_external_lists');
});

test('user-provided disposable samples are all blocked', () => {
  const emails = [
    'debitis.cum.sunt@tempmail.freevpnplanet.com',
    'bjf55@temp-email.io',
    'charlie.happy@beaconwarp.com',
    'coht86@mailingdragon.com',
    'elegantlightning24@imnmail.com',
    'v7y65pix58o29fj3@temp-mail.snaper24.com',
    'sasr35@mailingdragon.com',
  ];
  for (const email of emails) {
    const result = detector.check(email);
    assert.equal(result.blocked, true, email);
    assert.equal(result.disposable, true, email);
    assert.equal(result.tier, 'verified', email);
  }
});

test('new Korean and Japanese service domains are blocked', () => {
  const domains = [
    'vhm.cc',
    'acucmc.com',
    'gamerhive.xyz',
    'zzzzig.com',
    'tomy634.com',
    'miho.uk',
    '9k3r.com',
    'myfmcast.com',
  ];
  for (const domain of domains) {
    const result = detector.check(`person@${domain}`);
    assert.equal(result.disposable, true, domain);
    assert.equal(result.tier, 'verified', domain);
  }
});

test('subdomain matches its parent rule', () => {
  const result = detector.check('person@mx.jebqo.top');
  assert.equal(result.disposable, true);
  assert.equal(result.matched_domain, 'jebqo.top');
});

test('allowlist overrides source lists', () => {
  const result = detector.check('person@gmail.com');
  assert.equal(result.valid, true);
  assert.equal(result.blocked, false);
  assert.equal(result.disposable, false);
  assert.equal(result.tier, 'allowlist');
});

test('reserved example domain is not disposable', () => {
  const result = detector.check('person@example.com');
  assert.equal(result.disposable, false);
  assert.equal(result.blocked, false);
  assert.equal(result.tier, 'allowlist');
});

test('unknown domain is allowed', () => {
  const result = detector.check('person@cleanmail-test.invalid');
  assert.equal(result.valid, true);
  assert.equal(result.disposable, false);
  assert.equal(result.reason, 'not_listed');
});

test('invalid email is reported separately', () => {
  const result = detector.check('not-an-email');
  assert.equal(result.valid, false);
  assert.equal(result.blocked, true);
  assert.equal(result.disposable, false);
  assert.equal(result.reason, 'invalid_email_syntax');
});

test('practical syntax check rejects dot and delimiter errors in the local part', () => {
  for (const email of ['.start@example.com', 'end.@example.com', 'two..dots@example.com', 'name<bad>@example.com']) {
    const result = detector.check(email);
    assert.equal(result.valid, false, email);
    assert.equal(result.blocked, true, email);
  }
});

test('IDN domain is normalized', () => {
  const result = detector.check('person@예시.한국');
  assert.equal(result.valid, true);
  assert.match(result.domain, /^xn--/);
});

test('online check blocks a rotating domain by MX hostname', async () => {
  let lookups = 0;
  const onlineDetector = new CleanMailDetector(undefined, {
    resolveMx: async () => {
      lookups += 1;
      return [{ exchange: 'smtp.yopmail.com', priority: 10 }];
    },
    resolve4: async () => [],
    resolve6: async () => [],
  });
  const first = await onlineDetector.checkOnline('person@fresh-rotation.test');
  const second = await onlineDetector.checkOnline('other@fresh-rotation.test');
  assert.equal(first.disposable, true);
  assert.equal(first.blocked, true);
  assert.equal(first.tier, 'mx');
  assert.equal(first.matched_mx_pattern, 'yopmail.com');
  assert.equal(second.disposable, true);
  assert.equal(lookups, 1);
});

test('online check blocks a rotating domain by dedicated MX IP', async () => {
  const onlineDetector = new CleanMailDetector(undefined, {
    resolveMx: async () => [{ exchange: 'mail.rotating-inbox.example', priority: 10 }],
    resolve4: async () => ['161.35.253.124'],
    resolve6: async () => { throw Object.assign(new Error('not found'), { code: 'ENODATA' }); },
  });
  const result = await onlineDetector.checkOnline('person@brand-new-temp.test');
  assert.equal(result.disposable, true);
  assert.equal(result.blocked, true);
  assert.equal(result.tier, 'mx');
  assert.equal(result.matched_mx_ip, '161.35.253.124');
});

test('allowlist bypasses online DNS classification', async () => {
  const onlineDetector = new CleanMailDetector(undefined, {
    resolveMx: async () => { throw new Error('should not be called'); },
  });
  const result = await onlineDetector.checkOnline('person@gmail.com');
  assert.equal(result.disposable, false);
  assert.equal(result.blocked, false);
  assert.equal(result.tier, 'allowlist');
});

test('missing MX records are blocked as undeliverable', async () => {
  const onlineDetector = new CleanMailDetector(undefined, {
    resolveMx: async () => { throw Object.assign(new Error('no data'), { code: 'ENODATA' }); },
  });
  const result = await onlineDetector.checkOnline('person@no-mail-server.test');
  assert.equal(result.valid, true);
  assert.equal(result.blocked, true);
  assert.equal(result.disposable, false);
  assert.equal(result.deliverable, false);
  assert.equal(result.tier, 'deliverability');
  assert.equal(result.reason, 'no_mx_records');
});

test('transient DNS failure keeps the static not-listed result', async () => {
  const onlineDetector = new CleanMailDetector(undefined, {
    resolveMx: async () => { throw Object.assign(new Error('temporary failure'), { code: 'ESERVFAIL' }); },
  });
  const result = await onlineDetector.checkOnline('person@temporary-dns-failure.test');
  assert.equal(result.blocked, false);
  assert.equal(result.disposable, false);
  assert.equal(result.reason, 'not_listed');
});
