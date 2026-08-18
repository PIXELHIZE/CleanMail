import assert from 'node:assert/strict';
import test from 'node:test';

import { CleanMailAnalyzer, isPublicIp } from '../src/cleanmail/analyzer.js';
import { CleanMailDetector } from '../src/cleanmail/detector.js';

function noData() {
  return Object.assign(new Error('no data'), { code: 'ENODATA' });
}

function fixture(overrides = {}) {
  const resolveMx = overrides.resolveMx || (async () => [{ exchange: 'mail.example.net', priority: 10 }]);
  const resolve4 = overrides.resolve4 || (async (name) => name.startsWith('mail.') ? ['8.8.8.8'] : ['93.184.216.34']);
  const resolve6 = overrides.resolve6 || (async () => { throw noData(); });
  const detector = new CleanMailDetector(undefined, { resolveMx, resolve4, resolve6 });
  const analyzer = new CleanMailAnalyzer(detector, {
    resolveMx,
    resolve4,
    resolve6,
    resolveNs: overrides.resolveNs || (async () => ['ns1.example.net']),
    resolveTxt: overrides.resolveTxt || (async (name) => {
      if (name.startsWith('_dmarc.')) return [['v=DMARC1; p=reject']];
      if (name.startsWith('_mta-sts.')) return [['v=STSv1; id=1']];
      return [['v=spf1 -all']];
    }),
    reverse: overrides.reverse || (async () => ['dns.google']),
    smtpProbe: overrides.smtpProbe,
    fetch: overrides.fetch,
    now: overrides.now,
  });
  return analyzer;
}

test('deep analysis detects subaddressing and role accounts without blocking by default', async () => {
  const result = await fixture().analyze('support+trial@ordinary.test', { rdap: false });
  assert.equal(result.blocked, false);
  assert.equal(result.canonical_email, 'support@ordinary.test');
  assert.equal(result.checks.local_part.subaddressed, true);
  assert.equal(result.checks.local_part.role_based, true);
  assert.equal(result.checks.account_type.classification, 'role');
  assert.ok(result.signals.some((signal) => signal.code === 'subaddress_detected'));
  assert.ok(result.signals.some((signal) => signal.code === 'role_based_address'));
});

test('role accounts can be blocked by explicit policy', async () => {
  const result = await fixture().analyze('admin@ordinary.test', { rdap: false, blockRoleAccounts: true });
  assert.equal(result.blocked, true);
  assert.equal(result.tier, 'policy');
  assert.equal(result.reason, 'role_address_blocked_by_policy');
});

test('combined gibberish, prohibited token, and young domain signals cross the risk threshold', async () => {
  const analyzer = fixture();
  analyzer.lookupRdap = async () => ({ status: 'ok', age_days: 1, registrar: 'Example Registrar' });
  const result = await analyzer.analyze('fuckxqzvbnm948273@fresh-domain.test');
  assert.equal(result.blocked, true);
  assert.equal(result.tier, 'risk');
  assert.equal(result.reason, 'high_risk_score');
  assert.ok(result.risk_score >= 7);
  assert.equal(result.checks.local_part.likely_gibberish, true);
  assert.deepEqual(result.checks.local_part.prohibited_tokens, ['fuck']);
});

test('Null MX is a critical deliverability block', async () => {
  const analyzer = fixture({
    resolveMx: async () => [{ exchange: '', priority: 0 }],
    resolve4: async () => { throw noData(); },
  });
  const result = await analyzer.analyze('person@null-mx.test', { rdap: false });
  assert.equal(result.blocked, true);
  assert.equal(result.tier, 'deliverability');
  assert.ok(['no_mx_records', 'null_mx_domain'].includes(result.reason));
  assert.equal(result.checks.domain.dns.mx_status, 'null_mx');
});

test('SMTP permanent recipient rejection blocks when the optional probe is enabled', async () => {
  const analyzer = fixture({
    smtpProbe: async () => ({ status: 'rejected', response_code: 550, catch_all: null }),
  });
  const result = await analyzer.analyze('missing@ordinary.test', { rdap: false, smtp: true });
  assert.equal(result.blocked, true);
  assert.equal(result.tier, 'smtp');
  assert.equal(result.reason, 'smtp_recipient_rejected');
});

test('known MX infrastructure provider is identified without becoming a risk signal', async () => {
  const result = await fixture({
    resolveMx: async () => [{ exchange: 'gmail-smtp-in.l.google.com', priority: 5 }],
  }).analyze('person@ordinary.test', { rdap: false });
  assert.equal(result.checks.domain.infrastructure.provider, 'Google Workspace');
  assert.equal(result.blocked, false);
});

test('deep domain inspection is cached between addresses on the same domain', async () => {
  let mxLookups = 0;
  const analyzer = fixture({
    resolveMx: async () => {
      mxLookups += 1;
      return [{ exchange: 'mail.example.net', priority: 10 }];
    },
  });
  await analyzer.analyze('first@ordinary.test', { rdap: false });
  await analyzer.analyze('second@ordinary.test', { rdap: false });
  assert.equal(mxLookups, 2);
});

test('RDAP bootstrap supplies domain age and registrar without exposing registrant PII', async () => {
  const fetch = async (url) => ({
    ok: true,
    json: async () => String(url).includes('dns.json')
      ? { services: [[['test'], ['https://rdap.example/']]] }
      : {
          events: [{ eventAction: 'registration', eventDate: '2026-08-01T00:00:00Z' }],
          entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Clean Registrar']]] }],
          status: ['active'],
          secureDNS: { delegationSigned: true },
        },
  });
  const result = await fixture({ fetch, now: () => Date.parse('2026-08-18T00:00:00Z') })
    .analyze('person@young.test');
  assert.equal(result.checks.domain.registration.age_days, 17);
  assert.equal(result.checks.domain.registration.registrar, 'Clean Registrar');
  assert.equal(result.checks.domain.registration.registrant_disclosed, false);
});

test('public IP guard rejects loopback, private, link-local, and documentation ranges', () => {
  assert.equal(isPublicIp('8.8.8.8'), true);
  assert.equal(isPublicIp('127.0.0.1'), false);
  assert.equal(isPublicIp('10.0.0.1'), false);
  assert.equal(isPublicIp('169.254.1.1'), false);
  assert.equal(isPublicIp('203.0.113.7'), false);
  assert.equal(isPublicIp('::1'), false);
  assert.equal(isPublicIp('2001:4860:4860::8888'), true);
});
