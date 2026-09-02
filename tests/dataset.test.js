import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const DATA = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cleanmail', 'data');

function readDomains(name) {
  return fs.readFileSync(path.join(DATA, name), 'utf8').trim().split(/\r?\n/);
}

test('domain files are sorted and unique', () => {
  for (const name of ['allowlist.txt', 'verified_domains.txt', 'core_domains.txt', 'community_domains.txt', 'domains.txt', 'mx_patterns.txt', 'mx_ips.txt']) {
    const values = readDomains(name);
    assert.deepEqual(values, [...new Set(values)].sort(), name);
  }
});

test('final file is the tier union', () => {
  const verified = new Set(readDomains('verified_domains.txt'));
  const core = new Set(readDomains('core_domains.txt'));
  const community = new Set(readDomains('community_domains.txt'));
  const final = new Set(readDomains('domains.txt'));
  const allowlist = new Set(readDomains('allowlist.txt'));
  assert.deepEqual(final, new Set([...verified, ...core, ...community]));
  assert.equal([...final].some((domain) => allowlist.has(domain)), false);
  assert.equal([...core].some((domain) => community.has(domain)), false);
});

test('metadata counts match files', () => {
  const metadata = JSON.parse(fs.readFileSync(path.join(DATA, 'metadata.json'), 'utf8'));
  assert.equal(metadata.counts.all_blocked, readDomains('domains.txt').length);
  assert.equal(metadata.counts.core, readDomains('core_domains.txt').length);
  assert.equal(metadata.counts.community, readDomains('community_domains.txt').length);
  assert.equal(metadata.counts.verified, readDomains('verified_domains.txt').length);
  assert.equal(metadata.counts.mx_patterns, readDomains('mx_patterns.txt').length);
  assert.equal(metadata.counts.mx_ips, readDomains('mx_ips.txt').length);
  assert.equal(metadata.builder_policy_version, 8);
  assert.equal(Object.keys(metadata.sources).filter((name) => name.startsWith('community_')).length, 15);
  assert.ok(Object.values(metadata.sources).every((source) => source.url && source.license && source.sha256));
});

test('live comparison covers every verified domain', () => {
  const verified = new Set(readDomains('verified_domains.txt'));
  const comparison = JSON.parse(fs.readFileSync(path.join(DATA, 'baseline_comparison.json'), 'utf8'));
  assert.equal(comparison.sample_size, verified.size);
  assert.deepEqual(new Set(comparison.rows.map((row) => row.domain)), verified);
  const coverage = comparison.coverage;
  assert.equal(coverage.cleanmail, verified.size);
  assert.ok(coverage.baseline_union >= coverage.baseline_disposable_email_domains);
  assert.ok(coverage.baseline_union >= coverage.baseline_groundcat);
  assert.ok(coverage.baseline_intersection <= coverage.baseline_disposable_email_domains);
  assert.ok(coverage.baseline_intersection <= coverage.baseline_groundcat);
});
