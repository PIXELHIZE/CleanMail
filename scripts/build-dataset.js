#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { domainToASCII, fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_OUTPUT = path.join(ROOT, 'src', 'cleanmail', 'data');
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const BUILDER_POLICY_VERSION = 6;

const SOURCES = {
  baseline_disposable_email_domains: {
    url: 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf',
    license: 'CC0-1.0',
    local: 'disposable-email-domains/disposable_email_blocklist.conf',
    format: 'lines',
    minDomains: 5_000,
  },
  baseline_groundcat: {
    url: 'https://raw.githubusercontent.com/groundcat/disposable-email-domain-list/master/domains.txt',
    license: 'MIT',
    local: 'groundcat/domains.txt',
    format: 'lines',
    minDomains: 5_000,
  },
  community_disposable: {
    url: 'https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt',
    license: 'MIT',
    local: 'disposable-generated/domains.txt',
    format: 'lines',
    minDomains: 50_000,
  },
  community_fakefilter: {
    url: 'https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt',
    license: 'BSD-3-Clause',
    local: 'fakefilter/txt/data.txt',
    format: 'lines',
    minDomains: 3_000,
  },
  community_burner_email_providers: {
    url: 'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt',
    license: 'MIT',
    local: 'burner-email-providers/emails.txt',
    format: 'lines',
    minDomains: 20_000,
  },
  community_email_check_app: {
    url: 'https://raw.githubusercontent.com/email-check-app/disposable-email-providers/master/disposable-email-providers.json',
    license: 'MIT',
    local: 'email-check-app/disposable-email-providers.json',
    format: 'json',
    minDomains: 100_000,
  },
  community_eramitgupta: {
    url: 'https://raw.githubusercontent.com/eramitgupta/disposable-email/main/disposable_email.txt',
    license: 'MIT',
    local: 'eramitgupta/disposable_email.txt',
    format: 'lines',
    minDomains: 100_000,
  },
};

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function normalizeDomain(value) {
  if (typeof value !== 'string') return null;
  let candidate = value.trim().toLowerCase().replace(/\.$/, '');
  if (candidate.startsWith('*.')) candidate = candidate.slice(2);
  if (!candidate || candidate.startsWith('#') || candidate.includes('@') || candidate.includes('://')) return null;
  candidate = domainToASCII(candidate);
  if (!candidate || candidate.length > 253) return null;
  const labels = candidate.split('.');
  if (labels.length < 2 || labels.some((label) => !LABEL.test(label)) || /^\d+$/.test(labels.at(-1))) return null;
  return candidate;
}

function parseDomains(raw, format) {
  const text = raw.toString('utf8').replace(/^\uFEFF/, '');
  let values;
  if (format === 'json') {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) throw new TypeError('source JSON must be an array');
    values = parsed;
  } else {
    values = text.split(/\r?\n/).map((line) => line.split('#', 1)[0]);
  }
  const domains = new Set();
  for (const value of values) {
    const domain = normalizeDomain(value);
    if (domain) domains.add(domain);
  }
  return domains;
}

async function fetchSource(name, spec, sourceRoot) {
  if (sourceRoot) {
    const filePath = path.join(sourceRoot, ...spec.local.split('/'));
    if (!fs.statSync(filePath, { throwIfNoEntry: false })?.isFile()) {
      throw new Error(`${name}: local source not found: ${filePath}`);
    }
    let revision = null;
    try {
      revision = execFileSync('git', ['-C', path.dirname(filePath), 'rev-parse', 'HEAD'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
    } catch {
      // A source directory does not have to be a Git checkout.
    }
    return { raw: fs.readFileSync(filePath), revision };
  }

  let response;
  try {
    response = await fetch(spec.url, {
      headers: { 'user-agent': 'CleanMail/0.3' },
      signal: AbortSignal.timeout(45_000),
    });
  } catch (error) {
    throw new Error(`${name}: source request failed: ${error.message}`);
  }
  if (!response.ok) throw new Error(`${name}: source returned HTTP ${response.status}`);
  return { raw: Buffer.from(await response.arrayBuffer()), revision: null };
}

function readAllowlist(filePath) {
  return parseDomains(fs.readFileSync(filePath), 'lines');
}

function readIpPatterns(filePath) {
  const values = new Set();
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const candidate = line.split('#', 1)[0].trim();
    if (!candidate) continue;
    if (!net.isIP(candidate)) throw new TypeError(`invalid MX IP fingerprint: ${candidate}`);
    values.add(candidate);
  }
  return values;
}

function readVerified(filePath) {
  const records = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!Array.isArray(records)) throw new TypeError('verified_domains.json must be an array');
  const domains = new Set();
  for (const record of records) {
    const domain = normalizeDomain(record?.domain);
    if (!domain) throw new TypeError(`invalid verified domain: ${record?.domain}`);
    record.domain = domain;
    domains.add(domain);
  }
  return { domains, records };
}

function intersection(left, right) {
  return new Set([...left].filter((value) => right.has(value)));
}

function difference(left, ...others) {
  return new Set([...left].filter((value) => others.every((other) => !other.has(value))));
}

function union(...sets) {
  return new Set(sets.flatMap((set) => [...set]));
}

function coveredBy(domain, rules) {
  const labels = domain.split('.');
  for (let index = 0; index < labels.length - 1; index += 1) {
    const candidate = labels.slice(index).join('.');
    if (rules.has(candidate)) return candidate;
  }
  return null;
}

function atomicText(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const temporary = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(temporary, content, 'utf8');
    fs.renameSync(temporary, filePath);
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function writeDomains(filePath, domains) {
  atomicText(filePath, [...domains].sort().map((domain) => `${domain}\n`).join(''));
}

function parseArguments(argv) {
  const options = { sourceRoot: null, output: DEFAULT_OUTPUT, quorum: 2 };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = argv[index + 1];
    if (!['--source-root', '--output', '--quorum'].includes(arg) || value === undefined) {
      throw new TypeError(`unknown or incomplete argument: ${arg}`);
    }
    if (arg === '--source-root') options.sourceRoot = path.resolve(value);
    if (arg === '--output') options.output = path.resolve(value);
    if (arg === '--quorum') options.quorum = Number(value);
    index += 1;
  }
  if (!Number.isInteger(options.quorum) || options.quorum < 2) {
    throw new TypeError('quorum must be an integer of at least 2');
  }
  return options;
}

function localDateVersion() {
  const now = new Date();
  return [now.getFullYear(), String(now.getMonth() + 1).padStart(2, '0'), String(now.getDate()).padStart(2, '0')].join('.');
}

export async function buildDataset(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const loaded = {};
  const sourceMetadata = {};

  for (const [name, spec] of Object.entries(SOURCES)) {
    const { raw, revision } = await fetchSource(name, spec, options.sourceRoot);
    const domains = parseDomains(raw, spec.format);
    if (domains.size < spec.minDomains) {
      throw new Error(`${name} produced only ${domains.size} valid domains; minimum is ${spec.minDomains}`);
    }
    loaded[name] = domains;
    sourceMetadata[name] = {
      url: spec.url,
      license: spec.license,
      domains: domains.size,
      sha256: sha256(raw),
      revision,
    };
  }

  const allowlistPath = path.join(ROOT, 'config', 'allowlist.txt');
  const verifiedPath = path.join(ROOT, 'config', 'verified_domains.json');
  const mxPatternsPath = path.join(ROOT, 'config', 'disposable_mx_patterns.txt');
  const mxIpsPath = path.join(ROOT, 'config', 'disposable_mx_ips.txt');
  const allowlist = readAllowlist(allowlistPath);
  const { domains: verified, records: verifiedRecords } = readVerified(verifiedPath);
  const mxPatterns = readAllowlist(mxPatternsPath);
  const mxIps = readIpPatterns(mxIpsPath);
  const conflict = intersection(verified, allowlist);
  if (conflict.size) throw new Error(`verified domains conflict with allowlist: ${[...conflict].sort().join(', ')}`);

  const core = difference(
    intersection(loaded.baseline_disposable_email_domains, loaded.baseline_groundcat),
    allowlist,
  );
  const votes = new Map();
  for (const [name, domains] of Object.entries(loaded)) {
    if (!name.startsWith('community_')) continue;
    for (const domain of domains) votes.set(domain, (votes.get(domain) || 0) + 1);
  }
  const communityCandidates = new Set([...votes].filter(([, count]) => count >= options.quorum).map(([domain]) => domain));
  const community = difference(communityCandidates, allowlist, core);
  const allBlocked = union(core, community, verified);

  writeDomains(path.join(options.output, 'allowlist.txt'), allowlist);
  writeDomains(path.join(options.output, 'verified_domains.txt'), verified);
  writeDomains(path.join(options.output, 'core_domains.txt'), core);
  writeDomains(path.join(options.output, 'community_domains.txt'), community);
  writeDomains(path.join(options.output, 'domains.txt'), allBlocked);
  writeDomains(path.join(options.output, 'mx_patterns.txt'), mxPatterns);
  atomicText(path.join(options.output, 'mx_ips.txt'), [...mxIps].sort().map((ip) => `${ip}\n`).join(''));
  atomicText(path.join(options.output, 'verified_evidence.json'), `${JSON.stringify(verifiedRecords, null, 2)}\n`);

  const baselineNames = ['baseline_disposable_email_domains', 'baseline_groundcat'];
  const coverage = Object.fromEntries(baselineNames.map((name) => [name, 0]));
  let unionCoverage = 0;
  let intersectionCoverage = 0;
  const comparisonRows = verifiedRecords.map((record) => {
    const row = { domain: record.domain, service: record.service, region: record.region };
    const matches = baselineNames.map((name) => {
      const matched = coveredBy(record.domain, loaded[name]);
      row[name] = matched;
      coverage[name] += Number(matched !== null);
      return matched !== null;
    });
    unionCoverage += Number(matches.some(Boolean));
    intersectionCoverage += Number(matches.every(Boolean));
    return row;
  });
  coverage.baseline_union = unionCoverage;
  coverage.baseline_intersection = intersectionCoverage;
  coverage.cleanmail = verified.size;
  const comparison = {
    sample: 'domains observed live on disposable-mail services',
    observed_at: verifiedRecords.map((record) => record.observed_at).sort().at(-1),
    sample_size: verified.size,
    coverage,
    rows: comparisonRows,
  };
  atomicText(path.join(options.output, 'baseline_comparison.json'), `${JSON.stringify(comparison, null, 2)}\n`);

  const fingerprintPayload = {
    policy_version: BUILDER_POLICY_VERSION,
    quorum: options.quorum,
    sources: Object.fromEntries(Object.entries(sourceMetadata).map(([name, details]) => [name, details.sha256])),
    allowlist: sha256(fs.readFileSync(allowlistPath)),
    verified: sha256(fs.readFileSync(verifiedPath)),
    mx_patterns: sha256(fs.readFileSync(mxPatternsPath)),
    mx_ips: sha256(fs.readFileSync(mxIpsPath)),
  };
  const inputFingerprint = sha256(Buffer.from(JSON.stringify(fingerprintPayload)));
  let generatedAt = new Date().toISOString();
  let datasetVersion = localDateVersion();
  const previousMetadataPath = path.join(options.output, 'metadata.json');
  try {
    const previous = JSON.parse(fs.readFileSync(previousMetadataPath, 'utf8'));
    if (previous.input_fingerprint === inputFingerprint) {
      generatedAt = previous.generated_at;
      datasetVersion = previous.dataset_version;
    }
  } catch {
    // No previous valid build metadata exists.
  }
  const metadata = {
    name: 'CleanMail',
    dataset_version: datasetVersion,
    generated_at: generatedAt,
    input_fingerprint: inputFingerprint,
    builder_policy_version: BUILDER_POLICY_VERSION,
    policy: {
      core: 'exact intersection of the two baseline repositories',
      community: `present in at least ${options.quorum} external public inputs`,
      verified: 'observed on a live service or confirmed by a supplied usage sample',
      online: 'unknown domains are checked against dedicated disposable MX host and IP fingerprints',
      allowlist: 'always overrides every block tier',
    },
    community_quorum: options.quorum,
    counts: {
      all_blocked: allBlocked.size,
      core: core.size,
      community: community.size,
      verified: verified.size,
      allowlist: allowlist.size,
      mx_patterns: mxPatterns.size,
      mx_ips: mxIps.size,
      verified_already_in_other_tiers: intersection(verified, union(core, community)).size,
    },
    sources: sourceMetadata,
  };
  atomicText(previousMetadataPath, `${JSON.stringify(metadata, null, 2)}\n`);
  console.log(JSON.stringify(metadata.counts, null, 2));
  return metadata;
}

const isEntryPoint = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntryPoint) {
  buildDataset().catch((error) => {
    console.error(error.stack || error.message);
    process.exitCode = 1;
  });
}
