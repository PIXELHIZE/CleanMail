import dns from 'node:dns/promises';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, domainToASCII } from 'node:url';

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DEFAULT_DATA_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');

export function normalizeDomain(value) {
  if (typeof value !== 'string') {
    throw new TypeError('domain must be a string');
  }
  const raw = value.trim().replace(/\.$/, '');
  if (!raw || raw.includes('@') || raw.includes('://')) {
    throw new TypeError('invalid domain');
  }
  const domain = domainToASCII(raw).toLowerCase();
  if (!domain || domain.length < 3 || domain.length > 253) {
    throw new TypeError('invalid domain length');
  }
  const labels = domain.split('.');
  if (labels.length < 2 || labels.some((label) => !LABEL.test(label))) {
    throw new TypeError('invalid domain labels');
  }
  if (/^\d+$/.test(labels.at(-1))) {
    throw new TypeError('numeric top-level domain');
  }
  return domain;
}

export function parseEmail(value) {
  if (typeof value !== 'string') {
    throw new TypeError('email must be a string');
  }
  const email = value.trim();
  if (email.length > 254 || email.split('@').length !== 2) {
    throw new TypeError('email must contain one @');
  }
  const [local, rawDomain] = email.split('@');
  if (!local || Buffer.byteLength(local, 'utf8') > 64 || /[\x00-\x20\x7f]/.test(local)) {
    throw new TypeError('invalid local part');
  }
  return { email, domain: normalizeDomain(rawDomain) };
}

function readDomains(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`CleanMail data file is missing: ${filePath}`);
  }
  const domains = new Set();
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const candidate = line.split('#', 1)[0].trim();
    if (candidate) {
      domains.add(normalizeDomain(candidate));
    }
  }
  return domains;
}

function readIpAddresses(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`CleanMail data file is missing: ${filePath}`);
  }
  const addresses = new Set();
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const candidate = line.split('#', 1)[0].trim();
    if (!candidate) continue;
    if (!net.isIP(candidate)) throw new TypeError(`invalid MX IP fingerprint: ${candidate}`);
    addresses.add(candidate);
  }
  return addresses;
}

function suffixMatch(domain, rules) {
  const labels = domain.split('.');
  for (let index = 0; index < labels.length - 1; index += 1) {
    const candidate = labels.slice(index).join('.');
    if (rules.has(candidate)) {
      return candidate;
    }
  }
  return null;
}

async function within(promise, timeoutMs) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export class CleanMailDetector {
  constructor(dataDir = process.env.CLEANMAIL_DATA_DIR || DEFAULT_DATA_DIR, options = {}) {
    if (dataDir && typeof dataDir === 'object') {
      options = dataDir;
      dataDir = process.env.CLEANMAIL_DATA_DIR || DEFAULT_DATA_DIR;
    }
    this.dataDir = path.resolve(dataDir);
    this.allowlist = readDomains(path.join(this.dataDir, 'allowlist.txt'));
    this.verified = readDomains(path.join(this.dataDir, 'verified_domains.txt'));
    this.core = readDomains(path.join(this.dataDir, 'core_domains.txt'));
    this.community = readDomains(path.join(this.dataDir, 'community_domains.txt'));
    this.mxPatterns = readDomains(path.join(this.dataDir, 'mx_patterns.txt'));
    this.mxIps = readIpAddresses(path.join(this.dataDir, 'mx_ips.txt'));
    this.metadata = JSON.parse(fs.readFileSync(path.join(this.dataDir, 'metadata.json'), 'utf8'));
    this.resolveMx = options.resolveMx || dns.resolveMx;
    this.resolve4 = options.resolve4 || dns.resolve4;
    this.resolve6 = options.resolve6 || dns.resolve6;
    this.dnsTimeoutMs = options.dnsTimeoutMs ?? 2_500;
    this.dnsCacheTtlMs = options.dnsCacheTtlMs ?? 6 * 60 * 60 * 1_000;
    this.dnsCache = new Map();
  }

  check(email) {
    let parsed;
    try {
      parsed = parseEmail(email);
    } catch {
      return {
        email: String(email),
        valid: false,
        disposable: false,
        domain: null,
        matched_domain: null,
        tier: null,
        reason: 'invalid_email_syntax',
      };
    }

    const allowed = suffixMatch(parsed.domain, this.allowlist);
    if (allowed) {
      return {
        email: parsed.email,
        valid: true,
        disposable: false,
        domain: parsed.domain,
        matched_domain: allowed,
        tier: 'allowlist',
        reason: 'known_legitimate_provider',
      };
    }

    const tiers = [
      ['verified', this.verified, 'confirmed_disposable_domain'],
      ['core', this.core, 'present_in_both_baseline_lists'],
      ['community', this.community, 'confirmed_by_multiple_external_lists'],
    ];
    for (const [tier, rules, reason] of tiers) {
      const matched = suffixMatch(parsed.domain, rules);
      if (matched) {
        return {
          email: parsed.email,
          valid: true,
          disposable: true,
          domain: parsed.domain,
          matched_domain: matched,
          tier,
          reason,
        };
      }
    }

    return {
      email: parsed.email,
      valid: true,
      disposable: false,
      domain: parsed.domain,
      matched_domain: null,
      tier: null,
      reason: 'not_listed',
    };
  }

  checkMany(emails) {
    return Array.from(emails, (email) => this.check(email));
  }

  async checkOnline(email) {
    const staticResult = this.check(email);
    if (!staticResult.valid || staticResult.disposable || staticResult.tier === 'allowlist') {
      return staticResult;
    }

    const fingerprint = await this.lookupInfrastructure(staticResult.domain);
    if (!fingerprint) return staticResult;
    return {
      ...staticResult,
      disposable: true,
      matched_domain: staticResult.domain,
      tier: 'mx',
      reason: 'disposable_mail_infrastructure',
      matched_mx: fingerprint.exchange,
      ...(fingerprint.pattern ? { matched_mx_pattern: fingerprint.pattern } : {}),
      ...(fingerprint.ip ? { matched_mx_ip: fingerprint.ip } : {}),
    };
  }

  async checkManyOnline(emails) {
    return Promise.all(Array.from(emails, (email) => this.checkOnline(email)));
  }

  async lookupInfrastructure(domain) {
    const now = Date.now();
    const cached = this.dnsCache.get(domain);
    if (cached && cached.expiresAt > now) return cached.value;

    const value = this.resolveInfrastructure(domain).catch(() => null);
    if (this.dnsCache.size >= 10_000) {
      this.dnsCache.delete(this.dnsCache.keys().next().value);
    }
    this.dnsCache.set(domain, { expiresAt: now + this.dnsCacheTtlMs, value });
    return value;
  }

  async resolveInfrastructure(domain) {
    const mxRecords = await within(Promise.resolve().then(() => this.resolveMx(domain)), this.dnsTimeoutMs);
    if (!Array.isArray(mxRecords) || mxRecords.length === 0) return null;

    const exchanges = [];
    for (const record of mxRecords.slice(0, 20)) {
      try {
        exchanges.push(normalizeDomain(record?.exchange || ''));
      } catch {
        // Ignore malformed DNS answers.
      }
    }
    for (const exchange of exchanges) {
      const pattern = suffixMatch(exchange, this.mxPatterns);
      if (pattern) return { exchange, pattern };
    }

    const resolutions = exchanges.flatMap((exchange) => [
      Promise.resolve().then(() => this.resolve4(exchange)).then((addresses) => ({ exchange, addresses })),
      Promise.resolve().then(() => this.resolve6(exchange)).then((addresses) => ({ exchange, addresses })),
    ]);
    if (resolutions.length === 0) return null;
    const settled = await within(Promise.allSettled(resolutions), this.dnsTimeoutMs);
    if (!settled) return null;
    for (const result of settled) {
      if (result.status !== 'fulfilled' || !Array.isArray(result.value.addresses)) continue;
      for (const ip of result.value.addresses) {
        if (this.mxIps.has(ip)) return { exchange: result.value.exchange, ip };
      }
    }
    return null;
  }

  stats() {
    const allBlocked = new Set([...this.verified, ...this.core, ...this.community]);
    return {
      name: 'CleanMail',
      version: this.metadata.dataset_version,
      generated_at: this.metadata.generated_at,
      total_blocked: allBlocked.size,
      verified: this.verified.size,
      core: this.core.size,
      community: this.community.size,
      allowlist: this.allowlist.size,
      mx_patterns: this.mxPatterns.size,
      mx_ips: this.mxIps.size,
      community_quorum: this.metadata.community_quorum,
    };
  }
}
