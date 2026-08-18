import { normalizeDomain, parseEmail } from './syntax.js';

const NO_MX_ERROR_CODES = new Set(['ENODATA', 'ENOTFOUND', 'ENONAME']);

export function suffixMatch(domain, rules) {
  const labels = domain.split('.');
  for (let index = 0; index < labels.length - 1; index += 1) {
    const candidate = labels.slice(index).join('.');
    if (rules.has(candidate)) return candidate;
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

function asSet(value, name) {
  if (!(value instanceof Set)) throw new TypeError(`${name} must be a Set`);
  return value;
}

export class CleanMailRuntimeDetector {
  constructor(data, options = {}) {
    if (!data || typeof data !== 'object') throw new TypeError('detector data is required');
    this.allowlist = asSet(data.allowlist, 'allowlist');
    this.verified = asSet(data.verified, 'verified');
    this.core = asSet(data.core, 'core');
    this.community = asSet(data.community, 'community');
    this.mxPatterns = asSet(data.mxPatterns, 'mxPatterns');
    this.mxIps = asSet(data.mxIps, 'mxIps');
    this.metadata = data.metadata || {};
    this.resolveMx = options.resolveMx;
    this.resolve4 = options.resolve4;
    this.resolve6 = options.resolve6;
    if (![this.resolveMx, this.resolve4, this.resolve6].every((resolver) => typeof resolver === 'function')) {
      throw new TypeError('resolveMx, resolve4, and resolve6 functions are required');
    }
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
        email: String(email), valid: false, blocked: true, disposable: false,
        domain: null, matched_domain: null, tier: null, reason: 'invalid_email_syntax',
      };
    }

    const allowed = suffixMatch(parsed.domain, this.allowlist);
    if (allowed) {
      return {
        email: parsed.email, valid: true, blocked: false, disposable: false,
        domain: parsed.domain, matched_domain: allowed, tier: 'allowlist', reason: 'known_legitimate_provider',
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
          email: parsed.email, valid: true, blocked: true, disposable: true,
          domain: parsed.domain, matched_domain: matched, tier, reason,
        };
      }
    }

    return {
      email: parsed.email, valid: true, blocked: false, disposable: false,
      domain: parsed.domain, matched_domain: null, tier: null, reason: 'not_listed',
    };
  }

  checkMany(emails) {
    return Array.from(emails, (email) => this.check(email));
  }

  async checkOnline(email) {
    const staticResult = this.check(email);
    if (!staticResult.valid || staticResult.disposable || staticResult.tier === 'allowlist') return staticResult;
    const fingerprint = await this.lookupInfrastructure(staticResult.domain);
    if (!fingerprint) return staticResult;
    if (fingerprint.noMx) {
      return {
        ...staticResult, blocked: true, disposable: false, deliverable: false,
        matched_domain: staticResult.domain, tier: 'deliverability', reason: 'no_mx_records',
      };
    }
    return {
      ...staticResult,
      blocked: true,
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
    if (this.dnsCache.size >= 10_000) this.dnsCache.delete(this.dnsCache.keys().next().value);
    this.dnsCache.set(domain, { expiresAt: now + this.dnsCacheTtlMs, value });
    return value;
  }

  async resolveInfrastructure(domain) {
    let mxRecords;
    try {
      mxRecords = await within(Promise.resolve().then(() => this.resolveMx(domain)), this.dnsTimeoutMs);
    } catch (error) {
      if (NO_MX_ERROR_CODES.has(error?.code)) return { noMx: true };
      return null;
    }
    if (mxRecords === null || !Array.isArray(mxRecords)) return null;
    if (mxRecords.length === 0) return { noMx: true };

    const exchanges = [];
    for (const record of mxRecords.slice(0, 20)) {
      try {
        exchanges.push(normalizeDomain(record?.exchange || ''));
      } catch {
        // Ignore malformed DNS answers and Null MX's empty exchange.
      }
    }
    if (exchanges.length === 0) return { noMx: true };
    for (const exchange of exchanges) {
      const pattern = suffixMatch(exchange, this.mxPatterns);
      if (pattern) return { exchange, pattern };
    }

    const resolutions = exchanges.flatMap((exchange) => [
      Promise.resolve().then(() => this.resolve4(exchange)).then((addresses) => ({ exchange, addresses })),
      Promise.resolve().then(() => this.resolve6(exchange)).then((addresses) => ({ exchange, addresses })),
    ]);
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
    const generatedTotal = this.metadata.counts?.all_blocked;
    return {
      name: 'CleanMail',
      version: this.metadata.dataset_version,
      generated_at: this.metadata.generated_at,
      total_blocked: Number.isInteger(generatedTotal)
        ? generatedTotal
        : new Set([...this.verified, ...this.core, ...this.community]).size,
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
