import dns from 'node:dns/promises';
import net from 'node:net';

import { parseEmail } from './syntax.js';

const DNS_ABSENT_CODES = new Set(['ENODATA', 'ENOTFOUND', 'ENONAME']);
const ROLE_LOCALS = new Set([
  'abuse', 'admin', 'administrator', 'billing', 'compliance', 'contact', 'hello', 'help',
  'info', 'legal', 'marketing', 'no-reply', 'noreply', 'postmaster', 'privacy', 'sales',
  'security', 'support', 'webmaster',
]);
const CONSUMER_DOMAINS = new Set([
  'aol.com', 'daum.net', 'gmail.com', 'googlemail.com', 'hanmail.net', 'hotmail.com',
  'icloud.com', 'kakao.com', 'live.com', 'mail.com', 'me.com', 'msn.com', 'naver.com',
  'nate.com', 'outlook.com', 'proton.me', 'protonmail.com', 'yahoo.co.jp', 'yahoo.com',
  'yandex.com',
]);
const DEFAULT_PROHIBITED_TOKENS = [
  'asshole', 'bitch', 'fuck', 'porn', 'shit', '씨발', '시발', '병신', '死ね', 'くそ',
];
const COMMON_SECOND_LEVEL_SUFFIXES = new Set([
  'ac.jp', 'ac.kr', 'ac.uk', 'co.jp', 'co.kr', 'co.nz', 'co.uk', 'com.au', 'com.br',
  'com.cn', 'com.hk', 'com.sg', 'com.tw', 'go.jp', 'go.kr', 'gov.uk', 'ne.jp', 'ne.kr',
  'net.au', 'net.cn', 'net.nz', 'or.jp', 'or.kr', 'org.au', 'org.cn', 'org.nz', 'org.uk',
]);
const MX_PROVIDERS = [
  { suffix: 'aspmx.l.google.com', provider: 'Google Workspace' },
  { suffix: 'l.google.com', provider: 'Google Workspace' },
  { suffix: 'googlemail.com', provider: 'Google Workspace' },
  { suffix: 'mail.protection.outlook.com', provider: 'Microsoft 365' },
  { suffix: 'pphosted.com', provider: 'Proofpoint', security: true },
  { suffix: 'mimecast.com', provider: 'Mimecast', security: true },
  { suffix: 'barracudanetworks.com', provider: 'Barracuda', security: true },
  { suffix: 'mx.cloudflare.net', provider: 'Cloudflare Email Routing' },
  { suffix: 'messagingengine.com', provider: 'Fastmail' },
  { suffix: 'zoho.com', provider: 'Zoho Mail' },
  { suffix: 'protonmail.ch', provider: 'Proton Mail' },
  { suffix: 'protonmail.net', provider: 'Proton Mail' },
  { suffix: 'mailgun.org', provider: 'Mailgun' },
  { suffix: 'amazonses.com', provider: 'Amazon SES' },
];

function timeoutValue(promise, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ status: 'timeout', value: [] }), timeoutMs);
    timer.unref?.();
    Promise.resolve(promise).then(
      (value) => {
        clearTimeout(timer);
        resolve({ status: 'ok', value });
      },
      (error) => {
        clearTimeout(timer);
        if (DNS_ABSENT_CODES.has(error?.code)) resolve({ status: 'absent', value: [], code: error.code });
        else resolve({ status: 'error', value: [], code: error?.code || 'DNS_ERROR' });
      },
    );
  });
}

function flattenTxt(records) {
  return Array.isArray(records)
    ? records.map((record) => Array.isArray(record) ? record.join('') : String(record)).filter(Boolean)
    : [];
}

function hostMatches(host, suffix) {
  return host === suffix || host.endsWith(`.${suffix}`);
}

function identifyMxProvider(hosts) {
  for (const entry of MX_PROVIDERS) {
    if (hosts.some((host) => hostMatches(host, entry.suffix))) {
      return {
        provider: entry.provider,
        security_gateway: Boolean(entry.security),
        matched_suffix: entry.suffix,
      };
    }
  }
  return { provider: null, security_gateway: false, matched_suffix: null };
}

function registrableDomain(domain) {
  const labels = domain.split('.');
  if (labels.length <= 2) return domain;
  const lastTwo = labels.slice(-2).join('.');
  return labels.slice(COMMON_SECOND_LEVEL_SUFFIXES.has(lastTwo) ? -3 : -2).join('.');
}

function publicIpv4(address) {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return false;
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

export function isPublicIp(address) {
  const family = net.isIP(address);
  if (family === 4) return publicIpv4(address);
  if (family !== 6) return false;
  const value = address.toLowerCase();
  if (value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd')) return false;
  if (/^fe[89ab]/.test(value) || value.startsWith('ff') || value.startsWith('2001:db8:')) return false;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(value);
  return mapped ? publicIpv4(mapped[1]) : true;
}

function localPartAnalysis(local, prohibitedTokens) {
  const normalized = local.normalize('NFKC').toLowerCase();
  const plus = normalized.indexOf('+');
  const base = plus === -1 ? normalized : normalized.slice(0, plus);
  const tag = plus === -1 ? null : normalized.slice(plus + 1);
  const compact = base.replace(/[^a-z0-9]/g, '');
  const letters = [...compact].filter((character) => /[a-z]/.test(character));
  const digits = [...compact].filter((character) => /\d/.test(character));
  const vowels = letters.filter((character) => /[aeiou]/.test(character)).length;
  const consonantRuns = compact.match(/[bcdfghjklmnpqrstvwxyz]+/g) || [];
  const longestConsonantRun = Math.max(0, ...consonantRuns.map((run) => run.length));
  const uniqueRatio = compact.length ? new Set(compact).size / compact.length : 0;

  let gibberishScore = 0;
  if (compact.length >= 8) {
    if (letters.length >= 5 && vowels / letters.length < 0.15) gibberishScore += 0.3;
    if (longestConsonantRun >= 6) gibberishScore += 0.35;
    if (digits.length / compact.length >= 0.4) gibberishScore += 0.2;
    if (compact.length >= 11 && uniqueRatio >= 0.72) gibberishScore += 0.15;
    if (letters.length > 0 && digits.length > 0 && !/[._-]/.test(base)) gibberishScore += 0.1;
    if (/(?:asdf|qwer|zxcv|1234|abcd){2,}/.test(compact)) gibberishScore += 0.7;
  }
  gibberishScore = Math.min(1, Number(gibberishScore.toFixed(2)));
  const matchedTokens = prohibitedTokens.filter((token) => normalized.includes(token));

  return {
    normalized,
    base,
    tag,
    subaddressed: plus !== -1,
    role_based: ROLE_LOCALS.has(base),
    gibberish_score: gibberishScore,
    likely_gibberish: gibberishScore >= 0.55,
    prohibited_tokens: matchedTokens,
  };
}

function entityName(entity) {
  const properties = entity?.vcardArray?.[1];
  if (!Array.isArray(properties)) return null;
  const name = properties.find((property) => Array.isArray(property) && property[0] === 'fn')?.[3];
  return typeof name === 'string' ? name : null;
}

function parseRdap(domain, payload, now) {
  const events = Array.isArray(payload?.events) ? payload.events : [];
  const registration = events.find((event) => event?.eventAction === 'registration')?.eventDate || null;
  const expiration = events.find((event) => event?.eventAction === 'expiration')?.eventDate || null;
  const created = registration ? new Date(registration) : null;
  const ageDays = created && Number.isFinite(created.getTime())
    ? Math.max(0, Math.floor((now - created.getTime()) / 86_400_000))
    : null;
  const entities = Array.isArray(payload?.entities) ? payload.entities : [];
  const registrar = entities.find((entity) => entity?.roles?.includes('registrar'));
  const registrant = entities.find((entity) => entity?.roles?.includes('registrant'));
  return {
    status: 'ok',
    domain,
    created_at: created && Number.isFinite(created.getTime()) ? created.toISOString() : null,
    expires_at: expiration,
    age_days: ageDays,
    registrar: entityName(registrar),
    registration_statuses: Array.isArray(payload?.status) ? payload.status : [],
    dnssec_signed: payload?.secureDNS?.delegationSigned ?? null,
    registrant_disclosed: Boolean(registrant),
  };
}

function riskLevel(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

export class CleanMailAnalyzer {
  constructor(detector, options = {}) {
    if (!detector || typeof detector.checkOnline !== 'function') {
      throw new TypeError('a CleanMail detector is required');
    }
    this.detector = detector;
    this.resolveMx = options.resolveMx || detector.resolveMx || dns.resolveMx;
    this.resolve4 = options.resolve4 || detector.resolve4 || dns.resolve4;
    this.resolve6 = options.resolve6 || detector.resolve6 || dns.resolve6;
    this.resolveNs = options.resolveNs || dns.resolveNs;
    this.resolveTxt = options.resolveTxt || dns.resolveTxt;
    this.reverse = options.reverse || dns.reverse;
    this.fetch = options.fetch || globalThis.fetch;
    this.smtpProbe = options.smtpProbe || (async () => ({
      status: 'unsupported',
      reason: 'smtp_probe_not_available_in_this_runtime',
      catch_all: null,
    }));
    this.now = options.now || Date.now;
    this.dnsTimeoutMs = options.dnsTimeoutMs ?? 2_500;
    this.rdapTimeoutMs = options.rdapTimeoutMs ?? 3_500;
    this.riskThreshold = options.riskThreshold ?? 7;
    this.prohibitedTokens = (options.prohibitedTokens || DEFAULT_PROHIBITED_TOKENS)
      .map((token) => String(token).normalize('NFKC').toLowerCase());
    this.dnsblZones = options.dnsblZones || [];
    this.domainCacheTtlMs = options.domainCacheTtlMs ?? 60 * 60 * 1_000;
    this.domainCache = new Map();
    this.rdapCache = new Map();
    this.bootstrap = null;
  }

  async dnsQuery(fn) {
    return timeoutValue(Promise.resolve().then(fn), this.dnsTimeoutMs);
  }

  async inspectDomain(domain, { rdap = true } = {}) {
    const key = `${domain}|rdap=${rdap}`;
    const now = this.now();
    const cached = this.domainCache.get(key);
    if (cached && cached.expires_at > now) return cached.value;
    const value = this.resolveDomain(domain, { rdap }).catch((error) => {
      this.domainCache.delete(key);
      throw error;
    });
    if (this.domainCache.size >= 5_000) this.domainCache.delete(this.domainCache.keys().next().value);
    this.domainCache.set(key, { value, expires_at: now + this.domainCacheTtlMs });
    return value;
  }

  async resolveDomain(domain, { rdap = true } = {}) {
    const root = registrableDomain(domain);
    const [mx, ipv4, ipv6, ns, txt, dmarc, mtaSts] = await Promise.all([
      this.dnsQuery(() => this.resolveMx(domain)),
      this.dnsQuery(() => this.resolve4(domain)),
      this.dnsQuery(() => this.resolve6(domain)),
      this.dnsQuery(() => this.resolveNs(domain)),
      this.dnsQuery(() => this.resolveTxt(domain)),
      this.dnsQuery(() => this.resolveTxt(`_dmarc.${domain}`)),
      this.dnsQuery(() => this.resolveTxt(`_mta-sts.${domain}`)),
    ]);

    const mxRecords = (Array.isArray(mx.value) ? mx.value : []).map((record) => ({
      exchange: String(record?.exchange || '').replace(/\.$/, '').toLowerCase(),
      priority: Number(record?.priority) || 0,
    }));
    const nullMx = mxRecords.length === 1 && mxRecords[0].exchange === '' && mxRecords[0].priority === 0;
    const mxHosts = mxRecords.map((record) => record.exchange).filter(Boolean);
    const mxAddressResults = await Promise.all(mxHosts.slice(0, 20).flatMap((host) => [
      this.dnsQuery(() => this.resolve4(host)).then((result) => ({ host, family: 4, ...result })),
      this.dnsQuery(() => this.resolve6(host)).then((result) => ({ host, family: 6, ...result })),
    ]));
    const mxAddresses = [];
    for (const result of mxAddressResults) {
      if (result.status !== 'ok' || !Array.isArray(result.value)) continue;
      for (const address of result.value) {
        if (net.isIP(address)) mxAddresses.push({ host: result.host, address, family: result.family, public: isPublicIp(address) });
      }
    }
    const ptrResults = await Promise.all(mxAddresses.slice(0, 10).map(async (entry) => {
      const result = await this.dnsQuery(() => this.reverse(entry.address));
      return { address: entry.address, names: result.status === 'ok' && Array.isArray(result.value) ? result.value : [] };
    }));
    const rootTxt = flattenTxt(txt.value);
    const dmarcTxt = flattenTxt(dmarc.value);
    const mtaStsTxt = flattenTxt(mtaSts.value);
    const rdapResult = rdap ? await this.lookupRdap(root) : { status: 'disabled' };
    const dnsbl = await this.checkDnsbl(mxAddresses.filter((entry) => entry.family === 4 && entry.public).map((entry) => entry.address));

    return {
      registrable_domain: root,
      is_subdomain: domain !== root,
      dns: {
        active: [mx, ipv4, ipv6, ns].some((result) => result.status === 'ok' && Array.isArray(result.value) && result.value.length > 0),
        mx_status: nullMx ? 'null_mx' : mx.status,
        mx_records: mxRecords,
        a_records: ipv4.status === 'ok' && Array.isArray(ipv4.value) ? ipv4.value : [],
        aaaa_records: ipv6.status === 'ok' && Array.isArray(ipv6.value) ? ipv6.value : [],
        nameservers: ns.status === 'ok' && Array.isArray(ns.value) ? ns.value : [],
        spf: rootTxt.find((record) => /^v=spf1(?:\s|$)/i.test(record)) || null,
        dmarc: dmarcTxt.find((record) => /^v=dmarc1(?:;|\s|$)/i.test(record)) || null,
        mta_sts: mtaStsTxt.find((record) => /^v=stsv1(?:;|\s|$)/i.test(record)) || null,
        transient_error: [mx, ipv4, ipv6, ns].some((result) => ['error', 'timeout'].includes(result.status)),
      },
      infrastructure: {
        ...identifyMxProvider(mxHosts),
        mx_addresses: mxAddresses,
        reverse_dns: ptrResults,
        dns_blocklists: dnsbl,
      },
      registration: rdapResult,
    };
  }

  async fetchJson(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.rdapTimeoutMs);
    timer.unref?.();
    try {
      const response = await this.fetch(url, {
        headers: { accept: 'application/rdap+json, application/json', 'user-agent': 'CleanMail/0.4' },
        signal: controller.signal,
      });
      if (!response.ok) throw Object.assign(new Error(`HTTP ${response.status}`), { status: response.status });
      return await response.json();
    } finally {
      clearTimeout(timer);
    }
  }

  async lookupRdap(domain) {
    const cached = this.rdapCache.get(domain);
    const now = this.now();
    if (cached && cached.expires_at > now) return cached.value;
    let result;
    try {
      if (!this.bootstrap || this.bootstrap.expires_at <= now) {
        this.bootstrap = {
          value: await this.fetchJson('https://data.iana.org/rdap/dns.json'),
          expires_at: now + 24 * 60 * 60 * 1_000,
        };
      }
      const tld = domain.split('.').at(-1);
      const service = this.bootstrap.value?.services?.find(([tlds]) => Array.isArray(tlds) && tlds.includes(tld));
      const bases = service?.[1];
      const base = Array.isArray(bases) ? bases.find((value) => typeof value === 'string' && value.startsWith('https://')) : null;
      if (!base) result = { status: 'unsupported' };
      else {
        const url = new URL(`domain/${encodeURIComponent(domain)}`, base.endsWith('/') ? base : `${base}/`);
        result = parseRdap(domain, await this.fetchJson(url), now);
      }
    } catch (error) {
      result = { status: error?.name === 'AbortError' ? 'timeout' : 'unavailable', reason: error?.status || error?.code || error?.message };
    }
    this.rdapCache.set(domain, { value: result, expires_at: now + 6 * 60 * 60 * 1_000 });
    return result;
  }

  async checkDnsbl(addresses) {
    if (this.dnsblZones.length === 0) return { status: 'disabled', listed: [] };
    const listed = [];
    for (const address of [...new Set(addresses)].slice(0, 10)) {
      const reversed = address.split('.').reverse().join('.');
      for (const zone of this.dnsblZones.slice(0, 5)) {
        const result = await this.dnsQuery(() => this.resolve4(`${reversed}.${zone}`));
        if (result.status === 'ok' && Array.isArray(result.value) && result.value.length > 0) listed.push({ address, zone });
      }
    }
    return { status: 'ok', listed };
  }

  async analyze(email, options = {}) {
    let parsed;
    try {
      parsed = parseEmail(email);
    } catch {
      return {
        ...this.detector.check(email),
        risk_score: 10,
        risk_level: 'critical',
        canonical_email: null,
        signals: [{ code: 'invalid_email_syntax', severity: 'critical', weight: 10 }],
        checks: { syntax: { valid: false } },
      };
    }

    const local = localPartAnalysis(parsed.local, this.prohibitedTokens);
    const canonicalEmail = `${local.base}@${parsed.domain}`;
    const [base, domain] = await Promise.all([
      this.detector.checkOnline(parsed.email),
      this.inspectDomain(parsed.domain, { rdap: options.rdap !== false }),
    ]);
    const signals = [];
    let score = 0;
    let forcedReason = null;
    let forcedTier = null;
    const add = (code, severity, weight, details) => {
      signals.push({ code, severity, weight, ...(details === undefined ? {} : { details }) });
      score += weight;
    };
    const forceBlock = (code, tier, details) => {
      if (!forcedReason) {
        forcedReason = code;
        forcedTier = tier;
      }
      if (signals.some((signal) => signal.code === code && signal.severity === 'critical')) return;
      add(code, 'critical', 10, details);
    };

    if (base.blocked) forceBlock(base.reason, base.tier || 'policy');
    if (local.subaddressed) add('subaddress_detected', 'info', 0.5, { tag: local.tag });
    if (local.role_based) add('role_based_address', 'low', 0.5, { local: local.base });
    if (local.likely_gibberish) add('likely_gibberish_local_part', 'medium', 2.5, { score: local.gibberish_score });
    if (local.prohibited_tokens.length > 0) add('prohibited_local_part_token', 'medium', 3, { matches: local.prohibited_tokens });
    if (options.blockSubaddresses && local.subaddressed) forceBlock('subaddress_blocked_by_policy', 'policy');
    if (options.blockRoleAccounts && local.role_based) forceBlock('role_address_blocked_by_policy', 'policy');
    if (options.blockProhibited && local.prohibited_tokens.length > 0) forceBlock('prohibited_token_blocked_by_policy', 'policy');

    if (domain.dns.mx_status === 'null_mx') forceBlock('null_mx_domain', 'deliverability');
    else if (domain.dns.mx_status === 'absent' || (domain.dns.mx_status === 'ok' && domain.dns.mx_records.length === 0)) {
      forceBlock('no_mx_records', 'deliverability');
    }
    if (!domain.dns.active && !domain.dns.transient_error) forceBlock('inactive_domain', 'deliverability');
    if (!domain.dns.spf) add('spf_not_published', 'info', 0.25);
    if (!domain.dns.dmarc) add('dmarc_not_published', 'info', 0.25);
    if (!domain.dns.mta_sts) add('mta_sts_not_published', 'info', 0);
    if (domain.is_subdomain) add('email_uses_subdomain', 'info', 0, { registrable_domain: domain.registrable_domain });
    if (domain.infrastructure.security_gateway) add('strict_mail_security_gateway', 'info', 0, { provider: domain.infrastructure.provider });
    if (domain.infrastructure.mx_addresses.some((entry) => !entry.public)) add('non_public_mx_address', 'high', 4);
    if (domain.infrastructure.dns_blocklists.listed.length > 0) {
      forceBlock('mx_ip_on_configured_blocklist', 'reputation', domain.infrastructure.dns_blocklists.listed);
    }

    const age = domain.registration?.age_days;
    if (Number.isFinite(age)) {
      if (age < 7) add('domain_younger_than_7_days', 'high', 3, { age_days: age });
      else if (age < 30) add('domain_younger_than_30_days', 'medium', 2, { age_days: age });
      else if (age < 90) add('domain_younger_than_90_days', 'medium', 1.5, { age_days: age });
      else if (age < 180) add('domain_younger_than_180_days', 'low', 0.5, { age_days: age });
    }

    let smtp = { status: 'disabled', catch_all: null };
    if (options.smtp === true && !forcedReason) {
      const smtpMx = domain.dns.mx_records.flatMap((record) => domain.infrastructure.mx_addresses
        .filter((entry) => entry.host === record.exchange && entry.public)
        .map((entry) => ({ ...record, address: entry.address })));
      smtp = await this.smtpProbe({
        email: parsed.email,
        mxRecords: smtpMx,
        timeoutMs: options.smtpTimeoutMs,
        port: options.smtpPort,
        catchAll: options.catchAll === true,
      });
      if (smtp.status === 'rejected') forceBlock('smtp_recipient_rejected', 'smtp', { code: smtp.response_code });
      else if (smtp.status === 'rejected_or_protected') add('smtp_recipient_rejected_or_protected', 'medium', 2, { code: smtp.response_code });
      else if (smtp.status === 'greylisted') add('smtp_greylisted_recheck_required', 'info', 0, { code: smtp.response_code });
      else if (smtp.catch_all === true) add('catch_all_mail_server', 'low', 0.75);
    }

    score = Math.min(10, Number(score.toFixed(2)));
    const riskBlocked = score >= (options.riskThreshold ?? this.riskThreshold);
    const blocked = Boolean(forcedReason || riskBlocked);
    const reason = forcedReason || (riskBlocked ? 'high_risk_score' : base.reason);
    const tier = forcedTier || (riskBlocked ? 'risk' : base.tier);
    const accountType = local.role_based
      ? 'role'
      : CONSUMER_DOMAINS.has(domain.registrable_domain) ? 'consumer_provider' : 'custom_or_business_domain';

    return {
      ...base,
      blocked,
      tier,
      reason,
      risk_score: score,
      risk_level: riskLevel(score),
      canonical_email: canonicalEmail,
      signals,
      checks: {
        syntax: { valid: true, practical_dot_atom: true },
        local_part: local,
        account_type: { classification: accountType, credit_assessment: 'not_performed' },
        domain,
        smtp,
      },
    };
  }

  async analyzeMany(emails, options = {}) {
    const values = Array.from(emails);
    const results = new Array(values.length);
    let next = 0;
    const workers = Array.from({ length: Math.min(options.concurrency ?? 5, values.length) }, async () => {
      while (next < values.length) {
        const index = next;
        next += 1;
        results[index] = await this.analyze(values[index], options);
      }
    });
    await Promise.all(workers);
    return results;
  }
}
