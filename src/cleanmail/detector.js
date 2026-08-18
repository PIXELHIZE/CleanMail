import dns from 'node:dns/promises';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { CleanMailRuntimeDetector } from './runtime-detector.js';
import { normalizeDomain, parseEmail } from './syntax.js';

const DEFAULT_DATA_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');

function readDomains(filePath) {
  if (!fs.existsSync(filePath)) throw new Error(`CleanMail data file is missing: ${filePath}`);
  const domains = new Set();
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const candidate = line.split('#', 1)[0].trim();
    if (candidate) domains.add(normalizeDomain(candidate));
  }
  return domains;
}

function readIpAddresses(filePath) {
  if (!fs.existsSync(filePath)) throw new Error(`CleanMail data file is missing: ${filePath}`);
  const addresses = new Set();
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const candidate = line.split('#', 1)[0].trim();
    if (!candidate) continue;
    if (!net.isIP(candidate)) throw new TypeError(`invalid MX IP fingerprint: ${candidate}`);
    addresses.add(candidate);
  }
  return addresses;
}

export class CleanMailDetector extends CleanMailRuntimeDetector {
  constructor(dataDir = process.env.CLEANMAIL_DATA_DIR || DEFAULT_DATA_DIR, options = {}) {
    if (dataDir && typeof dataDir === 'object') {
      options = dataDir;
      dataDir = process.env.CLEANMAIL_DATA_DIR || DEFAULT_DATA_DIR;
    }
    const resolvedDataDir = path.resolve(dataDir);
    super({
      allowlist: readDomains(path.join(resolvedDataDir, 'allowlist.txt')),
      verified: readDomains(path.join(resolvedDataDir, 'verified_domains.txt')),
      core: readDomains(path.join(resolvedDataDir, 'core_domains.txt')),
      community: readDomains(path.join(resolvedDataDir, 'community_domains.txt')),
      mxPatterns: readDomains(path.join(resolvedDataDir, 'mx_patterns.txt')),
      mxIps: readIpAddresses(path.join(resolvedDataDir, 'mx_ips.txt')),
      metadata: JSON.parse(fs.readFileSync(path.join(resolvedDataDir, 'metadata.json'), 'utf8')),
    }, {
      ...options,
      resolveMx: options.resolveMx || dns.resolveMx,
      resolve4: options.resolve4 || dns.resolve4,
      resolve6: options.resolve6 || dns.resolve6,
    });
    this.dataDir = resolvedDataDir;
  }
}

export { CleanMailRuntimeDetector, normalizeDomain, parseEmail };
