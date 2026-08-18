import { domainToASCII } from 'node:url';

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function normalizeDomain(value) {
  if (typeof value !== 'string') throw new TypeError('domain must be a string');
  const raw = value.trim().replace(/\.$/, '');
  if (!raw || raw.includes('@') || raw.includes('://')) throw new TypeError('invalid domain');
  const domain = domainToASCII(raw).toLowerCase();
  if (!domain || domain.length < 3 || domain.length > 253) throw new TypeError('invalid domain length');
  const labels = domain.split('.');
  if (labels.length < 2 || labels.some((label) => !LABEL.test(label))) throw new TypeError('invalid domain labels');
  if (/^\d+$/.test(labels.at(-1))) throw new TypeError('numeric top-level domain');
  return domain;
}

export function parseEmail(value) {
  if (typeof value !== 'string') throw new TypeError('email must be a string');
  const email = value.trim();
  if (email.length > 254 || email.split('@').length !== 2) throw new TypeError('email must contain one @');
  const [local, rawDomain] = email.split('@');
  if (
    !local
    || Buffer.byteLength(local, 'utf8') > 64
    || /[\x00-\x20\x7f]/.test(local)
    || local.startsWith('.')
    || local.endsWith('.')
    || local.includes('..')
    || /[()<>\[\]:;,\\\"]/.test(local)
  ) {
    throw new TypeError('invalid local part');
  }
  return { email, local, domain: normalizeDomain(rawDomain) };
}
