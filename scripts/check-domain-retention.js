#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RELATIVE_FILES = [
  'src/cleanmail/data/core_domains.txt',
  'src/cleanmail/data/community_domains.txt',
  'src/cleanmail/data/domains.txt',
];

function parseDomains(value) {
  return new Set(value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean));
}

const allowlist = parseDomains(fs.readFileSync(path.join(ROOT, 'src', 'cleanmail', 'data', 'allowlist.txt'), 'utf8'));
const violations = [];
let previousTotal = 0;

for (const relativePath of RELATIVE_FILES) {
  const previous = parseDomains(execFileSync('git', ['show', `HEAD:${relativePath}`], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  }));
  const current = parseDomains(fs.readFileSync(path.join(ROOT, relativePath), 'utf8'));
  const removed = [...previous].filter((domain) => !current.has(domain) && !allowlist.has(domain)).sort();
  previousTotal += previous.size;
  if (removed.length) violations.push(`${relativePath}:\n${removed.join('\n')}`);
}

if (violations.length) {
  throw new Error(`append-only policy violation; blocked domains removed:\n${violations.join('\n\n')}`);
}

console.log(`Append-only check passed: ${previousTotal} previous tier entries remain present.`);
