#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createCleanMailServer } from './api.js';
import { CleanMailDetector } from './detector.js';

function usage() {
  console.error(`Usage:
  cleanmail [--data-dir PATH] check [--json] [--offline] EMAIL...
  cleanmail [--data-dir PATH] stats [--json]
  cleanmail [--data-dir PATH] serve [--host HOST] [--port PORT]`);
}

function takeOption(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  if (index === args.length - 1) throw new TypeError(`${name} requires a value`);
  const [value] = args.splice(index + 1, 1);
  args.splice(index, 1);
  return value;
}

export async function main(argv = process.argv.slice(2)) {
  const args = [...argv];
  let dataDir;
  try {
    dataDir = takeOption(args, '--data-dir');
  } catch (error) {
    console.error(error.message);
    return 2;
  }
  const command = args.shift();
  if (!command || command === '--help' || command === '-h') {
    usage();
    return command ? 0 : 2;
  }

  const detector = new CleanMailDetector(dataDir);
  if (command === 'check') {
    const asJson = args.includes('--json');
    const offline = args.includes('--offline');
    const emails = args.filter((arg) => arg !== '--json' && arg !== '--offline');
    if (emails.length === 0) {
      usage();
      return 2;
    }
    const results = offline ? detector.checkMany(emails) : await detector.checkManyOnline(emails);
    if (asJson) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      for (const result of results) {
        const verdict = result.disposable ? 'BLOCK' : result.valid ? 'ALLOW' : 'INVALID';
        console.log(`${verdict.padEnd(7)} ${result.email} (${result.tier || result.reason})`);
      }
    }
    return results.some((result) => result.disposable || !result.valid) ? 1 : 0;
  }

  if (command === 'stats') {
    const stats = detector.stats();
    if (args.includes('--json')) {
      console.log(JSON.stringify(stats, null, 2));
    } else {
      for (const [key, value] of Object.entries(stats)) console.log(`${key}: ${value}`);
    }
    return 0;
  }

  if (command === 'serve') {
    let host;
    let rawPort;
    try {
      host = takeOption(args, '--host', '127.0.0.1');
      rawPort = takeOption(args, '--port', '8080');
    } catch (error) {
      console.error(error.message);
      return 2;
    }
    const port = Number(rawPort);
    if (!Number.isInteger(port) || port < 0 || port > 65535 || args.length > 0) {
      usage();
      return 2;
    }
    const server = createCleanMailServer(detector);
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, resolve);
    });
    const address = server.address();
    console.log(`CleanMail listening on http://${host}:${address.port}`);
    const stop = () => server.close(() => { process.exitCode = 0; });
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    return 0;
  }

  usage();
  return 2;
}

const isEntryPoint = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntryPoint) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    console.error(error.stack || error.message);
    process.exitCode = 1;
  });
}
