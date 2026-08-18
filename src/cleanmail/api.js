import http from 'node:http';

import { CleanMailAnalyzer } from './node-analyzer.js';
import { CleanMailDetector } from './detector.js';

const MAX_BODY_BYTES = 16 * 1024;
const MAX_BATCH_SIZE = 100;

function sendJson(response, status, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  response.end(body);
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let tooLarge = false;
    request.on('data', (chunk) => {
      length += chunk.length;
      if (length > MAX_BODY_BYTES) {
        tooLarge = true;
      } else {
        chunks.push(chunk);
      }
    });
    request.on('end', () => {
      if (tooLarge) {
        reject(Object.assign(new Error('body must be between 1 and 16384 bytes'), { status: 413 }));
        return;
      }
      if (length === 0) {
        reject(Object.assign(new Error('body must be between 1 and 16384 bytes'), { status: 400 }));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('invalid JSON'), { status: 400 }));
      }
    });
    request.on('error', reject);
  });
}

export function createCleanMailServer(detector = new CleanMailDetector(), analyzer = new CleanMailAnalyzer(detector)) {
  return http.createServer(async (request, response) => {
    const url = new URL(request.url || '/', 'http://localhost');

    if (request.method === 'GET' && url.pathname === '/health') {
      sendJson(response, 200, { status: 'ok', service: 'CleanMail' });
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/stats') {
      sendJson(response, 200, detector.stats());
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/check') {
      const emails = url.searchParams.getAll('email');
      if (emails.length !== 1) {
        sendJson(response, 400, { error: 'one email query parameter is required' });
        return;
      }
      sendJson(response, 200, await detector.checkOnline(emails[0]));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/analyze') {
      const emails = url.searchParams.getAll('email');
      if (emails.length !== 1) {
        sendJson(response, 400, { error: 'one email query parameter is required' });
        return;
      }
      sendJson(response, 200, await analyzer.analyze(emails[0]));
      return;
    }
    if (request.method !== 'POST' || !['/v1/check', '/v1/analyze'].includes(url.pathname)) {
      sendJson(response, 404, { error: 'not found' });
      return;
    }

    const declaredLength = Number(request.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
      sendJson(response, 413, { error: 'body must be between 1 and 16384 bytes' });
      request.resume();
      return;
    }

    let payload;
    try {
      payload = await readJson(request);
    } catch (error) {
      sendJson(response, error.status || 400, { error: error.message || 'invalid request' });
      return;
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      sendJson(response, 400, { error: 'JSON object is required' });
      return;
    }
    const deep = url.pathname === '/v1/analyze';
    const requestedOptions = payload.options && typeof payload.options === 'object' && !Array.isArray(payload.options)
      ? payload.options
      : {};
    if (
      url.pathname === '/v1/analyze'
      && requestedOptions.risk_threshold !== undefined
      && (!Number.isFinite(requestedOptions.risk_threshold)
        || requestedOptions.risk_threshold < 0
        || requestedOptions.risk_threshold > 10)
    ) {
      sendJson(response, 400, { error: 'options.risk_threshold must be between 0 and 10' });
      return;
    }
    const analyzeOptions = deep ? {
      rdap: requestedOptions.rdap !== false,
      smtp: process.env.CLEANMAIL_ENABLE_SMTP === 'true' && requestedOptions.smtp === true,
      catchAll: process.env.CLEANMAIL_ENABLE_SMTP === 'true' && requestedOptions.catch_all === true,
      blockRoleAccounts: requestedOptions.block_role === true,
      blockSubaddresses: requestedOptions.block_subaddress === true,
      blockProhibited: requestedOptions.block_prohibited === true,
      riskThreshold: Number.isFinite(requestedOptions.risk_threshold) ? requestedOptions.risk_threshold : undefined,
    } : null;
    if (typeof payload.email === 'string') {
      sendJson(response, 200, deep
        ? await analyzer.analyze(payload.email, analyzeOptions)
        : await detector.checkOnline(payload.email));
      return;
    }
    if (!Array.isArray(payload.emails) || payload.emails.length < 1 || payload.emails.length > MAX_BATCH_SIZE) {
      sendJson(response, 400, { error: 'emails must contain 1 to 100 strings' });
      return;
    }
    if (payload.emails.some((email) => typeof email !== 'string')) {
      sendJson(response, 400, { error: 'every email must be a string' });
      return;
    }
    const results = deep
      ? await analyzer.analyzeMany(payload.emails, analyzeOptions)
      : await detector.checkManyOnline(payload.emails);
    sendJson(response, 200, { results, count: results.length });
  });
}
