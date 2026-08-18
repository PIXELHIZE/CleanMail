const MAX_BODY_BYTES = 16 * 1024;
const MAX_BATCH_SIZE = 100;

function json(status, payload) {
  const body = JSON.stringify(payload);
  return new Response(body, {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'content-length': String(new TextEncoder().encode(body).byteLength),
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

async function readJson(request) {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    throw Object.assign(new Error('body must be between 1 and 16384 bytes'), { status: 413 });
  }
  if (!request.body) throw Object.assign(new Error('body must be between 1 and 16384 bytes'), { status: 400 });

  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_BODY_BYTES) {
      await reader.cancel('request body too large');
      throw Object.assign(new Error('body must be between 1 and 16384 bytes'), { status: 413 });
    }
    chunks.push(value);
  }
  if (length === 0) throw Object.assign(new Error('body must be between 1 and 16384 bytes'), { status: 400 });
  const merged = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(merged));
  } catch {
    throw Object.assign(new Error('invalid JSON'), { status: 400 });
  }
}

function analyzeOptions(payload) {
  const requested = payload.options && typeof payload.options === 'object' && !Array.isArray(payload.options)
    ? payload.options
    : {};
  if (
    requested.risk_threshold !== undefined
    && (!Number.isFinite(requested.risk_threshold)
      || requested.risk_threshold < 0
      || requested.risk_threshold > 10)
  ) {
    throw Object.assign(new Error('options.risk_threshold must be between 0 and 10'), { status: 400 });
  }
  return {
    rdap: requested.rdap !== false,
    smtp: requested.smtp === true,
    catchAll: requested.catch_all === true,
    blockRoleAccounts: requested.block_role === true,
    blockSubaddresses: requested.block_subaddress === true,
    blockProhibited: requested.block_prohibited === true,
    riskThreshold: requested.risk_threshold,
  };
}

async function inspectPayload(pathname, payload, runtime) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw Object.assign(new Error('JSON object is required'), { status: 400 });
  }
  const deep = pathname === '/v1/analyze';
  const options = deep ? analyzeOptions(payload) : null;
  if (typeof payload.email === 'string') {
    return deep
      ? runtime.analyzer.analyze(payload.email, options)
      : runtime.detector.checkOnline(payload.email);
  }
  if (!Array.isArray(payload.emails) || payload.emails.length < 1 || payload.emails.length > MAX_BATCH_SIZE) {
    throw Object.assign(new Error('emails must contain 1 to 100 strings'), { status: 400 });
  }
  if (payload.emails.some((email) => typeof email !== 'string')) {
    throw Object.assign(new Error('every email must be a string'), { status: 400 });
  }
  const results = deep
    ? await runtime.analyzer.analyzeMany(payload.emails, options)
    : await runtime.detector.checkManyOnline(payload.emails);
  return { results, count: results.length };
}

export function createCleanMailWorker(createRuntime) {
  if (typeof createRuntime !== 'function') throw new TypeError('createRuntime must be a function');
  return {
    async fetch(request, env, ctx) {
      const url = new URL(request.url);
      try {
        if (request.method === 'GET' && url.pathname === '/health') {
          return json(200, { status: 'ok', service: 'CleanMail', runtime: 'cloudflare-workers' });
        }

        const runtime = createRuntime(ctx, env);
        if (request.method === 'GET' && url.pathname === '/v1/stats') return json(200, runtime.detector.stats());
        if (request.method === 'GET' && ['/v1/check', '/v1/analyze'].includes(url.pathname)) {
          const emails = url.searchParams.getAll('email');
          if (emails.length !== 1) return json(400, { error: 'one email query parameter is required' });
          const result = url.pathname === '/v1/analyze'
            ? await runtime.analyzer.analyze(emails[0])
            : await runtime.detector.checkOnline(emails[0]);
          return json(200, result);
        }
        if (request.method !== 'POST' || !['/v1/check', '/v1/analyze'].includes(url.pathname)) {
          return json(404, { error: 'not found' });
        }

        const payload = await readJson(request);
        return json(200, await inspectPayload(url.pathname, payload, runtime));
      } catch (error) {
        const message = error instanceof Error ? error.message : 'internal error';
        const status = Number.isInteger(error?.status) ? error.status : 500;
        if (status >= 500) {
          console.error(JSON.stringify({ message: 'CleanMail Worker request failed', error: message, path: url.pathname }));
        }
        return json(status, { error: status >= 500 ? 'internal error' : message });
      }
    },
  };
}
