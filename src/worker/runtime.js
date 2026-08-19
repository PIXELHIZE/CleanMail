import dns from 'node:dns/promises';

import { CleanMailAnalyzer } from '../cleanmail/analyzer.js';
import { CleanMailRuntimeDetector } from '../cleanmail/runtime-detector.js';
import { WORKER_DATA } from './data.js';
import {
  createCachedDnsResolvers,
  createCachedRdapFetch,
  openInfrastructureCache,
} from './infrastructure-cache.js';

function smtpUnsupported() {
  return Promise.resolve({
    status: 'unsupported',
    reason: 'smtp_port_25_unavailable_on_cloudflare_workers',
    catch_all: null,
  });
}

export function createWorkerRuntime(ctx) {
  const cache = openInfrastructureCache();
  const resolvers = createCachedDnsResolvers(ctx, dns, { cache });
  const detector = new CleanMailRuntimeDetector(WORKER_DATA, {
    resolveMx: resolvers.resolveMx,
    resolve4: resolvers.resolve4,
    resolve6: resolvers.resolve6,
  });
  const analyzer = new CleanMailAnalyzer(detector, {
    ...resolvers,
    fetch: createCachedRdapFetch(ctx, { cache }),
    smtpProbe: smtpUnsupported,
  });
  return { detector, analyzer };
}
