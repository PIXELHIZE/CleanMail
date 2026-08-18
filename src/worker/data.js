import allowlistText from '../cleanmail/data/allowlist.txt';
import communityText from '../cleanmail/data/community_domains.txt';
import coreText from '../cleanmail/data/core_domains.txt';
import metadata from '../cleanmail/data/metadata.json';
import mxIpsText from '../cleanmail/data/mx_ips.txt';
import mxPatternsText from '../cleanmail/data/mx_patterns.txt';
import verifiedText from '../cleanmail/data/verified_domains.txt';

function lines(text) {
  return new Set(text.split(/\r?\n/).map((value) => value.trim()).filter(Boolean));
}

// These sets are immutable configuration after module initialization. Request state
// is never written into them, so they are safe to share between Worker invocations.
export const WORKER_DATA = Object.freeze({
  allowlist: lines(allowlistText),
  verified: lines(verifiedText),
  core: lines(coreText),
  community: lines(communityText),
  mxPatterns: lines(mxPatternsText),
  mxIps: lines(mxIpsText),
  metadata,
});
