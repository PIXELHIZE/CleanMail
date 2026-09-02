import assert from 'node:assert/strict';
import test from 'node:test';

import { mergeHistoricalTiers } from '../scripts/build-dataset.js';

test('historical domains remain in existing tiers unless explicitly allowlisted', () => {
  const currentCore = new Set(['new-core.example', 'promoted.example']);
  const currentCommunity = new Set(['new-community.example']);
  const previousCore = new Set(['old-core.example']);
  const previousCommunity = new Set(['old-community.example', 'promoted.example']);
  const previousBlocked = new Set([
    ...previousCore,
    ...previousCommunity,
    'removed-upstream.example',
    'allowed.example',
  ]);
  const verified = new Set(['verified.example']);
  const allowlist = new Set(['allowed.example']);

  const { core, community, allBlocked } = mergeHistoricalTiers({
    currentCore,
    currentCommunity,
    previousCore,
    previousCommunity,
    previousBlocked,
    verified,
    allowlist,
  });

  assert.deepEqual(core, new Set(['old-core.example', 'new-core.example']));
  assert.deepEqual(community, new Set(['old-community.example', 'promoted.example', 'new-community.example', 'removed-upstream.example']));
  assert.deepEqual(allBlocked, new Set([
    'old-core.example',
    'new-core.example',
    'old-community.example',
    'promoted.example',
    'new-community.example',
    'removed-upstream.example',
    'verified.example',
  ]));
});
