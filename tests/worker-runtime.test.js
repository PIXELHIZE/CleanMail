import { exports } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';

function request(path, init) {
  return exports.default.fetch(new Request(`https://cleanmail.test${path}`, init));
}

describe('CleanMail Cloudflare Worker runtime', () => {
  it('boots in workerd and reports the Worker runtime', async () => {
    const response = await request('/health');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      status: 'ok',
      service: 'CleanMail',
      runtime: 'cloudflare-workers',
    });
  });

  it('loads the complete embedded dataset', async () => {
    const response = await request('/v1/stats');
    expect(response.status).toBe(200);
    const stats = await response.json();
    expect(stats.total_blocked).toBeGreaterThan(100_000);
    expect(stats.verified).toBeGreaterThan(100);
    expect(stats.core).toBeGreaterThan(1_000);
    expect(stats.community).toBeGreaterThan(1_000);
  });

  it('blocks a verified temporary-mail domain without a network lookup', async () => {
    const response = await request('/v1/check?email=person%40vhm.cc');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      valid: true,
      blocked: true,
      disposable: true,
      domain: 'vhm.cc',
      tier: 'verified',
    });
  });

  it('keeps a known legitimate provider allowed', async () => {
    const response = await request('/v1/check?email=person%40gmail.com');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      blocked: false,
      disposable: false,
      tier: 'allowlist',
    });
  });

  it('handles analyze syntax failures without external I/O', async () => {
    const response = await request('/v1/analyze?email=not-an-email');
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      valid: false,
      blocked: true,
      reason: 'invalid_email_syntax',
    });
  });
});
