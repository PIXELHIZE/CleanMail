# CleanMail

English | [한국어](README.ko.md) | [日本語](README.ja.md)

CleanMail is a Korean-first disposable email and signup-risk detector written in modern JavaScript. The same repository provides two alternative production targets: a Node.js/Docker service and a standalone Cloudflare Worker. Both expose the same filtering API and embedded dataset; you deploy only the target you need.

> CleanMail is a filtering layer for an existing authentication or registration flow. It is not an SMTP or IMAP mailbox server.

## Highlights

- 102,827 unique statically blocked domains
- 111 domains verified from live issuance, selectors, public APIs, supplied samples, or corroborated provider infrastructure
- 25 dedicated MX hostname fingerprints and 13 receiver IP fingerprints for rotating domains
- Parent-domain suffix matching for disposable subdomains
- Rejection of syntactically valid domains that have no MX records
- Deep DNS, local-part, RDAP registration, infrastructure, reputation, and optional SMTP analysis
- Configurable blocking for role accounts, subaddresses, and prohibited local-part tokens
- Existing protections for legitimate providers such as Gmail, Naver, Daum, and Yahoo
- No Node.js production dependencies and no Worker storage/service bindings
- Node.js 22 or newer for local development and Wrangler

The generated dataset metadata in `src/cleanmail/data/metadata.json` is the authoritative source for current counts.

## Choose one runtime

| Target | Includes | Does not include | SMTP probe |
|---|---|---|---|
| Node.js / Docker | CLI, Node HTTP API, DNS/RDAP, optional direct SMTP probe, embedded data | Worker entry point | Available, opt-in |
| Cloudflare Workers | Fetch API handler, DNS/RDAP, risk analyzer, embedded data | CLI, Node HTTP server, filesystem loader, direct SMTP implementation | Unsupported because Workers cannot connect to outbound port 25 |

These are separate build graphs, not two services that must run together. The Docker image copies only `src/cleanmail`. Wrangler follows imports from `src/worker/entry.js`, so the generated Worker contains the shared detector/analyzer and data but not the Node server or SMTP implementation. The current Worker dry-run upload is 1,585.26 KiB raw and 580.75 KiB gzip.

## Detection tiers

| Tier | Policy | Count |
|---|---|---:|
| `core` | Exact intersection of the two baseline repositories | 1,846 |
| `community` | Present in at least two public community inputs, excluding `core` | 100,887 |
| `verified` | Confirmed through live services, supplied samples, or provider/MX evidence | 111 |
| Unique static block set | Union of the three block tiers | **102,827** |
| `mx` hostname fingerprints | Dedicated infrastructure used by rotating providers | 25 |
| `mx` IP fingerprints | Receiver IPs used only after resolving an MX host | 13 |

The two original baseline lists cover only a small part of the intentionally difficult verified sample. Across 111 verified domains, `disposable-email-domains` detected 12 and `groundcat` detected 5; their union detected 14 and their intersection detected 3. This is a targeted sample, not an estimate of internet-wide recall.

## Quick start

```bash
npm install
node src/cleanmail/cli.js stats
node src/cleanmail/cli.js check user@gmail.com user@vhm.cc user@yorielle.com
node src/cleanmail/cli.js analyze --json user+trial@new-domain.example
```

Example output:

```text
ALLOW   user@gmail.com (allowlist)
BLOCK   user@vhm.cc (verified)
BLOCK   user@yorielle.com (mx)
```

CLI checks use online MX classification when a domain is absent from the static lists. Use `--offline` for a deterministic static-only check:

```bash
node src/cleanmail/cli.js check --offline user@example.com
```

The command exits with status 1 when any address is blocked or syntactically invalid, which makes it suitable for CI and registration scripts.

## JavaScript API

```js
import { CleanMailDetector } from './src/cleanmail/index.js';

const cleanmail = new CleanMailDetector();
const result = await cleanmail.checkOnline('hello@yorielle.com');

if (result.blocked) {
  console.log(`Blocked: ${result.matched_domain} (${result.tier})`);
}
```

- `check(email)` and `checkMany(emails)` are synchronous and static-only.
- `checkOnline(email)` and `checkManyOnline(emails)` check static data first and query DNS only when necessary.
- A domain with no MX records is returned as `blocked=true, disposable=false, deliverable=false, reason="no_mx_records"`.
- In a long-running Node process, online DNS results are cached for six hours by default, with a 2.5-second timeout per lookup phase. Worker request state is not reused across invocations.
- An MX match returns `tier: "mx"` plus `matched_mx`, `matched_mx_pattern`, or `matched_mx_ip`.

For a full assessment, use `CleanMailAnalyzer`:

```js
import { CleanMailAnalyzer, CleanMailDetector } from './src/cleanmail/index.js';

const analyzer = new CleanMailAnalyzer(new CleanMailDetector());
const report = await analyzer.analyze('support+trial@example.com', {
  smtp: false,
  catchAll: false,
});

if (report.blocked) console.log(report.reason, report.risk_score);
```

`analyze()` returns `canonical_email`, `risk_score`, `risk_level`, structured `signals`, and detailed `checks`. Domain details include DNS activity, MX, A/AAAA, NS, SPF, DMARC, MTA-STS, subdomain/registrable-domain classification, MX provider and gateway detection, public MX addresses, reverse DNS, optional DNS blocklists, RDAP creation age, registrar, statuses, and DNSSEC. Local-part details include practical syntax, role accounts, `+tag` subaddressing, gibberish heuristics, and prohibited tokens.

Permanent facts such as invalid syntax, a disposable match, Null MX/no MX, a configured DNS-blocklist hit, or an explicitly requested SMTP `550/551/553` rejection block immediately. Softer indicators are combined into the 0–10 score; the default risk threshold is 7. Role accounts and subaddresses are signals only unless their explicit policy switches are enabled.

RFC 5321 permits delivery fallback to a domain's A/AAAA address when an ordinary MX record is absent. CleanMail intentionally keeps the project's stricter “MX required” signup policy, so a legitimate legacy domain that relies on fallback will be blocked; Null MX is the standards-defined definitive no-mail case.

SMTP probing is off by default. `--smtp` performs only `EHLO`, `MAIL FROM`, and `RCPT TO`; CleanMail never sends `DATA` or a message body. `--catch-all` adds a random nonexistent-recipient probe. Only pre-resolved public MX IPs are contacted. A 2xx RCPT response is evidence, not a delivery guarantee; 4xx greylisting is returned as a retry signal rather than a rejection.

## HTTP API

Start the service:

```bash
node src/cleanmail/cli.js serve --host 127.0.0.1 --port 8080
```

Check one address:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/check \
  -H 'content-type: application/json' \
  -d '{"email":"hello@vhm.cc"}'
```

Request a deep report:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/analyze \
  -H 'content-type: application/json' \
  -d '{"email":"support+trial@example.com","options":{"risk_threshold":7}}'
```

Batch check, up to 100 addresses per request:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/check \
  -H 'content-type: application/json' \
  -d '{"emails":["hello@naver.com","hello@yorielle.com"]}'
```

Endpoints are the same on Node/Docker and Workers:

- `GET /health`
- `GET /v1/stats`
- `GET /v1/check?email=...`
- `POST /v1/check` with an `email` string or `emails` array
- `GET /v1/analyze?email=...`
- `POST /v1/analyze` with an `email` string or `emails` array and optional `options`

The Node HTTP service accepts SMTP requests only when it is started with `CLEANMAIL_ENABLE_SMTP=true`; the CLI still requires the explicit `--smtp` flag. This prevents a public endpoint from becoming an unrestricted SMTP scanner. Cloudflare Workers always return `checks.smtp.status="unsupported"` with `reason="smtp_port_25_unavailable_on_cloudflare_workers"` when an eligible deep analysis requests SMTP. Configurable DNS blocklists are library-level options and ship disabled because providers have different access and redistribution terms.

`blocked` is the canonical decision field. Invalid syntax is reported as `valid=false, blocked=true`. A domain with no MX records is blocked as undeliverable without being mislabeled as disposable. A domain with a working MX but no static or infrastructure match is returned as `valid=true, blocked=false, disposable=false, reason="not_listed"`.

## Docker

```bash
docker build -t cleanmail .
docker run --rm -p 8080:8080 cleanmail
```

The image intentionally copies only the Node implementation and generated data. It does not contain `src/worker`, Wrangler, Vitest, or Worker development dependencies.

## Cloudflare Workers

The Worker is standalone: it needs no Docker container, origin server, KV, D1, R2, Durable Object, or other binding. The static block tiers and MX fingerprints are bundled into the deployment. Rebuild and redeploy the Worker after updating the dataset.

Run it locally:

```bash
npm install
npm run dev:worker
```

Then call the same HTTP API on Wrangler's local URL:

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/check \
  -H 'content-type: application/json' \
  -d '{"email":"hello@vhm.cc"}'
```

Build without deploying, then deploy when the result is ready:

```bash
npm run build:worker
npm run deploy:worker
```

`wrangler.jsonc` uses the `2026-08-18` compatibility date, `nodejs_compat` for the supported DNS and URL utilities, and Workers Observability. `worker-configuration.d.ts` is generated with `npm run types:worker`.

Operational details:

- Static/allowlist matches complete without DNS or RDAP network calls.
- Unknown domains use Cloudflare's supported `node:dns` resolver; each DNS operation counts as a Worker subrequest.
- Deep analysis may fetch the IANA RDAP bootstrap and the applicable registry. Only the public IANA bootstrap is cached with the Cache API; per-domain RDAP results are not placed in a shared cache.
- Direct SMTP recipient and catch-all probing is not possible on Workers because outbound TCP port 25 is blocked. Use the Node/Docker target if this optional feature is required.
- JSON request bodies are limited to 16 KiB and batches to 100 addresses.
- The verified/core/community sets are read-only module configuration. Per-request analyzers hold DNS promises only for that request, avoiding cross-request I/O state.

## Rebuilding the dataset

Fetch the current public sources:

```bash
node scripts/build-dataset.js
```

Use already cloned sources for a reproducible offline build:

```bash
node scripts/build-dataset.js --source-root work/research
```

The default community quorum is 2. A quorum of 1 is rejected to reduce single-list pollution and false positives. The GitHub Actions workflow rebuilds the generated data daily and commits it only after the tests pass.

Manual block evidence lives in `config/verified_domains.json`. Dedicated rotating-provider infrastructure is maintained in `config/disposable_mx_patterns.txt` and `config/disposable_mx_ips.txt`. No separate allow tier was introduced for newly discovered disposable domains.

## Detection policy

1. Normalize the address and internationalized domain name.
2. Protect known legitimate providers before applying block rules.
3. Match `verified`, `core`, and `community` domain suffixes in that order.
4. For an unknown domain, resolve MX records; reject `ENODATA`, `ENOTFOUND`, empty, or null-MX results as undeliverable.
5. Match dedicated disposable-provider MX hostnames and, if necessary, their receiver IPs.
6. Return `not_listed` when a working MX has no disposable evidence. Transient DNS failures and timeouts remain fail-open.

Shared infrastructure such as Cloudflare Email Routing, Google Workspace, and generic hosting-provider MX servers is not fingerprinted. Blocking those shared systems would create severe false positives. Services that issue Gmail or Yahoo addresses cannot be safely detected by blocking the public provider domain itself.

## Deliberate boundaries

CleanMail does not infer gender, consumer/business credit, or private registrant identity. Those are not reliable email-validity signals and create privacy or bias problems. Dark-web association requires a licensed breach/intelligence source, so no unverified scraper is bundled. Tor, VPN, geolocation, data-center, and connection-type checks describe the signup IP—not the email address—and belong in a separate request-context risk layer. Mail-server geolocation is likewise not used as a block rule. The JSON report and API provide dashboard-ready data, but a UI is outside the filtering core.

RDAP is used instead of legacy WHOIS and public registrant personal data is not copied into results; CleanMail reports the registrar and whether a registrant entity was disclosed. RDAP and transient DNS failures fail open and are shown as unavailable/timeout signals.

Protocol behavior follows [SMTP RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321), [Null MX RFC 7505](https://datatracker.ietf.org/doc/html/rfc7505), [SPF RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489), [MTA-STS RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461), and the [IANA RDAP DNS bootstrap registry](https://data.iana.org/rdap/dns.json).

## Data sources and research

The baseline repositories are:

- [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains)
- [groundcat/disposable-email-domain-list](https://github.com/groundcat/disposable-email-domain-list)

Community inputs include [disposable/disposable](https://github.com/disposable/disposable), [7c/fakefilter](https://github.com/7c/fakefilter), [wesbos/burner-email-providers](https://github.com/wesbos/burner-email-providers), [email-check-app/disposable-email-providers](https://github.com/email-check-app/disposable-email-providers), and [eramitgupta/disposable-email](https://github.com/eramitgupta/disposable-email).

The Korean and Japanese research pass also verified live or rotating domains from VHM MAIL, LT's Email Workshop, Tempo, Mikiya Web, Tomy Mail JP, kuku.lu/InstAddr, MailPorary, mail.cx, Mohmal, GuerrillaMail, YOPmail, Temp-Mail.org, CleanTempMail, and related services. Evidence and observations are recorded in `docs/research-2026-08-18.md` and `src/cleanmail/data/verified_evidence.json`.

## Testing

```bash
npm test
npm run test:worker
npm run build:worker
```

The suite contains 43 Node tests plus 5 tests executed inside the Cloudflare Workers runtime. It covers syntax normalization, suffix rules, verified samples, MX hostname and IP detection, DNS failure behavior, local-part risk signals, RDAP parsing, public-IP safety, SMTP/greylisting behavior, dataset integrity, both HTTP handlers, Worker startup, and embedded-data loading. `npm run build:worker` performs a Wrangler dry-run bundle; `npx wrangler check startup` profiles module startup locally.

## License

CleanMail source code is licensed under MIT. Combined data retains the applicable CC0, MIT, and BSD-3-Clause terms of its upstream sources. See `THIRD_PARTY_NOTICES.md` for details.
