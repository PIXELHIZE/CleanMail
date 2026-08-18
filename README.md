# CleanMail

English | [한국어](README.ko.md) | [日本語](README.ja.md)

CleanMail is a Korean-first disposable email detector for signup, verification, coupon, and free-trial abuse prevention. It is implemented in modern JavaScript, uses only Node.js built-in modules, and ships with a CLI, batch checks, an HTTP API, a reproducible dataset builder, and online MX-infrastructure detection.

> CleanMail is a filtering layer for an existing authentication or registration flow. It is not an SMTP or IMAP mailbox server.

## Highlights

- 102,827 unique statically blocked domains
- 111 domains verified from live issuance, selectors, public APIs, supplied samples, or corroborated provider infrastructure
- 25 dedicated MX hostname fingerprints and 13 receiver IP fingerprints for rotating domains
- Parent-domain suffix matching for disposable subdomains
- Existing protections for legitimate providers such as Gmail, Naver, Daum, and Yahoo
- No runtime dependencies
- Node.js 20 or newer

The generated dataset metadata in `src/cleanmail/data/metadata.json` is the authoritative source for current counts.

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

if (result.disposable) {
  console.log(`Blocked: ${result.matched_domain} (${result.tier})`);
}
```

- `check(email)` and `checkMany(emails)` are synchronous and static-only.
- `checkOnline(email)` and `checkManyOnline(emails)` check static data first and query DNS only when necessary.
- Online DNS results are cached for six hours by default, with a 2.5-second timeout per lookup phase.
- An MX match returns `tier: "mx"` plus `matched_mx`, `matched_mx_pattern`, or `matched_mx_ip`.

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

Batch check, up to 100 addresses per request:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/check \
  -H 'content-type: application/json' \
  -d '{"emails":["hello@naver.com","hello@yorielle.com"]}'
```

Endpoints:

- `GET /health`
- `GET /v1/stats`
- `GET /v1/check?email=...`
- `POST /v1/check` with an `email` string or `emails` array

Invalid syntax is reported as `valid=false`. A domain with no static or infrastructure match is returned as `valid=true, disposable=false, reason="not_listed"`.

## Docker

```bash
docker build -t cleanmail .
docker run --rm -p 8080:8080 cleanmail
```

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
4. For an unknown domain, resolve MX records and match dedicated disposable-provider hostnames.
5. If necessary, resolve those MX hosts and compare their receiver IPs.
6. Return `not_listed` when no evidence matches or DNS fails.

Shared infrastructure such as Cloudflare Email Routing, Google Workspace, and generic hosting-provider MX servers is not fingerprinted. Blocking those shared systems would create severe false positives. Services that issue Gmail or Yahoo addresses cannot be safely detected by blocking the public provider domain itself.

## Data sources and research

The baseline repositories are:

- [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains)
- [groundcat/disposable-email-domain-list](https://github.com/groundcat/disposable-email-domain-list)

Community inputs include [disposable/disposable](https://github.com/disposable/disposable), [7c/fakefilter](https://github.com/7c/fakefilter), [wesbos/burner-email-providers](https://github.com/wesbos/burner-email-providers), [email-check-app/disposable-email-providers](https://github.com/email-check-app/disposable-email-providers), and [eramitgupta/disposable-email](https://github.com/eramitgupta/disposable-email).

The Korean and Japanese research pass also verified live or rotating domains from VHM MAIL, LT's Email Workshop, Tempo, Mikiya Web, Tomy Mail JP, kuku.lu/InstAddr, MailPorary, mail.cx, Mohmal, GuerrillaMail, YOPmail, Temp-Mail.org, CleanTempMail, and related services. Evidence and observations are recorded in `docs/research-2026-08-18.md` and `src/cleanmail/data/verified_evidence.json`.

## Testing

```bash
npm test
```

The test suite covers syntax normalization, suffix rules, verified samples, allowlist precedence, MX hostname and IP detection, DNS failure behavior, generated dataset integrity, and the HTTP API.

## License

CleanMail source code is licensed under MIT. Combined data retains the applicable CC0, MIT, and BSD-3-Clause terms of its upstream sources. See `THIRD_PARTY_NOTICES.md` for details.
