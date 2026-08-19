# CleanMail

[English](README.md) | 한국어 | [日本語](README.ja.md)

CleanMail은 회원가입·인증·쿠폰·무료체험 악용에 쓰이는 일회용 이메일과 가입 위험을 판별하는 JavaScript 필터입니다. 하나의 저장소에서 서로 독립적인 Node.js/Docker 서비스와 Cloudflare Worker를 지원합니다. 둘을 동시에 실행할 필요 없이 원하는 배포 대상 하나만 선택하면 됩니다.

> CleanMail은 기존 가입·인증 흐름 앞에 붙이는 판별 계층입니다. SMTP/IMAP 메일함 서버는 아닙니다.

## 주요 수치

- 정적 고유 차단 도메인: **188,134개**
- 실서비스·사용 표본·공급자 인프라로 검증: **111개**
- 회전형 서비스 MX 호스트 지문: **25개**
- 전용 MX 수신 IP 지문: **13개**
- 문법은 맞지만 MX 레코드가 없는 주소 차단
- DNS·로컬파트·RDAP 등록정보·인프라·평판·선택형 SMTP 심층 분석
- 역할 계정·하위 주소·금칙어의 정책별 차단 지원
- Node.js 프로덕션 의존 패키지 없음, Worker 캐시에 KV·R2·D1 바인딩 불필요
- 로컬 개발 및 Wrangler 기준 Node.js 22 이상

| 계층 | 정책 | 개수 |
|---|---|---:|
| `core` | 두 기준 저장소의 정확한 교집합 | 1,846 |
| `community` | 외부 공개 입력 중 2개 이상에 존재, `core` 제외 | 186,206 |
| `verified` | 실제 발급·선택기·API·사용 표본·MX 근거로 확인 | 111 |
| 최종 고유 정적 차단 | 위 세 차단 계층의 합집합 | **188,134** |

## 실행 대상 선택

| 대상 | 포함 기능 | 제외되는 코드 | SMTP 검사 |
|---|---|---|---|
| Node.js / Docker | CLI, Node HTTP API, DNS/RDAP, 선택형 직접 SMTP 검사, 내장 데이터 | Worker 진입점 | 명시적으로 켤 때 사용 가능 |
| Cloudflare Workers | Fetch API, DNS/RDAP, 위험 분석기, 내장 데이터 | CLI, Node HTTP 서버, 파일 로더, 직접 SMTP 구현 | Workers의 외부 25번 포트 제한으로 지원 불가 |

두 대상은 함께 구동하는 서비스가 아니라 서로 다른 빌드 그래프입니다. Docker 이미지는 `src/cleanmail`만 복사합니다. Wrangler는 `src/worker/entry.js`의 import 그래프만 묶기 때문에 Worker 결과물에는 공용 탐지기·분석기·데이터만 들어가고 Node 서버와 실제 SMTP 구현은 들어가지 않습니다. 현재 Worker dry-run 결과는 원본 2,884.04KiB, gzip 1,046.30KiB입니다.

111개 검증 표본에서 `disposable-email-domains`는 12개, `groundcat`은 5개를 탐지했습니다. 둘의 합집합은 14개, 교집합은 3개였습니다. 최신 누락값을 의도적으로 포함한 표본이므로 인터넷 전체 탐지율로 해석하면 안 됩니다.

## 빠른 시작

```bash
npm install
node src/cleanmail/cli.js stats
node src/cleanmail/cli.js check user@gmail.com user@vhm.cc user@yorielle.com
node src/cleanmail/cli.js analyze --json user+trial@new-domain.example
```

```text
ALLOW   user@gmail.com (allowlist)
BLOCK   user@vhm.cc (verified)
BLOCK   user@yorielle.com (mx)
```

CLI는 정적 목록에 없는 도메인에만 온라인 MX 검사를 수행합니다. 네트워크 없는 정적 검사에는 `--offline`을 사용합니다.

```bash
node src/cleanmail/cli.js check --offline user@example.com
```

하나라도 차단되거나 문법 오류가 있으면 종료 코드 1을 반환합니다.

## JavaScript API

```js
import { CleanMailDetector } from './src/cleanmail/index.js';

const cleanmail = new CleanMailDetector();
const result = await cleanmail.checkOnline('hello@yorielle.com');

if (result.blocked) {
  console.log(`차단: ${result.matched_domain} (${result.tier})`);
}
```

- `check()` / `checkMany()`는 동기식 정적 검사입니다.
- `checkOnline()` / `checkManyOnline()`은 정적 검사 후 필요할 때만 DNS를 조회합니다.
- MX가 없는 도메인은 `blocked=true, disposable=false, deliverable=false, reason="no_mx_records"`로 반환합니다.
- 장기 실행 Node 프로세스에서는 DNS 결과를 기본 6시간 캐시하며 조회 단계별 제한 시간은 2.5초입니다. Worker는 공개 도메인 인프라 결과만 내장 Cache API에 저장합니다.
- MX 판정은 `tier="mx"`와 `matched_mx`, `matched_mx_pattern` 또는 `matched_mx_ip`를 반환합니다.

심층 분석에는 `CleanMailAnalyzer`를 사용합니다.

```js
import { CleanMailAnalyzer, CleanMailDetector } from './src/cleanmail/index.js';

const analyzer = new CleanMailAnalyzer(new CleanMailDetector());
const report = await analyzer.analyze('support+trial@example.com');

if (report.blocked) console.log(report.reason, report.risk_score);
```

`analyze()`는 `canonical_email`, `risk_score`, `risk_level`, 구조화된 `signals`와 `checks`를 반환합니다. 구문·역할 계정·`+태그`·횡설수설·금칙어, DNS/MX/A/AAAA/NS, SPF·DMARC·MTA-STS, 서브도메인, MX 사업자·보안 게이트웨이·공인 IP·역방향 DNS, 선택형 DNS 차단목록, RDAP 생성일·도메인 나이·등록대행자·상태·DNSSEC가 포함됩니다.

문법 오류, 일회용 근거, Null MX/MX 부재, 설정한 DNS 차단목록 적중, 명시적으로 실행한 SMTP의 영구 수신자 거절은 즉시 차단합니다. 역할 계정·하위 주소·신규 도메인·횡설수설 같은 신호는 합산하며 기본 임계값은 7점입니다. 역할 계정과 하위 주소는 각각 `--block-role`, `--block-subaddress`를 지정하기 전에는 단독 차단하지 않습니다.

RFC 5321은 일반 MX가 없을 때 도메인의 A/AAAA 주소로 배달을 시도할 수 있게 합니다. CleanMail은 이 프로젝트가 정한 더 엄격한 “MX 필수” 가입 정책을 유지하므로 이 레거시 방식을 쓰는 정상 도메인도 차단될 수 있습니다. Null MX는 표준상 확정적인 메일 미수신 선언입니다.

SMTP 검사는 기본 꺼짐입니다. `--smtp`는 `EHLO`, `MAIL FROM`, `RCPT TO`까지만 실행하고 `DATA`나 메일 본문을 보내지 않습니다. `--catch-all`은 존재하지 않는 무작위 주소를 한 번 더 검사합니다. 미리 DNS로 확인한 공인 MX IP만 접속하며, 4xx 그레이리스팅은 차단이 아니라 재검사 신호로 반환합니다. 2xx 응답도 실제 최종 배달을 보장하지는 않습니다.

## HTTP API

```bash
node src/cleanmail/cli.js serve --host 127.0.0.1 --port 8080
```

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/check \
  -H 'content-type: application/json' \
  -d '{"email":"hello@vhm.cc"}'
```

심층 보고서:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/analyze \
  -H 'content-type: application/json' \
  -d '{"email":"support+trial@example.com","options":{"risk_threshold":7}}'
```

요청당 최대 100개를 일괄 검사할 수 있습니다.

Node/Docker와 Worker는 아래 엔드포인트를 동일하게 제공합니다. 최종 거부 여부는 `blocked` 필드가 기준입니다. 문법 오류는 `valid=false, blocked=true`, MX가 없는 주소는 `valid=true, blocked=true, disposable=false`입니다.

- `GET /health`
- `GET /v1/stats`
- `GET /v1/check?email=...`
- `POST /v1/check` — `email` 문자열 또는 `emails` 배열
- `GET /v1/analyze?email=...`
- `POST /v1/analyze` — `email`/`emails`와 선택형 `options`

Node HTTP에서 SMTP 검사를 허용하려면 서버 환경변수 `CLEANMAIL_ENABLE_SMTP=true`와 요청의 `options.smtp=true`가 모두 필요합니다. 공개 API가 무제한 SMTP 스캐너가 되는 것을 막기 위한 제한입니다. Worker에서 SMTP를 요청하면 가능한 심층 분석 결과의 `checks.smtp`에 `status="unsupported"`, `reason="smtp_port_25_unavailable_on_cloudflare_workers"`를 반환합니다. DNS 차단목록은 사업자별 이용 조건이 달라 기본 비활성화하고 라이브러리 옵션으로 주입합니다.

## Docker

```bash
docker build -t cleanmail .
docker run --rm -p 8080:8080 cleanmail
```

Docker 이미지는 Node 구현과 생성 데이터만 복사합니다. `src/worker`, Wrangler, Vitest, Worker 개발 의존성은 이미지에 포함하지 않습니다.

## Cloudflare Workers

Worker는 Docker, 원본 서버, 저장소 바인딩 없이 단독으로 동작합니다. 기준 차단 계층과 MX 지문은 배포 파일에 내장되며 필터 최신화 때마다 새로 빌드하고 배포합니다. 내장 Cache API는 공개 DNS·RDAP 인프라 결과에만 사용합니다.

로컬 실행:

```bash
npm install
npm run dev:worker
```

Wrangler의 기본 로컬 주소에서 Node/Docker와 동일한 API를 호출합니다.

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/check \
  -H 'content-type: application/json' \
  -d '{"email":"hello@vhm.cc"}'
```

배포 없는 번들 검사와 실제 배포:

```bash
npm run build:worker
npm run deploy:worker
```

최신 공개 원천을 가져와 전체 테스트를 실행하고 새로운 Worker 번들을 생성합니다.

```bash
npm run refresh:worker
```

필터 최신화는 항상 새 데이터셋 생성과 Worker 재빌드를 거칩니다. 생성된 변경을 검토한 다음 `npm run deploy:worker`로 해당 번들을 배포합니다.

`wrangler.jsonc`에는 호환 날짜 `2026-08-18`, 지원되는 DNS/URL 유틸리티를 위한 `nodejs_compat`, Workers Observability가 설정되어 있습니다. `worker-configuration.d.ts`는 `npm run types:worker`로 갱신합니다.

운영 특성:

- 정적 목록이나 정상 공급자 보호 규칙에 걸리면 DNS/RDAP 네트워크 호출 없이 끝납니다.
- 미등록 도메인은 Workers가 지원하는 `node:dns`로 조회하며 DNS 작업마다 Worker 하위 요청을 사용합니다.
- DNS/MX 성공 결과는 1시간, 영구적인 DNS 부재 응답은 5분 캐시합니다. 타임아웃과 일시 장애는 캐시하지 않습니다.
- 심층 분석의 도메인 RDAP 결과는 6시간, IANA 부트스트랩은 24시간, RDAP 404/410 응답은 5분 캐시합니다.
- 캐시에는 정규화한 공개 도메인, DNS 레코드 유형, 공개 메일 호스트 결과, RDAP URL만 들어갑니다. 전체 이메일 주소와 로컬 파트는 캐시 키나 값에 저장하지 않습니다.
- Cloudflare Cache API 캐시는 데이터센터별 임시 저장소이며 KV·R2·D1 설정이 필요하지 않습니다.
- Workers는 외부 TCP 25번 포트를 막으므로 직접 SMTP 수신자·캐치올 검사가 불가능합니다. 이 선택 기능이 필요하면 Node/Docker 대상을 사용해야 합니다.
- JSON 본문은 16KiB, 일괄 검사는 요청당 100개로 제한합니다.
- 검증/교집합/커뮤니티 집합은 읽기 전용 모듈 설정입니다. 요청별 분석기는 진행 중인 중복 작업만 합치며 요청에 묶인 I/O 객체를 전역에 두지 않습니다.

## 데이터 재생성

```bash
# 최신 공개 원천 사용
node scripts/build-dataset.js

# 이미 복제한 원천으로 오프라인 재현 빌드
node scripts/build-dataset.js --source-root work/research
```

기본 커뮤니티 정족수는 2이며 단일 목록 오염을 줄이기 위해 1은 허용하지 않습니다. 수동 검증값은 `config/verified_domains.json`, 회전형 인프라는 `config/disposable_mx_patterns.txt`와 `config/disposable_mx_ips.txt`에서 관리합니다.

## 판정 순서

1. 주소와 국제화 도메인을 정규화합니다.
2. 정상 메일 사업자 보호 규칙을 먼저 검사합니다.
3. `verified`, `core`, `community` 순서로 도메인 접미사를 검사합니다.
4. 미등록 도메인에 MX가 없거나 도메인이 존재하지 않으면 `no_mx_records`로 차단합니다.
5. MX가 있으면 전용 일회용 호스트와 수신 IP를 검사합니다.
6. 정상 MX에 일회용 근거가 없으면 `not_listed`를 반환합니다. 일시적인 DNS 장애와 타임아웃은 기존처럼 허용합니다.

Cloudflare Email Routing, Google Workspace, 범용 호스팅 MX처럼 여러 정상 사용자가 공유하는 인프라는 지문으로 사용하지 않습니다. Emailnator 등이 Gmail/Yahoo 주소를 발급하더라도 공용 도메인 자체를 막으면 정상 사용자가 대량 차단되므로 그렇게 처리하지 않습니다.

프로토콜 처리는 [SMTP RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321), [Null MX RFC 7505](https://datatracker.ietf.org/doc/html/rfc7505), [SPF RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489), [MTA-STS RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461), [IANA RDAP DNS 부트스트랩](https://data.iana.org/rdap/dns.json)을 따릅니다.

## 데이터 원천

기준 저장소는 [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains)와 [groundcat/disposable-email-domain-list](https://github.com/groundcat/disposable-email-domain-list)입니다. 커뮤니티 입력은 13개이며 MailChecker, 일본 전용 `jp-disposable-emails`, Rspamd freemail, EmailOnDeck 전용 목록, unkn0w, `email_data`, Castle, tompec 등을 포함합니다. 추가 공개 입력과 라이선스는 `THIRD_PARTY_NOTICES.md`, 한국·일본 집중 조사 기록은 `docs/research-2026-08-18.md`에 정리되어 있습니다.

## 테스트

```bash
npm test
npm run test:worker
npm run build:worker
```

Node 테스트 48개와 실제 Cloudflare Workers 런타임에서 실행하는 테스트 5개가 있습니다. 문법 정규화, 하위 도메인, 검증 표본, MX 호스트·IP, DNS 실패, 로컬파트 위험 신호, RDAP, 공인 IP 안전장치, SMTP·캐치올, 데이터 무결성, 캐시 성공·부재·일시 장애·실패 시 우회 처리, 두 HTTP 처리기, Worker 기동과 내장 데이터 로드를 검사합니다. `npm run build:worker`는 배포하지 않는 Wrangler 번들을 만듭니다.

## 라이선스

CleanMail 코드는 MIT 라이선스입니다. 결합 데이터에는 각 원천의 CC0, MIT, BSD-3-Clause, ISC, CC-BY-4.0 조건이 적용됩니다.
