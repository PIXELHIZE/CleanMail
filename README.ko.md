# CleanMail

[English](README.md) | 한국어 | [日本語](README.ja.md)

CleanMail은 회원가입·인증·쿠폰·무료체험 악용에 쓰이는 일회용 이메일을 판별하는 한국어 우선 필터입니다. 최신 JavaScript와 Node.js 내장 모듈만 사용하며 CLI, 일괄 검사, HTTP API, 재현 가능한 데이터 빌더와 회전형 도메인용 MX 탐지를 제공합니다.

> CleanMail은 기존 가입·인증 흐름 앞에 붙이는 판별 계층입니다. SMTP/IMAP 메일함 서버는 아닙니다.

## 주요 수치

- 정적 고유 차단 도메인: **102,827개**
- 실서비스·사용 표본·공급자 인프라로 검증: **111개**
- 회전형 서비스 MX 호스트 지문: **25개**
- 전용 MX 수신 IP 지문: **13개**
- 런타임 외부 의존성 없음
- Node.js 20 이상

| 계층 | 정책 | 개수 |
|---|---|---:|
| `core` | 두 기준 저장소의 정확한 교집합 | 1,846 |
| `community` | 외부 공개 입력 중 2개 이상에 존재, `core` 제외 | 100,887 |
| `verified` | 실제 발급·선택기·API·사용 표본·MX 근거로 확인 | 111 |
| 최종 고유 정적 차단 | 위 세 차단 계층의 합집합 | **102,827** |

111개 검증 표본에서 `disposable-email-domains`는 12개, `groundcat`은 5개를 탐지했습니다. 둘의 합집합은 14개, 교집합은 3개였습니다. 최신 누락값을 의도적으로 포함한 표본이므로 인터넷 전체 탐지율로 해석하면 안 됩니다.

## 빠른 시작

```bash
npm install
node src/cleanmail/cli.js stats
node src/cleanmail/cli.js check user@gmail.com user@vhm.cc user@yorielle.com
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

if (result.disposable) {
  console.log(`차단: ${result.matched_domain} (${result.tier})`);
}
```

- `check()` / `checkMany()`는 동기식 정적 검사입니다.
- `checkOnline()` / `checkManyOnline()`은 정적 검사 후 필요할 때만 DNS를 조회합니다.
- DNS 결과는 기본 6시간 캐시되며 조회 단계별 제한 시간은 2.5초입니다.
- MX 판정은 `tier="mx"`와 `matched_mx`, `matched_mx_pattern` 또는 `matched_mx_ip`를 반환합니다.

## HTTP API

```bash
node src/cleanmail/cli.js serve --host 127.0.0.1 --port 8080
```

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/check \
  -H 'content-type: application/json' \
  -d '{"email":"hello@vhm.cc"}'
```

요청당 최대 100개를 일괄 검사할 수 있습니다.

- `GET /health`
- `GET /v1/stats`
- `GET /v1/check?email=...`
- `POST /v1/check` — `email` 문자열 또는 `emails` 배열

## Docker

```bash
docker build -t cleanmail .
docker run --rm -p 8080:8080 cleanmail
```

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
4. 미등록 도메인은 MX 호스트와 전용 수신 IP를 검사합니다.
5. 근거가 없거나 DNS가 실패하면 `not_listed`를 반환합니다.

Cloudflare Email Routing, Google Workspace, 범용 호스팅 MX처럼 여러 정상 사용자가 공유하는 인프라는 지문으로 사용하지 않습니다. Emailnator 등이 Gmail/Yahoo 주소를 발급하더라도 공용 도메인 자체를 막으면 정상 사용자가 대량 차단되므로 그렇게 처리하지 않습니다.

## 데이터 원천

기준 저장소는 [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains)와 [groundcat/disposable-email-domain-list](https://github.com/groundcat/disposable-email-domain-list)입니다. 추가 공개 입력과 라이선스는 `THIRD_PARTY_NOTICES.md`, 한국·일본 집중 조사 기록은 `docs/research-2026-08-18.md`에 정리되어 있습니다.

## 테스트

```bash
npm test
```

문법 정규화, 하위 도메인, 검증 표본, 정상 사업자 우선순위, MX 호스트·IP 판정, DNS 실패, 데이터 무결성, HTTP API를 검사합니다.

## 라이선스

CleanMail 코드는 MIT 라이선스입니다. 결합 데이터에는 각 원천의 CC0, MIT, BSD-3-Clause 조건이 적용됩니다.
