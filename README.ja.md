# CleanMail

[English](README.md) | [한국어](README.ko.md) | 日本語

CleanMail は、使い捨てメールと登録リスクを検出する JavaScript フィルターです。1つのリポジトリで、互いに独立した Node.js/Docker サービスと Cloudflare Worker を提供します。両方を同時に動かす必要はなく、必要なデプロイ先を1つだけ選択できます。

> CleanMail は既存の登録・認証フローに追加する判定レイヤーです。SMTP/IMAP メールサーバーではありません。

## 主な特徴

- 静的ブロックドメイン: **188,134件**
- 実サービス、利用サンプル、プロバイダーのインフラで確認済み: **111件**
- ローテーション型サービスの MX ホスト指紋: **25件**
- 専用 MX 受信 IP 指紋: **13件**
- 構文は正しいが MX レコードが存在しないアドレスを拒否
- DNS、ローカル部、RDAP 登録情報、インフラ、レピュテーション、任意 SMTP の詳細分析
- ロールアドレス、サブアドレス、禁止語のポリシー別ブロック
- Node.js の本番依存パッケージなし、Worker キャッシュに KV・R2・D1 バインディング不要
- ローカル開発および Wrangler は Node.js 22 以上

| レイヤー | ポリシー | 件数 |
|---|---|---:|
| `core` | 2つの基準リポジトリの完全な共通部分 | 1,846 |
| `community` | 公開入力のうち2つ以上に存在し、`core`を除外 | 186,206 |
| `verified` | 発行画面、選択欄、API、利用サンプル、MX 根拠で確認 | 111 |
| 静的ブロックのユニーク合計 | 上記3レイヤーの和集合 | **188,134** |

## 実行環境の選択

| 対象 | 含まれる機能 | 含まれないコード | SMTP 検査 |
|---|---|---|---|
| Node.js / Docker | CLI、Node HTTP API、DNS/RDAP、任意の直接 SMTP 検査、組み込みデータ | Worker エントリーポイント | 明示的に有効化した場合のみ利用可能 |
| Cloudflare Workers | Fetch API、DNS/RDAP、リスク分析、組み込みデータ | CLI、Node HTTP サーバー、ファイルローダー、直接 SMTP 実装 | Workers の外向き25番ポート制限により非対応 |

2つは同時実行するサービスではなく、別々のビルドグラフです。Docker イメージは `src/cleanmail` だけをコピーします。Wrangler は `src/worker/entry.js` からの import グラフだけをバンドルするため、Worker には共有検出器・分析器・データが含まれ、Node サーバーと実 SMTP 実装は含まれません。現在の Worker dry-run は raw 2,884.04KiB、gzip 1,046.30KiB です。

111件の検証サンプルでは、`disposable-email-domains` が12件、`groundcat` が5件を検出しました。和集合は14件、共通部分は3件です。これは新しい未登録ドメインを意図的に含むサンプルであり、インターネット全体の検出率ではありません。

## クイックスタート

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

CLI は静的リストにないドメインだけオンライン MX 検査を行います。ネットワークを使わない静的検査には `--offline` を指定します。

```bash
node src/cleanmail/cli.js check --offline user@example.com
```

ブロックまたは構文エラーが1件でもある場合、終了コード 1 を返します。

## JavaScript API

```js
import { CleanMailDetector } from './src/cleanmail/index.js';

const cleanmail = new CleanMailDetector();
const result = await cleanmail.checkOnline('hello@yorielle.com');

if (result.blocked) {
  console.log(`Blocked: ${result.matched_domain} (${result.tier})`);
}
```

- `check()` / `checkMany()` は同期式の静的検査です。
- `checkOnline()` / `checkManyOnline()` は静的検査の後、必要な場合だけ DNS を照会します。
- MX が存在しないドメインは `blocked=true, disposable=false, deliverable=false, reason="no_mx_records"` を返します。
- 長時間稼働する Node プロセスでは DNS 結果を既定で6時間キャッシュし、各照会フェーズのタイムアウトは2.5秒です。Worker は公開ドメインのインフラ結果だけを組み込み Cache API に保存します。
- MX 判定では `tier="mx"` と `matched_mx`、`matched_mx_pattern` または `matched_mx_ip` を返します。

詳細分析には `CleanMailAnalyzer` を使用します。

```js
import { CleanMailAnalyzer, CleanMailDetector } from './src/cleanmail/index.js';

const analyzer = new CleanMailAnalyzer(new CleanMailDetector());
const report = await analyzer.analyze('support+trial@example.com');

if (report.blocked) console.log(report.reason, report.risk_score);
```

`analyze()` は `canonical_email`、`risk_score`、`risk_level`、構造化された `signals` と `checks` を返します。構文、ロールアドレス、`+tag`、ランダム文字列、禁止語、DNS/MX/A/AAAA/NS、SPF・DMARC・MTA-STS、サブドメイン、MX プロバイダー・セキュリティゲートウェイ・公開 IP・逆引き DNS、任意 DNS ブロックリスト、RDAP の作成日・ドメイン年齢・レジストラ・状態・DNSSEC が含まれます。

構文エラー、使い捨て根拠、Null MX/MX 不在、設定済み DNS ブロックリスト、明示的な SMTP 検査の恒久的な宛先拒否は即時ブロックします。ロール、サブアドレス、新規ドメイン、ランダム文字列などは合算し、既定のしきい値は7です。ロールとサブアドレスは `--block-role`、`--block-subaddress` を指定しない限り単独ではブロックしません。

RFC 5321 は通常の MX がない場合に A/AAAA への配送フォールバックを認めています。CleanMail はこのプロジェクトのより厳格な「MX 必須」登録ポリシーを維持するため、この旧方式を使う正規ドメインも拒否される可能性があります。Null MX は標準上の明確なメール非受信宣言です。

SMTP は既定で無効です。`--smtp` は `EHLO`、`MAIL FROM`、`RCPT TO` のみ実行し、`DATA` や本文を送信しません。`--catch-all` はランダムな存在しない宛先を追加確認します。事前解決した公開 MX IP のみに接続し、4xx グレーリストは拒否ではなく再検査シグナルになります。2xx 応答も最終配達を保証しません。

## HTTP API

```bash
node src/cleanmail/cli.js serve --host 127.0.0.1 --port 8080
```

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/check \
  -H 'content-type: application/json' \
  -d '{"email":"hello@vhm.cc"}'
```

詳細レポート:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/analyze \
  -H 'content-type: application/json' \
  -d '{"email":"support+trial@example.com","options":{"risk_threshold":7}}'
```

1回のリクエストで最大100件を検査できます。

Node/Docker と Worker は以下のエンドポイントを共通で提供します。最終的な拒否判定には `blocked` フィールドを使用します。構文エラーは `valid=false, blocked=true`、MX がないアドレスは `valid=true, blocked=true, disposable=false` です。

- `GET /health`
- `GET /v1/stats`
- `GET /v1/check?email=...`
- `POST /v1/check` — `email` 文字列または `emails` 配列
- `GET /v1/analyze?email=...`
- `POST /v1/analyze` — `email`/`emails` と任意の `options`

Node HTTP で SMTP を許可するには、サーバーの `CLEANMAIL_ENABLE_SMTP=true` とリクエストの `options.smtp=true` の両方が必要です。Worker で SMTP を要求した場合、実行可能な詳細分析の `checks.smtp` は `status="unsupported"`、`reason="smtp_port_25_unavailable_on_cloudflare_workers"` を返します。DNS ブロックリストはサービスごとに利用条件が異なるため既定では無効で、ライブラリオプションから設定します。

## Docker

```bash
docker build -t cleanmail .
docker run --rm -p 8080:8080 cleanmail
```

Docker イメージは Node 実装と生成済みデータだけをコピーします。`src/worker`、Wrangler、Vitest、Worker 開発依存関係は含みません。

## Cloudflare Workers

Worker は Docker、オリジンサーバー、ストレージバインディングなしで単独動作します。基準ブロックレイヤーと MX 指紋はデプロイに内蔵され、フィルター更新時に再ビルド・再デプロイされます。組み込み Cache API は公開 DNS・RDAP インフラ結果だけに使用します。

ローカル実行:

```bash
npm install
npm run dev:worker
```

Wrangler の既定ローカル URL で Node/Docker と同じ API を呼び出せます。

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/check \
  -H 'content-type: application/json' \
  -d '{"email":"hello@vhm.cc"}'
```

デプロイしないバンドル確認と実際のデプロイ:

```bash
npm run build:worker
npm run deploy:worker
```

最新の公開ソースを取得し、全テストを実行して新しい Worker バンドルを生成します。

```bash
npm run refresh:worker
```

フィルター更新は必ず新しいデータセット生成と Worker 再ビルドを経由します。生成された変更を確認してから `npm run deploy:worker` でそのバンドルを公開します。

`wrangler.jsonc` には互換日 `2026-08-18`、サポート済み DNS/URL ユーティリティ用の `nodejs_compat`、Workers Observability を設定しています。`worker-configuration.d.ts` は `npm run types:worker` で更新します。

運用上の特性:

- 静的リストまたは正規プロバイダー保護ルールに一致した場合、DNS/RDAP ネットワーク呼び出しなしで完了します。
- 未登録ドメインは Workers がサポートする `node:dns` で照会し、DNS 操作ごとに Worker サブリクエストを消費します。
- DNS/MX の成功結果は1時間、恒久的な DNS 不在応答は5分キャッシュします。タイムアウトと一時障害はキャッシュしません。
- 詳細分析のドメイン RDAP 結果は6時間、IANA ブートストラップは24時間、RDAP 404/410 応答は5分キャッシュします。
- キャッシュには正規化した公開ドメイン、DNS レコード種別、公開メールホスト結果、RDAP URL だけを保存します。完全なメールアドレスやローカル部はキャッシュキー・値に保存しません。
- Cloudflare Cache API はデータセンター単位の一時キャッシュで、KV・R2・D1 の設定は不要です。
- Workers は外向き TCP 25番ポートを遮断するため、直接の SMTP 宛先・catch-all 検査はできません。この任意機能が必要な場合は Node/Docker を使用してください。
- JSON 本文は16KiB、バッチは1リクエスト100件までです。
- 検証済み/core/community のセットは読み取り専用のモジュール設定です。リクエスト単位の分析器は処理中の重複作業だけをまとめ、リクエストに属する I/O オブジェクトをグローバルに保持しません。

## データセットの再生成

```bash
# 最新の公開ソースを使用
node scripts/build-dataset.js

# クローン済みソースでオフライン再現ビルド
node scripts/build-dataset.js --source-root work/research
```

コミュニティ入力の既定クォーラムは2です。単一リストの汚染を抑えるため、1は許可されません。手動検証ドメインは `config/verified_domains.json`、ローテーション型インフラは `config/disposable_mx_patterns.txt` と `config/disposable_mx_ips.txt` で管理します。

## 判定順序

1. メールアドレスと国際化ドメインを正規化します。
2. 正規メールプロバイダーの保護ルールを先に確認します。
3. `verified`、`core`、`community` の順でドメイン接尾辞を照合します。
4. 未登録ドメインに MX がない、またはドメインが存在しない場合は `no_mx_records` で拒否します。
5. MX がある場合は使い捨てサービス専用ホストと受信 IP を照合します。
6. 正常な MX に使い捨ての根拠がない場合は `not_listed` を返します。一時的な DNS 障害とタイムアウトは fail-open のままです。

Cloudflare Email Routing、Google Workspace、一般的なホスティング MX など、正規ユーザーと共有されるインフラは指紋として使用しません。Gmail や Yahoo のアドレスを発行するサービスがあっても、公開プロバイダー全体をブロックすると大規模な誤検出になるためです。

プロトコル処理は [SMTP RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321)、[Null MX RFC 7505](https://datatracker.ietf.org/doc/html/rfc7505)、[SPF RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208)、[DMARC RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489)、[MTA-STS RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461)、[IANA RDAP DNS ブートストラップ](https://data.iana.org/rdap/dns.json) に従います。

## データソース

基準リポジトリは [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) と [groundcat/disposable-email-domain-list](https://github.com/groundcat/disposable-email-domain-list) です。コミュニティ入力は13件で、MailChecker、日本向け `jp-disposable-emails`、Rspamd freemail、EmailOnDeck 専用リスト、unkn0w、`email_data`、Castle、tompec などを含みます。追加の公開入力とライセンスは `THIRD_PARTY_NOTICES.md`、韓国・日本向けの調査記録は `docs/research-2026-08-18.md` を参照してください。

日本向け調査では、とみーメールJP、Mikiya Web、kuku.lu/InstAddr、mail.cx、CleanTempMail などの実際の発行ドメインと MX インフラを確認しています。

## テスト

```bash
npm test
npm run test:worker
npm run build:worker
```

Node テスト48件と実際の Cloudflare Workers ランタイムで実行するテスト5件があります。構文正規化、サブドメイン、検証サンプル、MX ホスト・IP、DNS 障害、ローカル部のリスク、RDAP、公開 IP 保護、SMTP・catch-all、データ整合性、キャッシュの成功・不在・一時障害・フェイルオープン処理、2つの HTTP ハンドラー、Worker 起動、組み込みデータの読み込みを検査します。`npm run build:worker` はデプロイなしの Wrangler バンドルを作成します。

## ライセンス

CleanMail のソースコードは MIT ライセンスです。統合データには各ソースの CC0、MIT、BSD-3-Clause、ISC、CC-BY-4.0 条件が適用されます。
