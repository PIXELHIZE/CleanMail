# CleanMail

[English](README.md) | [한국어](README.ko.md) | 日本語

CleanMail は、アカウント登録、メール認証、クーポン、無料トライアルの不正利用に使われる使い捨てメールを検出する、韓国・日本のサービスを重視したフィルターです。Node.js の組み込みモジュールだけで実装され、CLI、バッチ検査、HTTP API、再現可能なデータセットビルダー、ローテーションドメイン向けの MX 検出を提供します。

> CleanMail は既存の登録・認証フローに追加する判定レイヤーです。SMTP/IMAP メールサーバーではありません。

## 主な特徴

- 静的ブロックドメイン: **102,827件**
- 実サービス、利用サンプル、プロバイダーのインフラで確認済み: **111件**
- ローテーション型サービスの MX ホスト指紋: **25件**
- 専用 MX 受信 IP 指紋: **13件**
- ランタイム依存パッケージなし
- Node.js 20 以上

| レイヤー | ポリシー | 件数 |
|---|---|---:|
| `core` | 2つの基準リポジトリの完全な共通部分 | 1,846 |
| `community` | 公開入力のうち2つ以上に存在し、`core`を除外 | 100,887 |
| `verified` | 発行画面、選択欄、API、利用サンプル、MX 根拠で確認 | 111 |
| 静的ブロックのユニーク合計 | 上記3レイヤーの和集合 | **102,827** |

111件の検証サンプルでは、`disposable-email-domains` が12件、`groundcat` が5件を検出しました。和集合は14件、共通部分は3件です。これは新しい未登録ドメインを意図的に含むサンプルであり、インターネット全体の検出率ではありません。

## クイックスタート

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

if (result.disposable) {
  console.log(`Blocked: ${result.matched_domain} (${result.tier})`);
}
```

- `check()` / `checkMany()` は同期式の静的検査です。
- `checkOnline()` / `checkManyOnline()` は静的検査の後、必要な場合だけ DNS を照会します。
- DNS 結果は既定で6時間キャッシュされ、各照会フェーズのタイムアウトは2.5秒です。
- MX 判定では `tier="mx"` と `matched_mx`、`matched_mx_pattern` または `matched_mx_ip` を返します。

## HTTP API

```bash
node src/cleanmail/cli.js serve --host 127.0.0.1 --port 8080
```

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/check \
  -H 'content-type: application/json' \
  -d '{"email":"hello@vhm.cc"}'
```

1回のリクエストで最大100件を検査できます。

- `GET /health`
- `GET /v1/stats`
- `GET /v1/check?email=...`
- `POST /v1/check` — `email` 文字列または `emails` 配列

## Docker

```bash
docker build -t cleanmail .
docker run --rm -p 8080:8080 cleanmail
```

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
4. 未登録ドメインは MX ホストと専用受信 IP を照合します。
5. 根拠がない場合や DNS が失敗した場合は `not_listed` を返します。

Cloudflare Email Routing、Google Workspace、一般的なホスティング MX など、正規ユーザーと共有されるインフラは指紋として使用しません。Gmail や Yahoo のアドレスを発行するサービスがあっても、公開プロバイダー全体をブロックすると大規模な誤検出になるためです。

## データソース

基準リポジトリは [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) と [groundcat/disposable-email-domain-list](https://github.com/groundcat/disposable-email-domain-list) です。追加の公開入力とライセンスは `THIRD_PARTY_NOTICES.md`、韓国・日本向けの調査記録は `docs/research-2026-08-18.md` を参照してください。

日本向け調査では、とみーメールJP、Mikiya Web、kuku.lu/InstAddr、mail.cx、CleanTempMail などの実際の発行ドメインと MX インフラを確認しています。

## テスト

```bash
npm test
```

構文正規化、サブドメイン、検証サンプル、正規プロバイダーの優先、MX ホスト・IP 判定、DNS 障害、データ整合性、HTTP API を検査します。

## ライセンス

CleanMail のソースコードは MIT ライセンスです。統合データには各ソースの CC0、MIT、BSD-3-Clause 条件が適用されます。
