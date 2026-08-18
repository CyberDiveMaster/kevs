# kevs

CISA / ENISA(EUVD) / CIRCL / KEVIntel / VulnCheck の5つのKEV(Known Exploited
Vulnerabilities)カタログを横断し、いずれか1つにでも掲載されているCVEを
一覧で確認できる軽量ビューワー。サーバ不要(GitHub Actions + GitHub Pages +
クライアントサイドJSのみ)。

表示言語は英語(グローバル利用を想定)。CVE ID / Date Published / Active
Since / CVSS Score / 各カタログ掲載有無 / Vendor / Product でフィルタ・
ソートできる。

## データソースと取得方法

| カタログ | 取得方法 | 認証 |
|---|---|---|
| CISA | 公開JSON( `known_exploited_vulnerabilities.json` )を1回取得 | 不要 |
| ENISA (EUVD) | `/api/kev/dump` を1回取得(全件ダンプ) | 不要 |
| CIRCL | `vulnerability.circl.lu/api/kev/` をページング取得 | 不要 |

**ENISA・CIRCLの掲載判定について:** どちらも「自前のKEVカタログ」を謳って
いるが、実データはCISA KEV(および他カタログ)を丸ごと自社DBに取り込んで
再公開しているだけの割合が非常に大きい。CISAの列と重複した情報になって
しまうため、この2列は**そのカタログ独自の情報のみ**を「掲載あり」とする
仕様にしている:
- **ENISA**: `sources` に `eukev_kev`(ENISA独自のEU域内調査によるタグ)
  が含まれるエントリのみ対象。`cisa_kev` タグのみ(CISAの単純ミラー、
  1600件超)は対象外。→ 実質40件程度。
- **CIRCL**: `evidence.source` がCIRCL自身の一次情報
  (`cti-feed.circl.lu` 等)であるエントリのみ対象。`cisa-kev` /
  `kevintel` / `shadowserver` / `enisa-cnw-kev` からのミラーは対象外
  (これらだけでCIRCLの生データの大半を占める。特にShadowserverは今回の
  5カタログに含まれない別ソース)。→ 実質数件程度。
| VulnCheck | `/v3/backup/vulncheck-kev` で全件バックアップzipのURLを取得しダウンロード | APIキー(Bearer) |
| KEVIntel | `/api/v2/kevs` をページング取得(無料枠) | APIキー(`X-API-Token`) |

Date Published / CVSS Score / Vendor / Product は、上記5カタログのどれかに
挙がった時点で cve.org の公式API( `cveawg.mitre.org/api/cve/{id}` )から
直接取得して補完する。読み取りアクセス自体は認証不要だが、レート制限が
厳しい(未認証: 30秒5リクエスト ≒ 毎分10件、CVE Services APIキー保有時:
30秒50リクエスト)。CVE Servicesのキーは自己登録制ではなく、CNA(CVE
Numbering Authority)のスポンサーが必要な登録制なので、未認証運用が既定。
一度取得した内容は `data/cve_metadata_cache.json` にキャッシュし、次回
以降は新規CVEのみ追加取得する。1回の実行で新規取得するCVE数は
`CVE_METADATA_MAX_PER_RUN`(既定1500件)で上限を設けており、現状(和集合
約5,200件)の初回バックフィルは3時間おきの定期実行に自然に分散される
(1回では終わらない点に注意。GitHub Actionsの1ジョブ6時間上限に対する
セーフティネットとして `timeout-minutes: 240` も設定済み)。

CVE Servicesのアカウントを取得できた場合は、Secretsに以下の3つを追加
すれば自動的にレート制限が緩和される(`scripts/fetch_cve_metadata.py`
参照。ヘッダー名は公開ドキュメントからの推測で、実アカウントでの検証は
未実施):
- `CVE_API_KEY`
- `CVE_API_ORG`
- `CVE_API_USER`

## 仕組み

1. **`.github/workflows/kev-sync.yml`**(3時間おき、GitHub Actionsが自動実行)
   `scripts/build.py` が5カタログすべてを取得 → 全体の和集合を取り、
   未キャッシュのCVEのみcve.orgから補完 → 各CVEについて
   5カタログ中もっとも早い掲載日を `active_since` として算出 →
   `docs/data/kevs.json` / `meta.json` を書き出し → 差分があればコミット
   (これがそのままGitHub Pagesの更新になる)。
   いずれかのカタログの取得に失敗した場合はビルド全体を中断し(既存の
   公開データは上書きしない)、次回の定期実行に委ねる。
2. **`docs/index.html`**(GitHub Pagesで配信)
   `kevs.json` / `meta.json` を取得してTabulator.jsに読み込ませる。
   フィルタ・ソートはすべてブラウザ側。バックエンドAPIは存在しない。

## セットアップ手順

1. このフォルダをGitHubに `kevs` という Public リポジトリとしてpush。
2. リポジトリの Settings → Secrets and variables → Actions で、以下の
   2つをSecretとして登録する(**コード中には一切書かない**):
   - `VULNCHECK_API_KEY`
   - `KEVINTEL_API_KEY`
   CVE ServicesのAPIキーを取得できた場合は、追加で以下3つも登録する
   (任意。未登録なら未認証のまま動作する):
   - `CVE_API_KEY` / `CVE_API_ORG` / `CVE_API_USER`
3. リポジトリの Settings → Pages で、Source を `Deploy from a branch`、
   Branch を `main` / `/docs` に設定。
4. Actions タブから `Update KEV data` を手動実行(workflow_dispatch)して
   初回データを生成・pushさせる。以降はスケジュール実行(3時間おき)に
   任せる。

## 各カタログ列の表示について

- CISA / ENISA / CIRCL / KEVIntel は匿名で閲覧できる公開ページへのリンク
  (ENISAは `/vulnerability/{EUVD-ID}` 形式。実URLでHTTP 200を確認済みだが
  中身はReact SPAのためブラウザでの最終確認はしていない)。
- VulnCheck のリンク先(`console.vulncheck.com`)は無料アカウントでの
  ログインが必要。匿名の第三者はクリックしても中身を見られない点に注意
  (VulnCheck側にログイン不要の個別CVEページが存在しないための制約)。
