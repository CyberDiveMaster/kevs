# kevs

CISA / ENISA(EUVD) / CIRCL / KEVIntel / VulnCheck の5つのKEV(Known Exploited
Vulnerabilities)カタログを横断し、いずれか1つにでも掲載されているCVEを
一覧で確認できる軽量ビューワー。サーバ不要(GitHub Actions + GitHub Pages +
クライアントサイドJSのみ)。

表示言語は英語(グローバル利用を想定)。CVE ID / Date Published / First
Listed / Days / CVSS Score / EPSS / 各カタログ掲載有無 / Vendor / Product
でフィルタ・ソートできる。ツールバーの **Columns** ボタンで列の表示・非表示を
切り替え可能(Days・EPSSは既定で非表示)。

- **Days**: Date Published(cve.org)からFirst Listed(現在含まれている
  カタログの中で一番早い掲載日)までの日数。カタログを除外すると
  First Listed同様に再計算される。マイナス値は、cve.orgの正式公開日より
  前に悪用が報告されていたことを意味する。

### フィルタ・ソート状態のURL共有

フィルタ内容・ソート順・除外カタログ(×ボタン)・列の表示/非表示(Columns
ボタン)は、すべてブラウザのアドレスバーの `?s=...` パラメータに自動的に
反映される(`history.replaceState`のため、変更のたびに閲覧履歴が増えることは
ない)。そのURLをそのまま他人に共有すれば、開いた相手にも同じ絞り込み・
並び替え・列構成が再現される。サーバ側での保存は一切行わない
(URLだけで完結)。ツールバーの **Reset** ボタンで `?s=` の付かない
素のURLに移動し、全ての状態を初期化できる。

### ソーシャル共有ボタン・ANTERASロゴ

ページ下部(フッター)左側に X / LinkedIn / Reddit / WhatsApp への共有
アイコン(各社の公式ブランドカラー・形状のSVGをインライン埋め込み、
外部アイコンCDNには依存しない)を設置。クリック時点の `location.href`
を使うため、`?s=` が付いていればそのフィルタ・ソート状態ごと共有される。
X/Reddit/WhatsAppは共有リンクのURLパラメータで本文サンプルも渡すが、
LinkedInの共有エンドポイントはURL以外のパラメータを受け付けないため、
`<head>` の `og:title` / `og:description` でLinkedInのスクレイパーに
本文サンプルを渡している。ヘッダーには置かず、フッターに留めることで
控えめな見た目にしている。

フッター右側には Macnica ANTERAS
( https://www.macnica.co.jp/business/security/manufacturers/anteras/ )
へのロゴリンクを設置。ロゴ画像自体は透過PNGで文字が黒色のため、
ダークモードでも視認できるよう小さな白背景チップを敷いている。

## データソースと取得方法

| カタログ | 取得方法 | 認証 |
|---|---|---|
| CISA | 公開JSON( `known_exploited_vulnerabilities.json` )を1回取得 | 不要 |
| ENISA (EUVD) | `/api/kev/dump` を1回取得(全件ダンプ) | 不要 |
| CIRCL | `vulnerability.circl.lu/api/kev/` をページング取得 | 不要 |
| VulnCheck | `/v3/backup/vulncheck-kev` で全件バックアップzipのURLを取得しダウンロード | APIキー(Bearer) |
| KEVIntel | `/api/v2/kevs` をページング取得(無料枠) | APIキー(`X-API-Token`) |

**ENISA・CIRCLの掲載判定について:** どちらも「自前のKEVカタログ」を謳って
いるが、実データはCISA KEV(および他カタログ)を丸ごと自社DBに取り込んで
再公開しているだけの割合が非常に大きい。CISAの列と重複した情報になって
しまうため、この2列は**そのカタログ独自の情報のみ**を「掲載あり」とする
仕様にしている:
- **ENISA**: `sources` に `eukev_kev`(ENISA独自のEU域内調査によるタグ)
  が含まれるエントリのみ対象。`cisa_kev` タグのみ(CISAの単純ミラー、
  1600件超)は対象外。→ 実質40件程度。
- **CIRCL**: `gcve.origin_uuid` がCIRCL自身の一次情報(「CIRCL Local」)
  であるエントリのみ対象(サーバー側の `vulnerability_lookup_origin`
  フィルタで絞り込み)。`cisa-kev` / `kevintel` / `shadowserver` /
  `enisa-cnw-kev` からのミラーは対象外(これらだけでCIRCLの生データの
  大半を占める。特にShadowserverは今回の5カタログに含まれない別ソース)。
  → 実質20件弱程度。

### Date Published / CVSS Score / Vendor / Product の補完

上記5カタログのどれかに挙がった時点で、cve.org の公式API
( `cveawg.mitre.org/api/cve/{id}` )から直接取得して補完する。読み取り
アクセス自体は認証不要だが、レート制限が厳しい(未認証: 30秒5リクエスト
≒ 毎分10件、CVE Services APIキー保有時: 30秒50リクエスト)。CVE Services
のキーは自己登録制ではなく、CNA(CVE Numbering Authority)のスポンサーが
必要な登録制なので、未認証運用が既定。一度取得した内容は
`data/cve_metadata_cache.json` にキャッシュし、次回以降は新規CVEのみ
追加取得する。1回の実行で新規取得するCVE数は `CVE_METADATA_MAX_PER_RUN`
(既定5000件。CVE Services/NVD双方のAPIキー認証済みなら和集合全体を
1回でカバーできる想定)で上限を設けている。未認証運用の場合は現状
(和集合約5,200件)の初回バックフィルが1回では終わらず、3時間おきの
定期実行に自然に分散される点に注意。GitHub Actionsの1ジョブ6時間上限
に対するセーフティネットとして
`timeout-minutes: 240` も設定済み)。

CVE Servicesのアカウントを取得できた場合は、Secretsに以下の3つを追加
すれば自動的にレート制限が緩和される(`scripts/fetch_cve_metadata.py`
参照。ヘッダー名は公開ドキュメントからの推測で、実アカウントでの検証は
未実施):
- `CVE_API_KEY`
- `CVE_API_ORG`
- `CVE_API_USER`

**Vendor/Productの"n/a"問題とNVDフォールバック:** cve.orgのCNAレコードは
約4割が vendor/product を "n/a" のまま(特に担当CNAが具体的な報告元を持たず
「mitre」が汎用的に受け付けたレコードに多い)。この場合、NVD
( `services.nvd.nist.gov` )のCPEデータ(先頭の一致のみ採用)で補完する。
NVDも別途レート制限があるが、CVE Servicesと違い**誰でも即時に無料APIキーを
自己発行できる**ので、`NVD_API_KEY` を発行して登録することを推奨。
補完した値はViewer上でVendor/Product列に薄い「NVD」ヒントタグを表示して
区別する。cve.org側のCNAレコードが後日更新されて実データが入った場合は、
7日ごとの再チェック(既存のnullフィールド再チェックの仕組みを流用)で
自動的にcve.org側の値へ差し替わる。

### EPSS(悪用予測スコア)

CVSS Scoreの右にEPSS列を追加(FIRST.org、`epss.empiricalsecurity.com/epss_scores-current.csv.gz`
のバルクCSVを1回取得し、和集合に該当するCVEだけを抽出)。EPSSは1日1回
(UTC 13:30頃)しか更新されないため、他4カタログと違い**3時間おきには
再取得しない**。GitHub Actionsのスケジュールに専用のcronエントリ
(`30 14 * * *`、UTC 14:30 = FIRST.org更新の1時間後)を追加してあり、
このタイミング(または手動実行時)だけ `REFRESH_EPSS=true` として
`data/epss_cache.json` を更新する。それ以外の3時間おきの通常実行では
前回キャッシュされた値をそのまま使い回す。

表示は「45.2% <span style="opacity:.5">89th</span>」のように、EPSS
スコア(%表記)を主表示にし、パーセンタイル順位はCVSSの「v3.1」ヒントと
同じスタイルで補足情報として添える(別カラムにすると別指標に見えてしまう
ため)。EPSS値はFIRST.orgの該当CVE APIレスポンス(`api.first.org/data/v1/epss?cve=...`、
人間向けページが無いため生JSON)にリンクし、列見出し自体は
`first.org/epss/` にリンクする。

**変化トレンド:** EPSS単体の絶対値だけでなく、直近でどれだけ変化したかも
表示する(例: 「45.2% 89th ▲+12.3pp/7d」)。30日固定にすると、VulnCheck
などが公開から日が浅いうちにKEV掲載するケースで軒並み「変化なし表示」に
なってしまうため、**30日→7日→1日の順で、実際にそのCVEのスナップショットが
存在する最長の期間**を自動選択して主表示にする(ラベルで実際の期間を明示)。
他の期間の変化量はツールチップに表示。悪化(上昇)は赤、改善(下降)は緑。

過去分は `epss_scores-YYYY-MM-DD.csv.gz`(FIRST.orgが2021-04-14以降を
日付ごとに保持)を毎回その場で取得して差分計算するだけで、**自前では
履歴を一切保存しない**。そのためこの機能を追加してもリポジトリの
データ量は増えない。

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
   NVD APIキー(無料・即時発行)も登録推奨:
   - `NVD_API_KEY`
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
