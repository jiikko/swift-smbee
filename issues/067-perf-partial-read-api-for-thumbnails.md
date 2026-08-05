# 067 perf: 小さい部分 READ を安く回すための API が足りない（サムネイル生成用途）

状態: **open（A は実装済み。B / C / D と実サーバ計測が未着手）**
起票: 2026-07-27
更新: 2026-07-27 — A: prefix read を実装（`9f20dbf` 実装 / `13acbdc` E2E / `4c36c12` 空ファイル unit）。
`SMBClientSession.readPrefix` / `withPrefixReadStream` が使える。unit + perf regression
（CREATE1/QUERY_INFO0/READ1/CLOSE1 = 3、既存 read は QUERY_INFO1 込みで 4）+ Samba E2E
（smoke 3 プロファイル green）で固定済み。**測定はコマンド数の固定のみで、実サーバの
往復レイテンシ削減は未計測**（「測定を先にやる」の実測部分は未達のまま）。
更新: 2026-08-05 — consumer 側の実機ログで **第 2 の profile（動画 range read）** を観測。
window ごとに CREATE+QUERY_INFO+CLOSE を払っていることが裏付けられた（下記「追加観測」）。
優先度の示唆: `knownSize:` による QUERY_INFO 省略が両 profile に効き、実装コストも B より低い。
関連: `Sources/SMBee/SMBClient.swift`（`read` / `withReadStream` / `streamRead` / `readBounds`） /
`Sources/SMBee/SMB2Header.swift`（`nextCommand` / `SMB2CreditWindow`） /
consumer 側: obaket `macOS/issues/437-feat-smb-thumbnail-display.md` /
obaket `issues/done/460-architecture-large-exact-range-bypasses-window-split.md`（window 分割の設計） /
obaket `issues/462-perf-video-range-window-prefetch.md`（C の consumer 側前提）

## 背景

consumer（obaket）は SMB 上の画像に対して **client-side サムネイル生成** を行う。その取得パターンは
「多数のファイルについて、それぞれ先頭 64 KiB だけ読む」で、既存の download / 大容量 read とは
コスト構造がまったく違う:

- 転送量は小さい（64 KiB）が **件数が多い**（可視 30〜60 件）。
- したがって **往復回数がコストの支配項**であり、スループットではなくレイテンシが効く。

既存の公開 API（`SMBClientSession.read` / `withReadStream`）はこの用途に対して往復が多い。

## 現状の事実（実装確認済み）

1. **通常ファイルの読みで 4 往復**。`read` / `withReadStream` はどちらも
   `create` → `queryInfo` → `readChunk`（1 回以上）→ `bestEffortClose` を個別のリクエストとして送る
   （空ファイルなど READ が出ないケースは 3 往復。「最低 4」ではない）。
2. **QUERY_INFO が常に発行される**。呼び出し側が range を明示していても、`readBounds` が
   `stat.size` でクランプするために必ず 1 往復増える。呼び出し側が listing で size を既に
   知っているケース（サムネイル生成はまさにこれ）でも省略できない。
3. **compound（chained）リクエストが未実装**。`SMB2Header.nextCommand` フィールドは codec に
   存在するが、複数コマンドを 1 フレームに連結して送る経路は無い。SMB2 の CREATE+QUERY_INFO+
   CLOSE / CREATE+READ+CLOSE 連鎖が使えていない。
4. **`streamRead` は逐次**。`readChunk` を 1 つずつ await して次を送るため、full fetch fallback
   （最大 16 MiB）では `maxReadSize` 単位の往復がそのまま直列に並ぶ。credit window
   （`SMB2CreditWindow`）と多重化受信（`pendingResponses` + 受信ループ）は既にあるので、
   READ をパイプライン化する下地はある。
5. **同時 open handle 数の上限が無い**。consumer が N 並列でサムネ生成すると N 個の handle が
   同時に開く。サーバ側上限に当たったときの挙動は未検証。

## 追加観測: 動画 range read という第 2 の consumer profile（2026-08-05、obaket 実機 SMB）

起票時の profile は「多数のファイルの先頭 64 KiB を読む」だったが、**同じ往復コストが
まったく違う形でもう 1 つの経路に効いている**ことが実測で分かった。

obaket は動画のプレビュー / サムネイルで 1 ファイルを **4 MiB の window に割って順に読む**
（window ごとに cancel 再確認と revision gate 再評価を行う設計）。この経路では
`withReadStream` が **window ごと**に呼ばれるため、上記「現状の事実 1/2」の
CREATE → QUERY_INFO → READ×N → CLOSE が **4 MiB ごとに 1 セット**発生する。

実測ログ（344 MB / 4.8 GB の mp4、SMB）:

- 連続再生中、4.2 MB の `[storage-request]` が完全に直列で 7 本連続（window ごとに 1 read）
- AVPlayer の `observedBitrate` は 69.2 Mbps。4 MiB の転送は約 0.49 秒で、
  そこに CREATE+QUERY_INFO+CLOSE の往復が毎回乗る

この profile に対する含意:

1. **`knownSize:`（A の代替案）は prefix read だけでなく ranged read にも効く**。
   consumer は listing で size を持っている（obaket の動画経路は `ObjectMetadata.size` が
   非 nil であることを生成の前提条件にしており、`totalBytes` として loader に渡している）。
   `readBounds` の EOF クランプのためだけの QUERY_INFO は、window ごとに 1 往復ぶん無駄になる。
   B（compound）より実装コストが低く、window 経路にも prefix 経路にも同時に効く。
2. **B（CREATE+READ+CLOSE の compound 化）はこの profile でこそ効く**。1 ファイルに対し
   数十〜数百 window を開くため、window あたり 3 往復の削減がそのまま積み上がる。
3. **C（READ パイプライン化）は consumer 側の先読みと組で初めて効く**
   （obaket `issues/462-perf-video-range-window-prefetch.md`）。ただし obaket 側は SMB を
   `StorageServiceKind.maxConcurrentConnectionsHint = 1` で直列化しており、その理由は
   「複数 outstanding requests の安全性を実機で確認するまで直列寄りにする」。C を活かすには
   SMBee 側の多重 outstanding の安全性確認と、consumer 側の hint 見直しの**両方**が要る。
4. **D（同時 open handle の上限）は現状この profile では顕在化していない**。obaket は動画
   サムネイル生成を幅 1 の gate で直列化しているため、同時に開く handle は実質 1 本。

なお consumer 側は「小さい尻尾のためだけに window を 1 つ増やさない」等の緩和を入れたが、
それは往復回数そのものを減らすものではない（`obaket issues/done/460-...` の trade-off）。
**往復を減らせるのは SMBee 側の A(knownSize) / B / C だけ**。

## 欲しいもの（候補・優先度順）

### A. prefix read: QUERY_INFO を省略できる部分 READ — ✅ 実装済み（冒頭の更新履歴参照）

「先頭 N バイトを読む。ファイルが N 未満なら取れた分だけ返す（EOF はエラーにしない）」という
API を用意する。現状は EOF クランプのために QUERY_INFO を強制しているのが往復増の直接原因。

- READ が `STATUS_END_OF_FILE` を返したら短く返す（`read` の「short read は error」契約とは別レーン）。
- 呼び出し側が既知の size を渡せる口（`knownSize:`）でも代替可能。どちらが素直かは設計で決める。

### B. CREATE + READ + CLOSE の compound 化

`nextCommand` 連鎖を実装して 1 往復にまとめる。A と組み合わせると **4 往復 → 1 往復**。
実装コストは A より高く、compound 応答の分解・部分失敗（CREATE 成功 / READ 失敗で handle が
残る）の扱いを決める必要がある。**A を先に入れて効果を測ってから判断する**のが妥当。

### C. READ のパイプライン化（full fetch 経路）

`streamRead` で credit の許す範囲だけ先行して READ を投げる。chunk 順序の保証と
onChunk の逐次呼び出し契約を壊さないこと（consumer は progressive decode に順序を仮定している）。

### D. 同時 open handle の上限とバックプレッシャー

セッション単位で「同時に開く handle 数」の上限を持ち、超過分は待たせる。サーバ側上限に
当たって STATUS_* で失敗するより、待つほうが consumer にとって扱いやすい。

## 測定を先にやる（Aの前）

「往復が支配項」は構造からの推論であり、実測していない。**まず現状のコストを測ってから**
API を追加する:

- container Samba に対し、64 KiB prefix read × N 件の総時間と往復回数を測る。
- `issues/003` の perf regression 基盤（`SMBeePerformanceRegressionTests`）に
  「小さい部分 READ の往復回数」を契約として固定できるか検討する。往復回数は環境非依存の
  指標なので、この基盤に載せやすいはず。

これをやらずに A/B を入れると、効いたかどうかを主張できない。

## Non-goals

- サムネイル生成そのもの（デコード・縮小）を SMBee が持つこと。SMBee の責務はバイト転送まで。
- EXIF / コンテナ解析。呼び出し側（consumer）の責務。

## 受け入れ条件（A を実装する場合）

- 先頭 N バイト読みが **QUERY_INFO なし**で成立し、ファイルが N 未満でもエラーにならない。
- 既存の `read` / `withReadStream` の契約（`read` の short read = error、`withReadStream` の
  onChunk 逐次・順序保証）を変えない。
- unit で EOF 到達・0 バイトファイル・N > size・N == size の境界を固定する。
- production の wire を触るため、`bin/e2e/smoke-all`（3 プロファイル）を commit 後に通す。

## 2026-08-01 追記: B/C/D の着手判断（issue 068 の実測データによる）

issue 068 close 時の再計測（container Samba・64KiB prefix read、`432c261` / `9e6cde7` の
CREDIT_FIFO_HOL_READ_TIMING）で B の価値判断に使える実測が取れた:

- prefix read 全体（CREATE+READ+CLOSE）: baseline ~2ms、大 WRITE 競合時 p50 10-14ms
- うち READ transaction 単体（pending→recv）: baseline ~0.85ms、競合時 ~3ms
- → **prefix 全体の 60-70% は CREATE/CLOSE と処理間の残差**。B（compound、3→1 往復）は
  localhost でも件数比例の削減余地があり、実 NAS（RTT が ms 級）では 2×RTT×件数の削減になる

判断: **B は「価値の見込みあり」だが着手は保留のまま**。理由:
1. issue の gate（consumer 実害）が未発火（obaket からのサムネイル遅延報告なし）
2. compound (related requests) は wire 中核（credit・署名・demux の複合 request 対応）の
   大きめ実装で、issue 010 §方針 1（single reader 構造改修）と同時期にやると危険
3. 実 NAS の RTT 実測（compatibility matrix 作業）が先。localhost の 1.5ms/件では
   30-60 件でも 50-90ms で、実害 gate（issue 068 と同じ基準）未達

C / D は B より優先度が下がる（C は full fetch 経路で今回の用途外、D は A の運用実績待ち）。
