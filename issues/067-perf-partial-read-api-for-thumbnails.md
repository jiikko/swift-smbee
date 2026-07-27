# 067 perf: 小さい部分 READ を安く回すための API が足りない（サムネイル生成用途）

状態: **open（A は実装済み。B / C / D と実サーバ計測が未着手）**
起票: 2026-07-27
更新: 2026-07-27 — A: prefix read を実装（`9f20dbf` 実装 / `13acbdc` E2E / `4c36c12` 空ファイル unit）。
`SMBClientSession.readPrefix` / `withPrefixReadStream` が使える。unit + perf regression
（CREATE1/QUERY_INFO0/READ1/CLOSE1 = 3、既存 read は QUERY_INFO1 込みで 4）+ Samba E2E
（smoke 3 プロファイル green）で固定済み。**測定はコマンド数の固定のみで、実サーバの
往復レイテンシ削減は未計測**（「測定を先にやる」の実測部分は未達のまま）。
関連: `Sources/SMBee/SMBClient.swift`（`read` / `withReadStream` / `streamRead` / `readBounds`） /
`Sources/SMBee/SMB2Header.swift`（`nextCommand` / `SMB2CreditWindow`） /
consumer 側: obaket `macOS/issues/437-feat-smb-thumbnail-display.md`

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
