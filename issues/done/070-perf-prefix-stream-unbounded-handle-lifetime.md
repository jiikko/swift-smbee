# 070 perf: withPrefixReadStream に上限も operation timeout も無く handle を無期限に保持しうる

状態: **done (2026-09-25)**
起票: 2026-07-27（issue 067 A の敵対的レビューで検出）
関連: `Sources/SMBee/SMBClient.swift`（`SMBClientSession.withPrefixReadStream` / `SMBClient.prefixRead`）

## 症状（未再現・レビュー由来の構造指摘）

`readPrefix` には 64 MiB の蓄積上限があるが、`withPrefixReadStream` は意図的に上限を持たない
（蓄積しないため）。しかし:

- `maxLength` に巨大な値を渡し、サーバが毎回要求長いっぱい返し続けると、長時間 handle を
  保持し続ける（credit は READ response 受信時点で grant 処理が済むため保持し続けない。
  問題は handle・session task・callback capture の寿命）。
- `onChunk` が戻らない（consumer 側のデッドロック等）と、READ ループがそこで止まり handle が
  開いたまま残る。operation timeout が無いため自力では抜けられない。
  なお協力的な `onChunk` であれば各 chunk 後に cancellation check があり、無期限保持は起きない。

consumer（サムネイル生成）の実用値は最大 4 MiB なので通常は問題にならないが、API 契約としては
「呼び出し側の行儀」だけに依存している。

## 対応候補

- stream 版にも合理的な `maxLength` 上限を設ける（download 用途と分けるなら別 API に誘導する）。
- `SMBOperationDeadline` 系の仕組みで operation timeout を渡せるようにする
  （既存の cleanup timeout と同じ思想。onChunk 停滞時に CANCEL + CLOSE で抜ける）。

## 先にやること

これは「悪用・事故に対する頑健性」の話で、実際に困っている consumer はまだ居ない。
obaket 側の採用（`macOS/issues/437` Phase 2）で実運用パターンが確定してから、その上限値・
timeout 値を決めるのが順序として正しい。先に値を決め打ちしない。

## 関連

- issue 067（A の実装で意図的に「stream 版は制限しない」と決めた経緯は
  `Sources/SMBee/SMBClient.swift` の `maxPrefixReadLength` の doc コメント参照）
- issue 065 / 066（cleanup・cancel 経路の資源寿命の系譜）

## 決着 (2026-09-25)

「先にやること」の前提は満たされていた: obaket の macOS issue 437 (done) で `withPrefixReadStream` が
サムネイル取得に採用され、実運用パターンは段階読み 64 KiB → 512 KiB → 4 MiB (呼び出しは
`shared/Sources/ObaketInfrastructure/Storage/SMB/SMBAdapter.swift` の `readPrefix` のみ。16 MiB の full fetch は別経路)。

### 採った対応: stream 版にも prefix read の上限を掛ける

- `withPrefixReadStream` の `maxLength` を `readPrefix` と同じ `SMBClientSession.maxPrefixReadLength` (64 MiB) で、
  CREATE を送る前に拒否する (`SMBCodecError.invalidValue`、`readPrefix` と同じ型)。
- 効果は「prefix API を無制限のダウンロードに使わせない」こと。**handle の寿命そのものは有界にならない**
  (寿命を決めるのは onChunk と server の遅さ)。大きい読みは `withReadStream(range:)` へ誘導する。
  obaket の最大 4 MiB には影響しない。README にも上限を書いた。

### 採らなかった対応: operation timeout 引数

- `SMBOperationDeadline` は operation task の終了を待つので、取消を無視する onChunk は timeout 引数を足しても
  抜けられない。取消に応じる onChunk は、呼び出し側が `SMBOperationDeadline.run(timeout:)` で包めば今でも抜けられ、
  handle は best-effort で CLOSE される。
- CLOSE も応答しなければ、cleanup timeout (5 秒) の後に transport ごと破棄される。戻りが deadline より遅れ、
  同じ session の他の操作も失敗する。この挙動を `withPrefixReadStream` の doc comment に書いた
  (`withReadStream` も timeout を持たない点も併記)。再評価の trigger: consumer が「deadline を包んでも抜けられない」
  停止を実際に報告したとき。

### テスト (Tests/SMBeeTests/SMBeeTests.swift)

- `testClientSessionPrefixStreamRejectsPrefixLimitBeforeCreate`: 上限 +1 で何も送らずに拒否する。
- `testClientSessionPrefixStreamAcceptsExactlyThePrefixLimit`: 上限ちょうどは通る (境界は「以下」)。
- `testClientSessionPrefixStreamDeadlineCancelsStalledChunkAndClosesHandle`: 止まった onChunk を deadline で包むと
  `timedOut` で抜け、CREATE・READ・CLOSE が出る。
- `testClientSessionPrefixStreamCancellationAfterChunkStopsBeforeNextRead`: 1 credit で READ が 64 KiB に切り詰められる
  fixture で 128 KiB を読む。取り消さない対照は READ 2 回。1 回目の onChunk で取り消すと、2 回目の READ を出さずに CLOSE する。

変異検証 (使い捨て worktree):
- guard を消す → 上限 +1 のテストが red / `<=` を `<` にする → 上限ちょうどのテストが red /
  エラー経路の CLOSE を消す → deadline のテストと既存の chunk 失敗テストが red。
- **prefixRead の取消確認 3 か所と、session 層の送信前の確認 (`readChunkReportingRequestedLength`) の計 4 か所を消しても、
  最後のテストは green のまま**だった。2 回目の READ は、onCancel → `cancelInFlightRequest` → `failPendingResponse` で
  未送信の送信タスクが取り消され、`sendSigned` の取消確認で止まる。この最後の層は、送信タスクと取消タスクの
  actor への到着順に依存する。つまりこのテストは「chunk 後の取消で次の READ は出ない」を端から端まで固定するもので、
  明示的な確認 1 か所ずつを見分けることはできない (明示的な確認があるので production では決定的)。

### レビュー

敵対レビュー (read-only) を 1 周通した。P1 なし。P2 2 件 (上限の効果の書き方 / 取消で handle が閉じるという過大な主張) は
doc を直し、P3-1 (chunk 後の取消が未固定) はテストを足した。P3-2 (上限超過の `SMBCodecError` を obaket が一時障害として
再試行しうる) は、obaket の最大値 4 MiB では到達しないので記録のみ。修正は doc とテストだけで判定ロジックを
増やしておらず、効き目は上の変異で確かめたので、2 周目は回していない。
container Samba の smoke (`make smoke`、3 profile) は `Sources/SMBee` tree 15a17fe で通過。
