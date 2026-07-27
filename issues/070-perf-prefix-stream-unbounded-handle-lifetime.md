# 070 perf: withPrefixReadStream に上限も operation timeout も無く handle を無期限に保持しうる

状態: **open**
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
