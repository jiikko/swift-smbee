# 002 design: SMBSession を並行 multi-task 利用可能にする (messageId/credit ベース応答多重分離)

状態: **closed (案 1: wire transaction serializer 実装済み, 2026-06-30)**
起票: 2026-06-30
関連: `Sources/SMBee/SMBClient.swift` の `actor SMBSession` doc comment / commit `056f183`
(read streaming + actor 化) / todo.md 横断「SMBSession (actor) で全 wire を直列化」

## 背景

commit `056f183` で `SMBSession` を `final class` → `actor` 化し、mutable wire state
(messageId / sessionId / transformNonce / 鍵 / 交渉値) を隔離した。あわせて **「1 セッション =
単一フライト前提」を doc 化**した (actor 宣言直上のコメント)。

## 問題 (現状は未顕在・将来の制約)

各 wire 操作は `sendSigned` → `receive` の間に await (suspension) がある。**actor 隔離だけでは
この区間を critical section にできない** (actor reentrancy)。同一 `SMBSession` を複数タスクが並行に
呼ぶと、send と receive の間に別の request が割り込み、応答が messageId で多重分離されていないため
**取り違える**。

- **現状は安全**: 唯一の利用経路 `SMBClient.withSession` は 1 タスクが connect→操作→close を逐次
  実行し、セッション参照を他タスクへ渡さない。並行呼び出しが発生しない。
- codex Pass A (codex-lead, 2026-06-30) が「actor isolation ≠ critical section」を P2 として指摘。
  並行 consumer が存在しないため、投機的 serializer は作らず制約を doc 化する判断とした
  ([`pending-issue-rationale-in-code.md`] 準拠)。

## Trigger (この issue に着手する条件)

- **persistent / 共有 SMBSession を導入する時**。具体的には:
  - obaket 統合 (issue 356/359) で 1 接続を複数操作に跨って使い回す設計に進む
  - streaming read 中に別操作を並行実行したい要件が出る
  - 公開 API として長命セッションハンドルを露出する

## 対応

2026-06-30 に案 1 を採用。`SMBWireTransactionGate` を追加し、各 SMB request/response pair
(`sendUnsigned`/`sendSigned` → `receive`) を FIFO で直列化した。

- 同一 `SMBSession` に複数タスクが並行に wire 操作を呼んでも、2 つ目の request は 1 つ目の response
  処理完了後に送信される。
- 高レベル操作全体 (`copyFile` など) はロックしない。内部で複数 request/response pair を発行するため、
  operation 全体をロックすると再入で詰まる。直列化単位は wire transaction のみ。
- 真の SMB2 multi-flight ではない。messageId/credit demux は将来の性能要件が出たら別 issue で扱う。

追加テスト:

- `testConcurrentReadChunksSerializeWireTransactions`: 2 つの `readChunk` を同一 session へ並行投入し、
  1 つ目の response を返すまで 2 つ目の request が transport に送られないことを確認。

## 対応案 (記録)

1. **wire transaction の直列化 (serializer)**: send→receive を 1 トランザクション単位で直列化する
   actor 内ゲート (chained Task / async semaphore 等)。**安全だが真の並行性は得られない** (操作は
   逐次化)。実装は小〜中、ただし concurrency helper はバグを生みやすいので要慎重レビュー。
2. **MS-SMB2 の messageId/credit ベース応答多重分離**: 送信した request の messageId をキーに応答を
   demux し、複数 request を in-flight にできる。**真の並行**。credit 管理 (MS-SMB2 3.2.4.1.2) も必要。
   実装は大。SMB3 の本来の多重化に沿う。

現状の単純な「send 後に次の packet を receive」モデルは案 2 と非互換なので、案 2 採用時は receive 経路の
リファクタが要る。

## やらないこと

- messageId/credit ベース応答多重分離はまだ実装しない。現行は安全性優先の serializer。

## 完了条件

- [x] 案 1 or 2 を実装し、同一セッションへの並行 wire 操作で応答取り違えが起きないことを test で担保
  (複数 in-flight request を InMemoryTransport で多重化し、応答が正しい呼び出し元へ届くことを assert)。
- [x] actor SMBSession の「単一フライト前提」doc comment を更新 (制約解除を反映)。
- [x] todo.md 横断の該当行を同期。
