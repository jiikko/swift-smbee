# 062 design: 保持 session 上の read cancel が session ごと破壊する — 設計見直し

- 種別: design (bug の構造的原因究明 + 修正設計)
- 優先度: 高 (obaket の SMB 動画プレビューでスキップ連打 → connection-lost + 数秒スタール。実利用で顕在)
- 状態: **設計見直し中**。実装は 2 アプローチ失敗済み (下記)、reproducer 確立済み

## 症状

保持した (long-lived / 共有) `SMBClient` session インスタンス上で `withReadStream(path:range:)`
による range streaming read を実行中に、その **read の Task を cancel すると session 全体が
`connection-lost` で壊れ**、次の操作が失敗する。

- obaket: SMB 動画プレビューを ←→ で高速スキップ → 各スキップが前の range loader を cancel →
  `[smb-session] discarded reason=connection-lost` → 再接続で数秒スタール。
- 使い捨て session (static `SMBee.withReadStream` 等) では session を捨てるので無害。**保持
  session 特有**。

## reproducer (確立済み)

`Tests/SMBeeTests/SMBeeSharedSessionRangedReadE2ETests.swift`:

- `testSharedSessionRepeatedRangedStreamingRead` (cancel なし、保持 session で range read ×10)
  → **PASS**。「通常再生」の退行ガード (下記アプローチ 1 の regression をこれが捕まえる)。
- `testSharedSessionRangedReadCancelStorm` (保持 session で range read を最初の chunk 後に
  cancel → 即別 offset を read、を ×10、最後に cancel なし read が成功するか)
  → **現状 FAIL (30s timeout)**。バグ本体。修正が入るまで `XCTSkip`。skip を外して緑化 = 修正完了。

container Samba E2E (`SMBEE_E2E=1`, `bin/e2e/container-samba.sh`) で再現。

## 根本原因 (調査結果)

- `POSIXSocketTransport.receive/send` は `withTaskCancellationHandler { } onCancel: { interruptBlockingIO() }`。
  `interruptBlockingIO` は `shutdown(fd)` + `close()` = **ソケットごと破棄**。
- caller の read Task を cancel すると、この onCancel 経由 (または送受 Task の cancel 伝播) で
  **共有ソケットが frame 途中で shutdown** され、session が死ぬ。使い捨て session なら無害だが
  保持 session では致命。
- SMB 本来の正しい振る舞い: in-flight READ に **SMB CANCEL** を送り、その応答 (STATUS_CANCELLED 等)
  を receiveLoop が消費して **ソケットを frame 境界で整列**させてから session を再利用可能にする。
  `signedWireTransaction` には onCancel で `sendCancelWithoutGate` する経路が既にあるが、これだけでは
  ソケット整列/drain が完結していない (or transport shutdown が先に走る)。

## 失敗したアプローチ (繰り返さない)

1. **DirectTCPFraming.send/receive を `Task.detached` でラップして frame-safe 化** (revert 済み,
   commit 812c4bf → revert 32664d2)。cancel なしの通常再生まで壊した (READ 応答が来ず 15s timeout)。
   detached が actor の直列化 / receiveLoop 駆動を壊した疑い。→ **wire I/O を detached でラップしない**。
2. **pendingResponse に cancellationRequested/cancelSent/sendStarted の状態機械を足し、frame 開始後の
   send task は cancel せず継続を即 CancellationError で解放しつつ response を drain** する案。
   unit は緑だが cancel-storm E2E は依然 FAIL (30s timeout)。drain が実際には効いていない or
   別経路で socket が壊れている。→ 状態機械だけでは不足。より下 (transport の cancel 契約) の見直しが要る。

## 設計で詰めるべき論点

- transport の cancel 契約: 「read を cancel = socket を殺す」を「read を cancel = この read だけ
  やめる。socket は frame 境界まで整列させて session は生かす」に変える。保持 session と使い捨て
  session で transport の cancel 挙動を分けるか、常に frame-safe にするか。
- SMB CANCEL 送信 → STATUS_CANCELLED 応答の drain を receiveLoop で確実に消費する経路の完成。
- credit / messageId 会計が cancel + follow-up read のレースで壊れないこと。
- 使い捨て session の既存挙動・全 unit test を壊さないこと。

## 暫定回避 (obaket 側)

構造修正が入るまで、obaket の SMB では「スキップ連打で前の range read を即 cancel」を避ける緩和も
検討可 (例: cancel せず現 chunk を捨てて次 range を張る / debounce)。ただし本質は smbee 側の
transport cancel 契約なので、恒久対処は本 issue で行う。
