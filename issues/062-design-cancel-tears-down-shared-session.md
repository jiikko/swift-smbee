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

## 設計壁打ち結論 (codex D1、2026-07-17)

### 推奨: 案1 (session 所有 frame-safe I/O coordinator + 論理 cancel + tombstone drain) + 案2 の drain timeout を fallback

核心: **`Task.cancel()` を transport の `shutdown(fd)+close()` に直結させない**。

- `Task.cancel()` = **論理的な request cancellation** (この read だけ中断)
- `close()` / 明示 `abort()` = **物理的な socket teardown**
- 使い捨て session は cancel 後に明示 `abort()` してよい (owner の最適化)。**transport の共通契約から「cancel = socket 破壊」を除く**

#### cancel の流れ (案1)

1. request を actor 内で pending 登録
2. **frame 送信前** の cancel: frame を送らず pending 解放 + credit refund。SMB CANCEL は送らない
3. **frame 送信開始後** の cancel: send task は cancel せず frame 完走 → `wireSent` 確定 → caller の
   continuation は即 `CancellationError` で解放 → request は **tombstone として保持** → 同 MessageId の
   SMB CANCEL 送信
4. receiveLoop が元 request の最終 response を受信: `STATUS_PENDING` は捨てて tombstone 保持、
   最終 `STATUS_CANCELLED` (or 遅延通常 response) を捨てた時点で tombstone と `sentResponseMessageIds`
   を削除。**`STATUS_CANCELLED` は CANCEL request の応答ではなく、CANCEL 対象だった元 READ の最終応答**
5. credit: frame 送信済み request は cancel でも refund しない。response 受信時に grant 反映。tombstone の
   MessageId は再利用しない。**`markRequestSent` は必ず frame 完了後に実行** (send 後の checkCancellation で飛ばさない)

案2 (cancel barrier / quarantine) は初期安定化に有効だが、follow-up read が CANCEL response 待ちで
stall しうる (サーバが CANCEL response を遅延/欠落させると顕在)。→ 案1 を本命、案2 の drain timeout を
「サーバが CANCEL response を返さない場合の quarantine」fallback にする。

案3 (session lifetime で transport cancel policy を分ける) は transport に policy が漏れ、選び忘れで
再発。単体では frame 送信開始位置を判断できず不十分。

### 実装前に必ず観測する (instrument-before-second-fix)

アプローチ2 (状態機械) が unit 緑・E2E timeout だった差は「実 socket / 実 receiveLoop 特有」。実装前に
**MessageId 単位の状態遷移** (`registered → sendStarted → wireSent → cancelRequested → cancelSent →
drained`) と、E2E timeout 時の一括 dump (`pendingResponses / sentResponseMessageIds / orphanResponses /
receiveLoopRunning / wireFailure / credit balance・waiter / 各 send task phase`) を仕込み、**timeout の
停止地点**を確定させてから案1 を実装する。

最有力仮説: `transport.send` 完了 → `sendSigned` の `checkCancellation()` → `markRequestSent()` の窓で
send task が cancel されると、frame は socket に出たが `sentResponseMessageIds` に入らず receiveLoop が
起動/継続せず、response が orphan 化 → follow-up read も timeout。InMemoryTransport は window が極小で
unit だけ緑になる。

### 確定させる 5 前提 (MessageId 単位で観測)

1. Samba が cancel 対象 READ に必ず最終 `STATUS_CANCELLED` を返すか
2. E2E timeout の停止地点 = follow-up read の response 待ち or cancel 済み read の `Task.value` 待ち
3. アプローチ2 で partial send 後に `markRequestSent` が欠落していたか
4. `sendCancelWithoutGate` と通常 send が実 socket 上で並行していたか
5. cancel 対象 request の credit をいつ返しているか

### 次のマイルストーン

M-obs: reproducer に MessageId 単位の観測を仕込み、E2E で timeout の停止地点と 5 前提を確定 (実装は
main agent が container で回す)。→ M1: 確定結果に基づき案1 を実装 (tombstone drain)。→ 案2 drain
timeout を fallback で追加。全て reproducer (cancel-storm の skip 解除) と全 unit + smoke を oracle にする。

## 観測結果 (M-obs、2026-07-17) — 重要: container では再現しない

SMBEE_DEBUG=1 で MessageId 単位の状態遷移を仕込み、cancel-storm を container Samba
(smb302-encrypted-required) で観測した結果:

- 最初の reproducer は **バグを再現していなかった** (2 つの欠陥): (a) follow-up の nextOffset が
  ファイルサイズ (EOF) に到達し 0 byte read で assert 失敗、(b) localhost で read が速すぎて cancel が
  **chunk 境界で観測**され wire transaction 途中に当たらず、cancel 経路自体が発火していなかった。
- reproducer を obaket 忠実版 (64 MiB ファイル + 「offset..末尾」の大 range read + first chunk 直後
  cancel + offset は範囲内) に修正して再観測すると、cancel 経路は**発火した**:
  `cancelInFlightRequest id=N wasSent=true` → `failPendingResponse cancellingSendTask=true` →
  `completed cancelled SMB response message id N` (receiveLoop が cancel 済み READ の最終応答をドレイン)。
  **しかし `interruptBlockingIO` は 0 回、`connection-lost` も 0 回、テストは PASS**。

### 結論 (仮説の否定)

- 「cancel → sendTask.cancel → transport `interruptBlockingIO` (shutdown) で共有ソケット破壊」という
  **当初の root-cause 仮説は container では成立しない**。localhost では cancel 時点で READ 応答が
  ほぼ届いており (send は tiny で即完了 = `sendTask?.cancel()` は no-op)、receiveLoop が応答を
  クリーンにドレインして socket は整列したまま。→ **container Samba では obaket の実 NAS バグを再現できない**。
- 実 NAS の `connection-lost` は **latency 依存 / サーバ実装依存** (SMB CANCEL への応答タイミング、
  大 READ 応答のストリーミング中に次 READ を送る wire interleave 等) と考えられ、localhost では
  window が出ない。

### 次にやるべきこと (方針転換)

緑の local テストに案1 を盲目実装しても実バグを直す保証がない。**実 NAS の wire 挙動を捕まえる**のが先:

1. **実 NAS で観測**: SMBEE_DEBUG=1 相当の obs (MessageId 状態遷移 + interruptBlockingIO 呼び出し +
   receiveLoop 終了理由) を obaket に載せた debug ビルドで、ユーザーがスキップ連打を再現し、
   `connection-lost` が出る瞬間の wire ログを採取する。どこで socket が壊れるか (send 途中の
   sendTask.cancel か / SMB CANCEL と次 read の interleave か / 大 READ 応答の途中打ち切りか) を確定。
2. 確定後に案1 (tombstone drain) or 別対処を実装し、実 NAS で検証。
3. reproducer (`testSharedSessionRangedReadCancelStorm`) は container では PASS のまま active guard
   として残す (cancel 経路が socket を壊さないこと + Task.detached 退行の guard)。実 NAS 再現条件が
   分かれば、それを container で再現する profile (遅延注入 transport 等) の追加も検討。

### 暫定回避 (obaket 側、実 NAS 修正までのブリッジ)

obaket の SMB 動画スキップで「前の range read を即 cancel」する頻度を下げる緩和が有効な可能性:
debounce (スキップ確定まで cancel を遅らせる) / cancel せず現 read を最後まで走らせて次 range を
逐次化 / SMB provider だけスキップ時の即 cancel を抑制。本質修正ではないが体感スタールを消せる。

## 実 NAS 観測 #1 (2026-07-17、SMBEE_OBS062=1、健全時ベースライン)

ユーザーが実 NAS で後方シーク連打を実施 (obs 有効)。**バグは未発火** (connection-lost /
interruptBlockingIO とも 0 回) だが、健全時の挙動が確定した:

- `wasSent=true` の cancel → 後で `drained cancelled response id=N` — キャンセル済み READ の
  最終応答を receiveLoop が消費し、ソケット整列が維持される (現行コードの drain は実 NAS でも機能する)
- `wasSent=false` の cancel (送信前に cancel が勝つ) → wire に出る前に破棄。正常
- 再生は滑らか (「前みたいなカクカクしなくなった」)

**cancel storm は後方シークに集中する** (前方は read-ahead が食うため cancel 不要が多い —
`finish-ok via=read-ahead`)。ユーザー観察と一致。

→ バグは間欠 (昨日の connection-lost と同一コードで今日は出ない = NAS/ネットワーク状態依存)。
観測ビルド (obaket が SMBEE_OBS062 対応 smbee bd5cf64 に pin、`SMBEE_OBS062=1 make dev-fg`) を
維持し、**再発した瞬間の [obs062] + connection-lost 前後のログ**で真因 (送信途中 teardown or
drain 漏れ) を確定する。それまで修正実装はしない。
