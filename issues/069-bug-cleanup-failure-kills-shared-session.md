# 069 design: 単一 handle の cleanup 失敗が closeTransport で共有 session 全体を巻き添えにする

状態: **open（未修正バグではなく、cleanup 失敗時の session invalidation policy の再検討）**
起票: 2026-07-27（issue 067 A の敵対的レビューで検出、codex 反証レビューで位置づけを訂正）
関連: `Sources/SMBee/SMBClient.swift`（`SMBSession.bestEffortClose` / `closeTransport`） /
`issues/065-leak-cleanup-wire-operations-have-no-deadline.md`（状態 done・cleanup timeout はここで実装済み。本 issue はその timeout が効いた後の巻き添え範囲の話）

## 位置づけ（codex 反証レビューの結論）

現挙動は**意図的な設計**である: コードコメントに「FileId の寿命が不明な場合、session を再利用しては
ならない → shared transport を invalidate する」と明記されている。CLOSE の成否が分からない handle を
抱えたまま session を使い続けるのは安全でない、という判断自体は正しい。
本 issue が問うのは「その invalidation の**範囲**が、並行利用が前提になった今も適切か」だけ。

## 症状（未再現・レビュー由来の構造指摘）

`bestEffortClose` は CLOSE がタイムアウト・失敗すると `closeTransport()` に落ちる。
`closeTransport()` は transport を閉じ、同一 session の **全 pending response と credit waiter** を
`connectionClosed` で解決する。つまり 1 つの handle の後始末に失敗しただけで、並行して動いていた
無関係な list / read / write がすべて巻き添えで失敗する。

発火条件（構築されたシナリオ。実測はしていない）:

1. 同一 `SMBClientSession` 上で複数 operation が並行している（prefix read 4 並列 + list など）。
2. どれか 1 本が cancel / エラーで `bestEffortClose` に入る。
3. サーバが CLOSE に応答しない / cleanupTimeout（5s）を超える / credit 待ちになる。
4. `closeTransport()` が発火し、他の operation の pending / waiter が全部 `connectionClosed`。

「dead session を確実に畳む」ためのこの設計は単発 operation では妥当だが、issue 067 A で
同一 session 上の並行利用が前提になったため、誤爆コストが上がった。

## 対応候補

- 「共有 session を安全に再利用できる条件」を定義した上で、handle 単位の cleanup 失敗と
  session 全体の transport 障害を区別する（CLOSE 失敗 = handle を諦めるだけにできるのは
  どの条件下か、を先に言語化する。無条件の分離は現コメントの安全判断を壊す）。
- または consumer 側でサムネイル用 session を browsing 用と分離する
  （obaket `macOS/issues/437` の Phase 2 表にある「サムネ用の session を分ける」と同じ話。
  どちらで吸収するかは 437 側の設計と合わせて決める）。

## 先にやること

「CLOSE 無応答 → closeTransport → 並行 operation 全滅」を fixture（応答を返さない
InMemoryTransport）で再現する unit を書き、現挙動を固定してから対応方針を決める。
✅ 実施済み (2026-08-01、`testBestEffortCloseTimeoutFailsWireReadsAndCreditWaiter`)。固定した範囲:

- **実 wire operation の巻き添え**: 低レベル `readChunk`×2 + `write`×1 が production の
  encode → demux 登録 → credit reserve → send → response 待ち経路で pending の状態で、
  `bestEffortClose` の CLOSE timeout → `closeTransport` により全て `connectionClosed` で解放される。
- **credit waiter の巻き添え**: 実 `SMB2CreditWindow.reserve` に park した waiter（seam 経由）と、
  credit 枯渇で park した実 `queryDirectory` operation（外側 error = `connectionClosed`）の両方。
- fixture は command-aware（CLOSE のみ応答を破棄・ECHO は正常応答・READ/WRITE は応答を生成して hold）
  で、「blackhole ではない」ことを ECHO 往復でテスト自身が証明する。
- ミューテーション検証済み: failAllWaiters 削除 / 非 READ pending の取りこぼし / closeTransport 省略 /
  transport.close() 省略 / deadline 素通し、の 5 変異すべてをこのテストが検知する。

固定していない範囲（意図的な限定。invalidation 範囲の再検討時に必要なら拡張する）:

- public `list`/`read`/`write` facade の CREATE〜cleanup lifecycle 込みの巻き添え（低レベル層で代表）。
- 内部 credit continuation の解放元が `failAllWaiters` であることの直接証明（cancellation との競合で
  非決定。外側 operation の `connectionClosed` までを固定）。
- held response の「遅延配信」（サーバが後から READ に応答するケース）。fixture は生成 + hold まで。
- 早い旧 fixture (`testBestEffortCloseTimeoutClosesTransportAndFailsConcurrentPendingOperations`,
  人工 park 版) はそのまま残置。

## 2026-09-08 追記: CI で実際に発火した（構築シナリオではない観測）

issue [`done/080`](done/080-bug-ci-multiflight-connection-closed.md) の調査で、
**「症状（未再現・レビュー由来の構造指摘）」に書いた発火条件 1〜4 が CI で実際に起きていた**
ことが分かった。起票時は「実測はしていない」だったが、以後はそうではない。

観測: CI E2E run 31650773027（`f725bd6`）の
`testSharedSessionRangedReadsHaveMultipleWireResponsesInFlight` が 12.4 秒で `connectionClosed`。
失敗直前のログ順序:

```
1 MiB response ×3 を復号完了（1 MiB あたり 18〜26 秒かかっている）
SMB response direct-TCP header length=176        ← 復号後 124 byte。CLOSE response のサイズと整合
CANCEL request (68 bytes)
SMB response queued for future message id 76     ← 遅れて届いた応答が orphan 化
CANCEL request failed: connectionClosed
```

- 12.4 秒なので 60 秒の `defaultRequestTimeout` ではありえず、**5 秒級の cleanup deadline 系が最有力**。
- 発火条件 3（サーバが応答しない）は成立していない。**receive loop が 1 MiB の復号で塞がっていて
  CLOSE の応答を処理できなかった**だけで、wire もサーバも健全だった
  （同 run の Samba ログに `Terminating connection` は 0 件）。
  → 起票時の想定より**発火しやすい**: サーバ無応答だけでなく、
  **自分が重い処理で詰まっている**ときにも起きる。遅い実 NAS・大きな read の復号・
  モバイル回線でも成立しうる。
- 🚨 **未確定**: `SMBEE_PERF` が無効だったため `close_transport cause=` がログに無く、
  `bestEffortClose` / `closeCreatedHandle` / `bestEffortTreeDisconnect` /
  `disconnect` のどれが発火したかは確定していない。`SMBOperationDeadline` は hard deadline ではなく
  cancel 後に task 完了を待つので、5 秒ちょうどで閉じるとも限らない。
  **着手時にまず `SMBEE_PERF=1` の 1 run で cause と timer 発火時刻を確定させること。**

### 対応候補の具体化（上の「対応候補」の 1 つ目を割ったもの）

| 案 | 内容 | 前提・懸念 |
|---|---|---|
| A. tombstone drain + bounded quarantine | deadline 超過で transport を閉じず、その CLOSE を tombstone として残して drain する（[`done/062`](done/062-design-cancel-tears-down-shared-session.md) の機構の再利用） | **drop-in 再利用では足りない**: `bestEffortClose` は detached task の完了を await しており、tombstone 化だけでは await を解除できない。CLOSE の最終応答 / `STATUS_CANCELLED` / handle state unknown / tombstone 上限 / quarantine 中の新規操作の可否を全部定義する必要がある |
| B. soft deadline + session quarantine | 即 close せず quarantine 状態にして新規 admission を止める | 復帰条件が要る |
| C. cleanup の直列化 / 新規 operation の admission 停止 | cleanup 中は新規操作を受けない | 保持 session の応答性が落ちる |
| D. handle 生成時点から専用 session | cleanup が共有 wire を巻き込まない | 既存の「consumer 側で session を分ける」案と同根（obaket 437） |
| E. cleanup を別 actor / worker へ隔離 | 復号の負荷と cleanup の deadline を分離する | 実装が大きい |
| F. deadline を長く / 適応的に | 5 秒 → 30 秒等 | 閾値の付け替えで構造の是正ではない。A〜E が固まるまでの緩和 |

### 完了条件（追記）

対応を実装する場合、既存の回帰テストに加えて
**「receive loop が塞がっている間に cleanup CLOSE が deadline を超えても、同じ session の
他の in-flight 操作が失敗しない」**を決定論的に固定すること（fake clock か遅い transport の seam。
壁時計に依存させない）。併せて、issue 065 の「cleanup failure で transport を閉じる」不変条件が
どう変わったかを 065 の本文か API contract へ追記する。

## 関連

- `issues/done/065-leak-cleanup-wire-operations-have-no-deadline.md`（状態 done。cleanup timeout の実装。本 issue はその timeout が「効いたとき」の巻き添え範囲の話）
- [`done/080`](done/080-bug-ci-multiflight-connection-closed.md)（本 issue の発火を CI で観測した調査。2026-09-08 追記の出典）
- [`075`](075-perf-linux-aes-ccm-pure-swift-throughput.md)（CI で receive loop を塞いでいる throughput）
- obaket `macOS/issues/437`（session 分離で consumer 側に吸収する案）
