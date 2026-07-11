# 018 leak: wire transaction の pending continuation が cancel/close で残り得る

- 種別: bug / resource leak
- 起票: 2026-07-11
- 状態: open

## 症状 / リスク

`SMBSession.demuxedWireTransaction(...)` は `pendingResponses[messageId]` に `CheckedContinuation` を登録し、unstructured `Task` で send を行う。通常は receive loop が response を demux して continuation を resume するが、キャンセルや transport close のタイミングによって pending entry が残り得る。

特に long poll の `CHANGE_NOTIFY`、遅い read/write、サーバ無応答、明示 `SMBClientSession.close()` が重なると、呼び出し task が解放されず、`SMBSession` actor / transport / closure capture も延命する可能性がある。

## 根拠

該当箇所:

- `Sources/SMBee/SMBClient.swift`: `signedWireTransaction(...)`
- `Sources/SMBee/SMBClient.swift`: `signedLongPollWireTransaction(...)`
- `Sources/SMBee/SMBClient.swift`: `demuxedWireTransaction(...)`
- `Sources/SMBee/SMBClient.swift`: `closeTransport()`
- `Sources/SMBee/SMBClient.swift`: `receiveLoop()` / `failAllPendingResponses(...)`

現在の流れ:

1. `demuxedWireTransaction` が continuation を `pendingResponses` に登録する。
2. send は unstructured `Task` で行われる。
3. cancellation handler は `SMB2 CANCEL` を送るだけで、元の pending continuation を即時 fail しない。
4. `closeTransport()` は transport と credit waiters だけを閉じ、`pendingResponses` を直接 drain しない。
5. receive loop が動いていない、または close によって receive loop がエラーを拾う前の pending は、terminal event がないまま残る可能性がある。

## 修正方針

1. wire transaction cancel 時に、対応する `messageId` の pending continuation を必ず `CancellationError` で resume する。
2. long poll は `CANCEL` を best-effort で送ったうえで、client 側 continuation は即時解放する。サーバから後で response が来ても orphan/drop できる設計にする。
3. `closeTransport()` で actor 内の `pendingResponses` / `sentResponseMessageIds` / `orphanResponses` を同期的に drain する API を用意する。
4. unstructured send task が actor を延命し続けないよう、task lifecycle を session 側で追跡するか、transaction 全体を structured cancellation に寄せる。

## 受け入れ条件

- [ ] `CHANGE_NOTIFY` 待機中の task cancel で caller が即時 return し、pending continuation が残らない
- [ ] `SMBClientSession.close()` 中に in-flight read/write/change notify があっても全 pending が terminal resume される
- [ ] cancellation 後に遅延 response が届いても二重 resume しない
- [ ] continuation leak を検出する unit test / stress test を追加する

## リグレッションテスト

- 応答待ちの通常requestとCHANGE_NOTIFYをcancelし、taskが有限時間内に`CancellationError`で完了する。
- pending登録直後、send完了後、STATUS_PENDING受信後の各タイミングでcancelを注入する。
- transport close後にpending responseとcredit waiterが0になり、continuationが各1回だけresumeされる。
- cancelと正常応答を競合させるstress testを反復し、hangと二重resumeが発生しない。
