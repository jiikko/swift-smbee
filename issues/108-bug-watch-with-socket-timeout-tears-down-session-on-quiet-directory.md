# 108 (bug): 受信 timeout を持つ POSIX transport の session で、CHANGE_NOTIFY を待つ間に何も受信しないと session が落ちる

起票日: 2026-10-07

## 概要

`POSIXSocketTransport(timeout:)` は接続の後に `SO_RCVTIMEO` を設定するので、その後の recv のたびに `timeout` が効く
（`POSIXSocketTransport.swift` の `applySocketTimeoutIfNeeded`）。

CHANGE_NOTIFY は、変化が起きるまでサーバが最終応答を返さない long-poll の request である。
`withChangeNotifications` が応答を待つ間、session の reader は recv に入ったままになる。
その間に同じ接続で何も受信しないまま `timeout` が過ぎると、recv が `.timedOut` になって session が落ちる。

- issue 105 の 2 の調査で見つけた。issue 105 は M3 由来の idle の切断だけを扱って閉じた。
- SO_RCVTIMEO は `b87495a`（`POSIXSocketTransport: socket timeout + close-on-cancel`）から入っており、M3 より前の master の受信ループでも、
  応答待ちの間は同じ recv に入る。M3 が持ち込んだ退行ではない。

## 詳細（静的に追った経路。未実測）

1. `SMBClientSession.withChangeNotifications` が CHANGE_NOTIFY を送り、応答待ちになる。
   - CHANGE_NOTIFY は `longPoll: true` で、`requestTimeout` の対象外。socket の timeout を外す処理は無い。
2. 同じ接続で何も受信しないまま `timeout` が過ぎると、reader の recv が `SMBTransportError.timedOut` で失敗する。
   - 監視先に変化が無いことだけでは決まらない。同じ接続の他の応答・keepalive の ECHO の応答・CHANGE_NOTIFY の interim（`STATUS_PENDING`）を
     `timeout` より短い間隔で受信していれば recv は進む。サーバが interim を定期的に送るかは未確認。
3. reader の終了（`readerDidExit` → `terminateForReceiveFault`）で transport が閉じる。同じ session の pending はすべて失敗する
   （並行中の list / read / write も巻き添えになる）。
4. `autoReconnect: false`（既定）なら、`withChangeNotifications` はそのまま `.timedOut` を投げて終わる。
   - `autoReconnect: true` で再接続できる session なら、`.timedOut` は再接続できる失敗として扱われる（`isReconnectable`）。
     再接続に成功すると `reconnectAttempts` を 0 に戻し、`onChange(.overflow)` を呼んでから購読し直す。
   - 何も受信しない状態が続けば 1〜4 を繰り返し、そのたびに呼び出し側は全件の再走査を強いられる。周期は受信状況・再接続の時間・callback の時間に依存する。

影響する条件:
- 使う transport が受信 timeout を持つ POSIX transport であること。
  - `makeTransport` を渡すとそちらが優先され、公開引数の `timeout:` は transport に渡らない（`resolvedTransportFactory`）。
  - `timeout:` を指定しても `NWConnectionTransport` を使えばこの受信 timeout は無い。逆に factory が有限 timeout の POSIX transport を返せば、`timeout:` が無くても影響する。
  - 既定の transport は macOS でも POSIX。
- CHANGE_NOTIFY の応答待ちの間に、その接続で `timeout` より長く何も受信しないこと。

## 対応方針（未決定。公開 API の意味が変わる案があるのでユーザーの判断が要る）

公開 API の `timeout` は、doc で「connect と各 recv/send の timeout」と約束している。受信の上限を recv から外して
request 単位の `requestTimeout` に寄せると、この約束の意味が変わる（issue 105 の「直し方の候補」の 2 と同じ論点）。

候補:
- A. 受信の timeout を recv から外す。long-poll 以外の待ちの上限は `requestTimeout` に任せる。
- B. long-poll が outstanding の間だけ recv の timeout を外す。socket の option の出し入れになり、並行する他の request の受信にも効く。
- C. 挙動は変えず doc に書く。監視専用の session を `timeout: nil` で作って通常の操作の session と分ける回避策を案内する。
  - 通常の request は `requestTimeout`（既定 60 秒）で上限がかかり、公開 API の意味も変わらず、巻き添えも避けられる。
  - keepalive の ECHO で受信を起こす回避は、keepalive が開始時の session を捕捉していて再接続後の新しい session へ追従しないので、案内には使えない。

先にやること: loopback（`POSIXLoopbackTestSupport.swift` の `serveFrames`）で再現テストを書く。
- 条件: CHANGE_NOTIFY に interim も最終応答も返さない server、timeout 付きの POSIX transport。
- `autoReconnect: false` では `.timedOut` が返ること。`autoReconnect: true` で再接続できる session では、`.overflow` が繰り返されること。

## 関連ファイル

- `Sources/SMBee/POSIXSocketTransport.swift`（`applySocketTimeoutIfNeeded`）
- `Sources/SMBee/SMBClient.swift`（`SMBClientSession.withChangeNotifications` / `isReconnectable` / `resolvedTransportFactory` /
  `changeNotify` / `terminateForReceiveFault`）
- `Tests/SMBeeTests/SMBIdleReceiveTimeoutTests.swift`（idle の側の固定。issue 105）

## 進捗

- 2026-10-07: 起票。codex の反証レビュー（sol、read-only）で 5 件の指摘を受けて直した:
  - 自動再接続は `autoReconnect: true` のときだけ
  - 「変化が無い」は十分条件ではない（何も受信しないことが条件）
  - 影響条件は `timeout:` ではなく transport で決まる
  - 監視専用 session の回避策を足した
  - 関数名を `withChangeNotifications` に直した
  - 経路の中心（SO_RCVTIMEO → `.timedOut` → transport の終了）は反証されなかった
- [ ] 再現テスト
- [ ] 方針の決定（ユーザー）
