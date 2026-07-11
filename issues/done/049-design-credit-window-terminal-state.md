# 049 design: SMB2CreditWindow に terminal 状態が無く、生存性の不変条件が呼び出し側の規律に分散している

- 種別: design / concurrency robustness
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMB2Header.swift` (`SMB2CreditWindow`), `Sources/SMBee/SMBClient.swift`
  (`wireFailure` / `failWire` / `reserveCredit`), issues/010 §B, 2026-07-11 の credit deadlock 群 (3da1a41 / 5ffdec0)

## 問題

「credit の grant は受信応答からしか来ない。受信経路が死んだら、park 中および将来の reserve は
必ず fail する」という生存性の不変条件が、`SMB2CreditWindow` 自身ではなく呼び出し側
(SMBSession の `wireFailure` フラグ + `failWire` + `reserveCredit` 冒頭のチェック) に分散している。

このため次の理論的競合窓が残っている: `reserveCredit` が `wireFailure == nil` を確認した後、
`creditWindow.reserve` の waiter として park するまでの間に `failWire` →
`creditWindow.failAllWaiters` が走ると、その waiter は drain 対象に入らず永久 park する
(SMBSession actor と SMB2CreditWindow actor は別 actor なので順序保証がない)。

## 影響

- 発生確率は低いが、発生すると teardown / 後続リクエストが無限待ちになり、
  呼び出し側にタイムアウトが無い場合はプロセスが hang する。
- 「reserve する前に wireFailure を見る」という規律を新しい送信経路を書く人が忘れると再発する。

## 対応方針

1. `SMB2CreditWindow` に terminal 状態 (`private var failure: Error?`) を追加する。
   - `failAllWaiters(error)` が terminal をセットし、以後の `reserve` は park せず即 throw。
   - park 直前 (waiter 追加時) にも terminal を確認し、競合窓を actor 内で閉じる。
2. 再接続対応: `connect()` の成功経路でリセットする明示 API (`reset(initialCredits:)` 等) を追加し、
   window の残高・waiter・terminal をまとめて初期化する。SMBSession 側の `wireFailure` リセットと同じ場所で呼ぶ。
3. `reserveCredit` 冒頭の `wireFailure` チェックは送信そのものの fail-fast として残してよいが、
   生存性の保証は window 側で完結させる (呼び出し側規律への依存をなくす)。
4. unit regression test: reserve が park した状態で failAllWaiters → 以後の reserve が即 throw、
   reset 後は再び reserve できることを固定する。failAllWaiters の二重呼び出し、および
   reset と旧失敗イベント (遅延して届く failWire 由来の failAllWaiters) の競合もテスト対象にする。
5. terminal 判定は `failure: Error?` の nil 判定に頼らず、状態を明示的に扱う
   (例: `enum State { case active, failed(Error) }`) — reset との遷移を型で追えるようにする。
