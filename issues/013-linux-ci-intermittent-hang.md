# Linux CI の間欠ハング（demux/credit window 導入後）

- 種別: bug (CI blocker, 間欠)
- 発見: 2026-07-03。codex レビューは usage limit のため未実施 (要: 後日 codex-review)

## 観測事実

- master `Add SMB2 multi-flight response demux` (08dbcd6) の Test run 28601793534:
  `linux-build-test` が **10 分 timeout**（54 test case 開始後に無出力）、`code-coverage` も
  **15 分 timeout**。それ以前 (2026-07-02 04:51, 28566256583) は green。
- feature/smbclient-backlog run 28604385922: `linux-build-test` は完走したが
  `testClientSessionKeepAliveSendsPeriodicEchoUntilClose` が fail（期待 [echo, treeDisconnect,
  logoff] に **SMB2 CANCEL (12) が混入**）。`code-coverage` は同 run でも 15 分 timeout。
- macOS ローカルでは unit 5 連続 green（2026-07-03 実測）。Linux 固有・timing 依存。

## 分かっているメカニズム（部分）

- `close()` が keepalive task を cancel すると、in-flight ECHO transaction の
  cancellation handler が SMB2 CANCEL を送る（仕様通り）。CANCEL は messageId を 1 消費する
  ため、**それ以降の request の messageId が fixture (`InMemoryTransport` の pre-queued
  response の messageId) とずれる**。keyed demux では応答が orphan 化し、テストは
  接続 close (`receive` 空→ `connectionClosed` → failAll) まで進んで flake / 最悪ケースで
  応答待ちの直列化が乱れる。
- keepalive テスト自体の flake は 2026-07-03 に許容化済み（CANCEL を除外して assert）。
- hang の直接原因は未特定。候補: cancel 混入時の fixture messageId ずれで continuation が
  resume されない経路が残っている / `SMB2CreditWindow.reserve` 待ちが grant の来ない状態で
  永久 block（cancellation 非対応の待ち）。

## 追加観測 (2026-07-03)

- run 28605761487 では **macOS `build-test` も hang** (Build complete! 以降テスト出力ゼロで
  10 分 timeout、orphan に xctest + swift-package)。Linux 限定ではない。
- ローカル `LIBDISPATCH_COOPERATIVE_POOL_STRICT=1` での hang 再現は **別問題**
  (swift-test driver の build フェーズ / SwiftLint plugin × llbuild lane が semaphore 待ちで
  deadlock) であり、CI の「build 完了後・テスト出力ゼロ」hang とは一致しない。
- 対応 (観測強化): test.yml の macOS job は 480s で self-timeout して hung xctest を
  `sample` で stack dump、Linux job は `stdbuf -oL` で最後に開始した test 名が残るようにした。
  次に hang した run のログで真因を特定する。

## 次の観測手段（instrument-before-second-fix）

- CI (Linux) で `swift test --parallel` ではなく verbose + 各 test の timeout を付け、
  hang するテスト名を特定する（`SMBTestTimeoutError` の仕組みを session await 系の
  全テストに広げる）。
- `SMB2CreditWindow.reserve` に Task cancellation 対応（withTaskCancellationHandler で
  waiter を除去して CancellationError throw）を入れる — hang 原因でなくても正しい改善。

## 関連

- `issues/012-credit-window-followups.md`（credit window の設計残件）
- `issues/done/007-*`（過去の CI 10 分 hang → awaitWithTimeout 導入の経緯）
