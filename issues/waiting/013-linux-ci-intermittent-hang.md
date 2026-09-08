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
- ✅ 2026-07-03: `SMB2CreditWindow.reserve` の Task cancellation 対応を実装（waiter 除去 +
  CancellationError throw、unit coverage あり）。hang 再発時はこの経路を容疑から除外できる。

## 関連

- `issues/012-credit-window-followups.md`（credit window の設計残件）
- `issues/done/007-*`（過去の CI 10 分 hang → awaitWithTimeout 導入の経緯）

## 全数勘定 (2026-09-08) — アーカイブログから確定した事実

**新しい CI run を 1 回も回さずに、GHA のアーカイブログから全数を洗った**
（グローバルルール `instrument-before-second-fix.md`「CI でしか出ない不具合は、新しい run を
取る前に既存の失敗 run のログを全部取る」）。retention は 90 日で、対象は経過 67〜69 日だった。
**ログは手元に落としてあるので、以降 retention の期限は無い**（`tmp/` は gitignore なので
本表が保全の実体）。

### hang クラスの job は 8 件。すべて 2026-07-01〜07-02 に集中している

判定基準は「失敗 job の実行時間が step timeout (10 分 / 15 分) に達している」。

| run | job | 最後に started して結果が出ていないテスト | 無出力 |
|---|---|---|---:|
| 28608702243 | code-coverage | `testChangeNotifyCancellationSendsSMB2Cancel` | 786.8s |
| 28604385922 | code-coverage | `testChangeNotifyCancellationSendsSMB2Cancel` | 801.3s |
| 28605761487 | code-coverage | `testChangeNotifyCancellationSendsSMB2Cancel` | 791.1s |
| 28601793534 | code-coverage | `testChangeNotifyEventConvenienceProperties` | 791.7s |
| 28601793534 | linux-build-test | `testChangeNotifyEventConvenienceProperties` | 585.7s |
| 28491898150 | linux-build-test / Swift 6.0 | **テスト行なし**（`Build complete!` の後ゼロ） | 596.9s |
| 28494248126 | linux-build-test / Swift 6.0 | **テスト行なし** | 597.0s |
| 28605761487 | **build-test (macOS)** | **テスト行なし** | 583.6s |

### ここから言えること / 言えないこと

- **単一の停止点は無い**。3 群（cancellation テスト 3 / convenience テスト 2 / テスト行なし 3）に割れる。
- 🚨 **「最後に出た行 = hang 点」とは言えない**。対象 8 job はいずれも `stdbuf` を通しておらず
  （観測強化は 2026-07-03 に入れた）、後続テストの出力がバッファに残った可能性を排除できない。
  確定して言えるのは「その行が最後に現れ、timeout まで結果行が現れなかった」までで、
  幅は **583.6〜801.3 秒**ある。
- **「テスト行なし」の 3 件は別の形**。`Build complete!` の後にテストケース行が 1 つも出ない。
  本 issue が既に記録している「swift-test driver の build フェーズ / SwiftLint plugin × llbuild の
  semaphore deadlock」と同じ形の可能性がある（未確認）。macOS の `build-test` もこの群。

### 2 つの仮説はどちらも支持されなかった

- **issue 010 の主仮説 A**（`testConcurrentReadChunksDemuxOutOfOrderResponses` が犯人）:
  run 28601793534 の Linux 2 job は**そのテストに到達していない**（実行はアルファベット順で
  `ChangeNotify…` < `ConcurrentRead…`）。同じ run の macOS job では当該テストが後で実行されて
  **pass している**。
- **「直前の cancellation テストが session をリークさせる」仮説**（2026-09-08 に Claude が立てた）:
  **誤り**。`testChangeNotifyCancellationSendsSMB2Cancel` は `cancel()` の後に
  `STATUS_CANCELLED` 応答を注入し、`awaitWithTimeout` 越しに `task.value` を await して
  `CancellationError` を確認している（`SMBeeTests.swift:5678-5694`）。Task も session も残らない。
  さらに parked な continuation は worker thread を保持しないので、
  「executor を枯渇させて次のテストを止める」機構も成立しない。

### 2026-07-03 以降は再発していない

`Test` workflow の直近 200 run（2026-07-02〜09-08）で、**step timeout に達した失敗 job は 1 件だけ**
（2026-07-29 の `linux-asan`, 970s）。しかもそれは
`SMBWireDiagnosticsTests.testCloseCauseAndVictimSnapshotAreLogged` が**失敗した後**に 13 分無出力
という**別 signature** で、本 issue の「テスト出力ゼロで無言に止まる」とは形が違う。

**ただし非再発は修正の証拠ではない**。2026-07-03 の対応（demux テストの順序非依存化 /
`awaitWithTimeout` の作り直し / credit waiter の cancellation 対応）と 2026-08 の
request timeout 既定化のどれが効いたのか、あるいはタイミングが変わっただけなのかは未確定。

## 派生して見つかった潜在バグ

`ControlledReceiveTransport.receive(maxLength:)`（`SMBeeTests.swift:1068` の test double）は
continuation を `pending` に保存するだけで **cancellation handler を持たない**。最終応答を
注入しないテストを書くと receive continuation が永久 pending になる。既存テストは応答を
注入しているので現状は発火しないが、次にこの double を使う人が踏む。

## 状態: waiting（再現待ち）

真因は**未確定**のまま。こちらから起こせる観測はアーカイブから取り切ったので、
`issues/waiting/` へ移す。

- **待っているもの**: 同じ signature の hang の再発（`stdbuf` と macOS の `sample` による
  観測強化は 2026-07-03 に入っているので、次に出たら停止位置とスタックが取れる）
- **それが来たとき何が分かるか**: バッファリング由来の曖昧さが消えて停止テストが確定する。
  macOS 側なら `sample` のスタックで、待っているのが continuation か lock か semaphore かが分かる
- **待たずに進める道**: issue 010 §修正方針 1（session 所有の single reader）は
  hang の原因が何であれ**構造上のデッドロック B を潰す**ので、再現を待たずに着手できる
