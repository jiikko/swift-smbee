# 113 (bug): Linux arm64 の network 性能テストが libdispatch の event loop で SIGSEGV になった（1 回観測）

起票日: 2026-10-14

## 概要

CI の Performance workflow の `samba-network-performance` の job（Linux arm64、`ubuntu-24.04-arm`）で、
実 Samba を相手にした `swift test -c release --filter SMBeeNetworkPerformanceE2ETests` のプロセスが crash した。
計測の出力（`PERF_NETWORK`）が 0 件になり、後段の summary の step が「expected read/write PERF_NETWORK summaries, found 0」で落ちた。

- run: https://github.com/jiikko/swift-smbee/actions/runs/38565152867 （commit b1ce109。テストだけの変更で、production は 2d3923c と同じ）
- 起きた日: 2026-10-14

```
*** Signal 11: Backtracing from 0xffba7652cdf0... done ***
*** Program crashed: Bad pointer dereference at 0x0000000000000022 ***
Platform: arm64 Linux (Ubuntu 24.04.5 LTS)
Thread 0 crashed:
  0      0x0000ffba7652cdf0 _dispatch_event_loop_drain + 1216 in libdispatch.so
  1 [ra] 0x0000ffba76521e38 _dispatch_mgr_invoke + 123 in libdispatch.so
  2 [ra] 0x0000ffba76521dac _dispatch_mgr_thread + 131 in libdispatch.so
  3 [ra] 0x0000ffba76525118 _dispatch_worker_thread + 431 in libdispatch.so
  4 [ra] 0x0000ffba74f6582c <unknown> in libc.so.6
```

## 分かっていること

- 落ちたのは libdispatch の manager thread（epoll の event loop）。SMBee は DispatchSource を直接使っていない
  （`grep -n "DispatchSource\|makeReadSource" Sources/SMBee/*.swift` で 0 件、2026-10-14）。
  この thread で動くのは主に Swift Concurrency の timer（`Task.sleep` の待ち）なので、timer の登録と取り消しが絡む可能性がある
- arm64 に移してから（issue 112）、この job は 643c50b・6af8706・c938d1a・2d3923c の 4 回とも通っていた。今回が初めて
- 直前の 2d3923c（issue 106 Commit 5 の M1+M2 を入れ直した commit。production のコードは今回と同じ）では通っている
- SMBee の欠陥か、Linux arm64 の libdispatch（Swift 6.2.4 の runtime）の不具合かは、1 回の観測では決められない

## 次にやること

- [x] 同じ run の落ちた job を 1 回だけ回し直した（2026-10-14、ユーザー承認済み）。`samba-network-performance` も `code-coverage` も success で、どちらも再現しなかった
- [x] 調査した（2026-10-16）。結論は下の「調査の結果」

- 2026-10-16: issue 106 は done へ移った（M3・M4 も master に入り、その後の CI で network 性能テストは 3 回とも通った）。この issue は発生の記録として継続

## 調査の結果（2026-10-16）

**結論: crash したのは SMBee のテストのプロセスではなく、テストのビルドを始める前の SwiftPM の道具（`swift test` そのもの。Swift 6.2.4、Linux arm64）。SMBee のコードは動いていない。**

- 根拠（ログの順序）: 成功した run（例: 5d34f7f の Performance、run 38804287433）では、`+ swift test -c release ...` の直後に
  `[1/1] Compiling plugin SwiftLintCommandPlugin` → `Building for production...` → SMBee のコンパイル → テストの出力が続く。
  crash した run では、`+ swift test ...` の直後、plugin のコンパイルの 1 行も出る前に crash している（テストの出力 `Test Suite` も 0 行）。
  テストのバイナリが作られる前なので、SMBee の timer・executor・transport は関係しない。
  ただし backtrace の image の一覧は 73 件が省略されていて、落ちたプログラムの名前そのものは出ていない（推定の根拠は出力の順序だけ）
- 発生の頻度: arm64 に移してから（643c50b 以降）の CI の run 29 本（Test / E2E / Performance。各 run の最新の試行のログ）を
  `Program crashed|Signal 11|Fatal error|Backtracing from` で走査して 0 件。crash は b1ce109 の Performance の最初の試行の 1 回だけ
- 手元の再現: Apple container の Linux arm64（指定の swift:6.2 の digest、4G）から Samba（SMB 3.0.2 暗号化必須）の container へ、
  同じ `swift test -c release --filter SMBeeNetworkPerformanceE2ETests` を 30 回（1 回目はビルドから、以降は `--skip-build`）。30 回とも pass、crash 0
- SMBee は DispatchSource を直接使っていない（`SMBSessionExecutor` は DispatchQueue の上の serial executor）。既知の不具合の検索
  （`_dispatch_event_loop_drain` × Linux aarch64）では同じ形は見つからなかった

**扱い**: SMBee の側で直すものは無いので done へ移す。

**再開の trigger**: CI か手元で同じ backtrace（`_dispatch_event_loop_drain` の SIGSEGV）がまた出たとき。そのときは、crash の直前の行を見て
**テストの出力（`Test Suite` / `PERF_NETWORK`）が出た後か前か**を最初に確かめる。出た後なら SMBee のプロセスなので、この issue を開き直して
M1+M2 の前（c938d1a）と後で起き方を比べる。出る前なら SwiftPM の道具の不具合として、Swift の版と一緒に記録する（頻発するなら CI の toolchain の版を上げることを検討する）

## 同じ時期の別の失敗（関係は未確認）

同じ commit（b1ce109）の Test workflow の `code-coverage` の job（Linux arm64）で、
`SMBClientCloseReconnectRaceTests.testTreeWireBarrierWaitsUntilFinalCreditGrantAcknowledgement` が開始 1.4 ms で `connectionClosed` を投げた
（run 38565152913）。手元の Linux arm64 のカバレッジ付きのビルドで単体 40 回・suite 3 回を回したが再現しなかった。こちらも同じ回し直しで様子を見る。
