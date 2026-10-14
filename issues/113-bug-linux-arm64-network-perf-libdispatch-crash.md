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

- [ ] 同じ run の落ちた job を 1 回だけ回し直し、再び起きるかを見る（2026-10-14、ユーザー承認済み）
- [ ] 再び起きる / 別の run でも起きるなら: 手元の arm64 container で network 性能テストを繰り返して再現を試し、
  M1+M2 の前（c938d1a）と後（2d3923c）で起き方を比べる。timer の取り消しの数を観測する
- [ ] 起きないなら: 発生の記録として残し、次に起きたときに比べられるよう、この issue に run と commit を追記する

## 同じ時期の別の失敗（関係は未確認）

同じ commit（b1ce109）の Test workflow の `code-coverage` の job（Linux arm64）で、
`SMBClientCloseReconnectRaceTests.testTreeWireBarrierWaitsUntilFinalCreditGrantAcknowledgement` が開始 1.4 ms で `connectionClosed` を投げた
（run 38565152913）。手元の Linux arm64 のカバレッジ付きのビルドで単体 40 回・suite 3 回を回したが再現しなかった。こちらも同じ回し直しで様子を見る。
