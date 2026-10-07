# 105 (risk): M3 の常駐 reader が idle 中に POSIX の blocking recv で pool のスレッドを占有し、SO_RCVTIMEO で idle な session を閉じる

起票日: 2026-10-03

## 概要

issue 010 の M3 (session が持つ常駐 reader。commit 136268a、master では revert 済み) を入れ直す前に、
forge の調査 (10 体 + cross-review、2026-10-03) が正しさの懸念を 2 件挙げた。どちらもコードを読んで出した推論で、**未実測**。
M3 の入れ直しの前提条件にするかは、下の再現テストで実在を確かめてから決める。

## 詳細

### 1. idle の reader が cooperative pool のスレッドを占有し続ける

- 経路: `POSIXSocketTransport.receive` は、`receiveBlocking` (blocking recv) を `Task.detached` で待つ。
  M3 の常駐 reader は、応答を待っていない idle の間もこの receive に入ったままになる。
- master は応答を待っている間だけこの形で占有する。M3 はその時間を、最初の完全送信の後から session の終了まで延ばす
  (`runRawReader` は pending の数を見ずに次の frame を読む。未送信の session は reader を起動しない)。
- 想定する失敗: idle な session が CPU 数以上あると、cooperative pool のスレッドが blocking recv で埋まり、
  他の session や Task が進まなくなる (hang)。既定の transport なので macOS も対象。
- 再現テストの案: Linux で idle session を CPU 数 + 1 本以上開いたまま、別の session の request が完了するかを見る。
  - 🚨 期限の監視を同じ cooperative pool の上に置かない。既存の `awaitWithTimeout` は watchdog も `Task` + `Task.sleep` なので、
    pool が埋まると timeout の処理自体が走らない。**別プロセスで再現し、親プロセスから期限を監視する**。
  - 「返らない recv」の fake は、試験の終わりに解除できないと後続のテストを巻き込む。これも別プロセスに閉じ込める。
  - 全 reader が blocking recv に入ったことを確かめられない試験の成功は、反証にならない。
- 直し方の候補: 待ちを pool の外へ出す。
  - recv を nonblocking にするだけでは、同じ `Task.detached` の中で poll/epoll_wait を待てば待つ場所が移るだけ。
    専用のイベント待ちスレッドか、readiness の通知で continuation を再開する形まで要る。
  - 既存の選択肢として、`makeTransport` で選べる `NWConnectionTransport.receive` (callback + continuation。macOS のみ) がある。
    既定の transport 全体の解決にはならない。
  - 現状でも receive の呼び出しごとに detached Task を作っている (frame は header と body を別に受信する)。移した後の起床の回数は
    通知の単位・buffering・executor で変わるので、実装した後に scheduling のコストを測って比べる。

### 2. SO_RCVTIMEO で、timeout を指定した idle な session が閉じられる

- 経路: `POSIXSocketTransport` の `applySocketTimeoutIfNeeded` → recv の EAGAIN が `.timedOut` になる
  → M3 の `readerDidExit` → `terminateForReceiveFault`。
- `timeout` の既定値は nil なので、影響するのは timeout を指定した利用者に限られる。
- 同じ根の問題は master にもある。timeout より長い long-poll (CHANGE_NOTIFY 等) が outstanding の間も `.timedOut` になる。
- 再現テストの案: loopback を使い、「timeout より長く idle にした後の request が成功する」ことを確かめる。
  - 既存の `POSIXSocketSyscalls` は接続用の境界で、recv の注入点は持たない。EAGAIN を注入するなら `POSIXSocketReader` の closure で
    errno を設定して -1 を返す。ただし注入だけでは、本物の `SO_RCVTIMEO` で起きることまでは確かめられない。
- 直し方の候補: 受信 timeout を recv から外し、待ちの上限を request 単位の `requestTimeout` に寄せる。
  - 🚨 公開 API の `timeout` は「connect と各 recv/send の timeout」と明記されている。外すと API の意味が変わる。
    `requestTimeout` は既定 60 秒で、完全送信の後に始まり、long-poll・blocking lock・named-pipe の read/transceive は対象外なので、
    `timeout: 1 秒` の利用者の受信上限をそのまま置き換えるものではない。意味の変更・対象外の操作の待ち方・ドキュメントと既存テストの
    変更を対応範囲に含める。
  - SO_RCVTIMEO は TCP connect の**完了後**に設定され、connect 自体は別の deadline + poll で制御されている。
    「connect / handshake に限る」はそのままでは実装の方針にならない。
  - 「`.sent` が無ければ再試行」案は採らない。frame の途中 (header は読み終えて body を待っている状態) の扱いが未定義で、check-then-act の窓もある。

## 対応方針

1. M3 の性能修正 (issue 010 の F1 以降) とは別の commit で、上の再現テストを M3 の worktree に書いて実在を確かめる。
2. 実在したら M3 の入れ直しの前提条件にする。単一の条件で再現しなかったことだけでは閉じない
   (全 reader が recv に入ったことを確かめたうえでの結果を書く)。
3. issue 010 で需要駆動 reader (pending が 0 なら reader を止め、次の send で起こし直す) を採れば、idle 中に recv しないので
   1・2 とも副次的に消える。その場合は 010 の決定をここへ書いて閉じる。

## 関連ファイル

- `Sources/SMBee/POSIXSocketTransport.swift` (`receive` / `receiveBlocking` / `applySocketTimeoutIfNeeded`)
- `Sources/SMBee/SMBClient.swift` (M3 の `startReaderIfNeeded` / `runRawReader` / `readerDidExit`。M3 の worktree 側)
- issue 010 (M3 の入れ直し)

## 進捗

- 2026-10-03: issue 010 で需要駆動の reader を採ることにした（pending が 0 なら reader を止め、次の send で起こし直す。
  master の `receiveLoop` と同じ idle の挙動）。
  - 1（idle 中の pool の占有）は、idle 中に recv しなくなるので消える見込み。実装の後に確かめる。
  - 2（SO_RCVTIMEO）は、idle 中の切断は消えて master と同じ状態に戻る。long-poll が outstanding の間に `.timedOut` になる根は
    master にもあり、残る。

- 2026-10-05: 需要駆動の reader（受信ループは session actor 上で、応答待ちがある間だけ動く）は M3 の入れ直し（b809c9b）で master に入った。
  - idle 中は transport.receive に入らない。docs/architecture.md の「session の reader」節にも書いた。
  - 1 は構造上は起きない見込みだが、再現テストで確かめてはいない。
  - 2 の idle 中の切断は起きない（idle 中に受信しない）。long-poll 中の `.timedOut` は master と同じで残る。
- [x] 1 の再現テスト（需要駆動の reader の下で、idle の session が pool のスレッドを占有しないことの確認）
  - 既存の `SMBeeTests.testSessionReaderStartsAfterEachFullSendAndStopsWhenNoResponseIsOutstanding` が、idle 中に transport.receive を
    新しく呼ばないこと（receiveCount が増えない）と reader task が 0 本になることを固定している。
    `POSIXSocketTransport.receive` は呼ばれたときだけ detached task で blocking recv するので、receive を呼ばなければ pool のスレッドは塞がらない。
  - 2026-10-07 に変異で確かめた: `runActorRawReader` と `processRawFrame` の `guard hasSentResponseOutstanding` を常に偽にする
    （応答待ちが無くても読み続ける = revert した常駐 reader の形）と、このテストは red（`reader exits when the final response is dispatched` の待ちが timeout）。
  - pool を実際に埋める別プロセスの試験は書いていない。上の固定で「idle の session は recv を持たない」が言えるので、pool の飽和を作る試験は要らないと判断した。
- [x] 2 の再現テスト
  - commit `test(session): issue 105 — SO_RCVTIMEO より長く idle にした session が次の request を処理できることを本物の socket で固定する`。
    `SMBIdleReceiveTimeoutTests`: 本物の POSIX socket（loopback）で `timeout: 100 ms` の session に ECHO → 400 ms idle → ECHO が成功する。
  - 同じ変異で red（`timedOut`）。macOS swift test 652 件（skip 37）失敗 0、新しいテストは 3 回連続 green。
- [x] 扱いの決定（2026-10-07）
  - 1 と 2 の idle の切断は、需要駆動の reader（M3 の入れ直し）で起きなくなり、上のテストで固定した。この issue は閉じる。
  - long-poll（CHANGE_NOTIFY）が outstanding の間の `.timedOut` は M3 より前からある既存の問題なので、[`108`](../108-bug-watch-with-socket-timeout-tears-down-session-on-quiet-directory.md) に切り出した。
    `watch` を `timeout:` 付きで使うと、変化の無いディレクトリで timeout ごとに session が落ちて再接続と `.overflow` が起きる。
