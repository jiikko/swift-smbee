# 073 bug: POSIX transport の fd close と blocking syscall の間に fd 再利用 race がある（既存）

状態: **実装済み（残リスクあり）**
起票: 2026-07-29
関連: `Sources/SMBee/POSIXSocketTransport.swift`（terminal 遷移の close / `interruptBlockingIO`） /
`issues/done/072-bug-posix-transport-concurrent-send-interleave.md`（送信直列化。この issue はそのレビュー副産物）

## 問題

fd を「取得してから syscall に入るまで」および「blocked syscall が fd 値を握っている間」に、
別スレッドの close / cancellation / poison が fd を close すると、OS が同じ fd 番号を再利用した場合に
**無関係な socket / file への read/write になりうる**（典型的な fd-reuse TOCTOU）。

- **HEAD 時点から存在する**: 旧 `interruptBlockingIO` のコメントは「shutdown で起こしてから、
  その後 close() が実際の解放を行う」と主張するが、実装は shutdown 直後に close() を呼んでおり、
  blocked syscall の復帰を待っていない（コメントと実装の乖離）。
- issue 072 の直列化実装もこの構造を引き継いでいる（terminal 遷移が即 close する）。
  072 のレビューで「send は `beginWriterCall()` 成功後〜`writer(...)` 呼出の間に close が走ると
  再利用 fd に書く」と具体化された。receive / connect の後続 `fcntl` / `getsockopt` も同様。

## 発火条件

1. 同一 process が fd を高頻度に開閉している（fd 番号の再利用が速い）。
2. send / receive / connect が fd 値を取得した直後〜syscall 突入前（または blocked 中）に、
   cancellation / close() / poison が同じ fd を close する。
3. OS が直後に同じ番号を別リソースへ割り当てる。

再現確率は低いが、結果は「無関係な fd への書き込み」なので実害は大きい。

## 実装内容

- `connectionLock` 配下に descriptor ごとの lease record を追加した。record は lease count、
  retired、shutdown の要否、shutdown 試行完了、close claim を一体で管理する。
- terminal 遷移は state を即時に `.closed` / `.poisoned` にして descriptor を retire し、
  lock 外で `shutdown(SHUT_RDWR)` を試行する。physical close は
  `retired && leaseCount == 0 && shutdownAttemptCompleted && !closeClaimed` を lock 下で満たした側だけが
  claim し、lock 外で一度だけ実行する。
- send は `sendBlocking` 全体、receive は `receiveBlocking` 全体を lease で覆った。各 writer / reader
  呼び出しの直前に retired を再確認する。partial-write 後の writer failure は lease を保持したまま
  poison してから unwind する。
- connect 候補は install と同時に lease を取得し、promotion または retire まで保持する。promotion /
  connecting owner 除去 / retire / lease return / close claim は単一の atomic helper に集約した。
  `connect` / `fcntl` / `poll` / `getsockopt` / `setsockopt` の直前にも retired を再確認する。
- `close()` は「terminal 化と blocking I/O interrupt の開始」であり、lease drain や physical close 完了を
  待つ API ではないことを doc comment に明記した。

## テスト

- active send を fake writer 内で block し、cancel 後が shutdown 1 / close 0、writer 復帰後が close 1、
  その後の close / terminal operation でも lifecycle count が増えないイベント列を固定した。
- active send 中の明示 close 後、partial write の次の writer call に進まないテストを追加した。
  即時 close への退行と syscall 直前の retired 再確認削除をそれぞれ検出する。
- internal initializer に reader injection hook を追加し、receive cancellation でも同じ
  shutdown 1 / close 0 → reader 復帰 → close 1 のイベント列を固定した。
- 既存 connect / timeout / loopback テストは維持する。

## 残テスト

connect の決定論的 lifecycle テストは、socket / connect / fcntl / poll / getsockopt / setsockopt をまとめた
syscall bundle injection が必要になるため今回は見送った。候補 lease と atomic retire はコード構造で
強制しているが、Darwin / Linux 双方で blocking connect / poll を停止させ、terminal 遷移後の
shutdown 1 / close 0 → syscall 復帰 → close 1 と deferred `fcntl(F_SETFL)` を固定する integration test は残る。

## 残課題（未解決経路 1 件 + 残リスク）

- **[未解決経路・格上げ済み]** `timeout == nil` の blocking connect は、別 thread からの shutdown でも
  復帰しない可能性がある。当初「残リスク」としたが、**`POSIXSocketTransport()` の public initializer は
  timeout の既定が nil** なので、既定 API の通常経路であって edge case ではない（セクション別 codex
  レビュー 2026-07-29 で格上げ）。SMBee 内部と Obaket は timeout を渡すため実害は出ていない。
  **具体的な発火列**（敵対レビューで構築）: C1 が candidate を leaseCount=1 で install → C1 が
  `connect()` 内で停止 → C2 が terminal 遷移で retired=true → C2 は shutdown 試行完了を記録するが
  leaseCount=1 のため close claim 不成立 → C1 が復帰せず `finishConnectingCandidate` も走らない
  → **close が一度も claim されず descriptor が残る**。
  **対応案**: `timeout == nil` でも nonblocking connect + 短い poll と state 再確認の反復にして、
  terminal 後に必ず candidate lease を返せるようにする（今回スコープ外。connect の実装方式変更のため）。
- syscall が復帰しない場合、transport は terminal だが lease と descriptor を保持した zombie transport になる。
- **retired 判定と syscall の間の窓は意図的に残している**: `descriptorAllowsSyscall` は syscall と
  atomic ではないため、terminal 遷移直後に in-flight の syscall が 1 回だけ通り得る。lease が close を
  抑止しているので fd 再利用は起きず（= 本 issue の対象 race は防げている）、「shutdown 済みの同じ
  open-file description に届くだけ」で安全。厳密な atomic 化は blocking syscall を lock 下に置くことになり、
  その syscall を止めるべき terminal 遷移自体が deadlock する。コード側にも同旨のコメントあり。
- 現在の connect は逐次実行なので descriptor record を fd 値で識別している。将来 parallel connect を導入する
  場合は、fd 再利用を世代間で区別する `(generation, fd)` identity が必要になる。

done への移動は、残リスクと残テストを踏まえて人間が判断する。

## 優先度

P2。既存挙動であり 072 の修正では悪化していない。ただし 072 で構造（所有権・状態機械）が
整理されたので、直すなら今が最も安い。
