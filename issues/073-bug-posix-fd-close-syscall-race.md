# 073 bug: POSIX transport の fd close と blocking syscall の間に fd 再利用 race がある（既存）

状態: **open（既存問題。issue 072 の敵対的レビュー round 2 で言語化。072 の修正は退行させていない）**
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

## 対応方針（案）

- terminal 遷移では **shutdown(SHUT_RDWR) のみ**行い（blocked syscall は確実にエラー復帰する）、
  **close は fd の lease / refcount が 0 になった時点で唯一の所有者が行う**。
- 072 で導入した「close 所有権の一元化」（connect 候補 fd）と同じ思想を、send/receive の
  syscall 期間にまで拡張する形。
- 検証: fake writer / lifecycle hook で「syscall 中に terminal 遷移 → close は syscall 復帰後に 1 回」を固定。

## 優先度

P2。既存挙動であり 072 の修正では悪化していない。ただし 072 で構造（所有権・状態機械）が
整理されたので、直すなら今が最も安い。
