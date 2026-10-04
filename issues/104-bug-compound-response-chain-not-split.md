# 104 (bug): 1 つの Direct-TCP frame にまとめた compound 応答を分割せず、2 つ目以降の応答と credit を捨てる

起票日: 2026-10-02

## 概要

受信経路は 1 つの Direct-TCP body を 1 つの SMB2 応答として扱い、`SMB2Header.nextCommand` を decode しても
応答の chain を分割しない。サーバが複数の応答を 1 frame に compound して返すと、先頭以外の応答が demux されず、
その credit も grant されず、署名も body 全体に対して検証されて正しい署名を拒否する。

[MS-SMB2 §3.2.5.1.9](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fe53ff-72c2-4065-a39f-29805a996a5f)
は、client が送信を compound にしたかどうかに関係なく、応答の chain を分割して順に処理することを要求する。
SMBee は送信を compound にしていないが、それは免責にならない。

issue 010 M3（session が所有する常駐 reader）の敵対レビュー（2026-10-02、観点 2）で見つかった。
master の eaf5ea4 にも同じ欠陥があり、M3 が持ち込んだ退行ではない。

## 再現（レビュワーの worktree 外の probe）

1. balance=2、requestTimeout=nil。ECHO A と B を別々に full send する（両方 `.sent`、balance=0）
2. サーバが 1 つの Direct-TCP body に A の応答（NextCommand=72、68 bytes + 4 bytes の padding）と
   B の応答（NextCommand=0）を連結し、それぞれ CreditResponse=1 で返す
3. 観測: `first completed; pending=1 balance=1`（期待は pending=0 balance=2）。B は応答が来ないまま待ち、
   requestTimeout が nil なら無期限、有限なら健全な wire を timeout で閉じる
4. 署名あり: 各応答を（padding を含めて）正しく署名し、単独で検証に渡すと通る。連結すると A の検証が
   body 全体で署名を計算し `SMB signature verification failed` になる
5. AEAD の transform で包んだ compound も、復号の後に同じ分割漏れへ入る（静的判定、未実行）

実サーバでこの形を観測したことはまだない。[MS-SMB2 §6 Appendix A の注記 235・237](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a64e55aa-1152-48e4-8206-edd96444e7f7)
によると、Windows のサーバは compound の request に対してだけ compound の応答を返し、credit は chain の最後にまとめて付ける。
SMBee は送信を compound にしないので、**記載どおりの Windows では上の再現は起きない**。仕様（§3.3.4.1.3 はサーバが
compound にすることを許す）には反するので潜在的な互換性の不具合として残すが、重要度は P2 扱い。Samba での到達条件は未確認。

## 対応方針

- AEAD の復号の後で、NextCommand の進み方・範囲・8 byte の alignment・最低 header 長を検証して個別の応答に分割する。
  不正な chain は黙って捨てず wire fault にする
- 各 slice について credit の grant を 1 回 → generation の再照合 → `.sent` gate / demux を wire の順に行う。
  署名は slice ごと（規定の padding を含む）に検証する。ただし [§3.2.5.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/36172e53-ac81-48fb-b2e3-caa3761b9157)
  の例外（復号に成功したもの・MessageId が UInt64.max・STATUS_PENDING の interim）は slice ごとにも維持する
- 応答の保存（master は MessageId をキーにした辞書で、満杯で最小の MessageId を捨てる。M3 では到着順の FIFO）の
  上限は、body の数ではなく保存した個別の応答の数で数える
- テスト: 2 つの `.sent` の record を 1 つの compound で完了させるケース、片方が `.sending` の混合、
  署名ありの compound、compound の中で interim と final が混ざるケース、不正な NextCommand（範囲外・非 alignment・後退）の拒否

## 関連ファイル

- `Sources/SMBee/SMBClient.swift` — master では `receiveDecryptedFrame` → `receiveLoop` → `dispatchReceivedPacket`、
  `recordCreditGrant`、`verifySigned`（M3 では `processRawFrame` が raw frame の処理を受け持つ）
- `Sources/SMBee/SMB2Header.swift` — `nextCommand` の decode
- issue 010 の M3 が受信の中心を作り直すので、M3 が master に入ってからその上で直す

## 進捗

- [ ] 実サーバが compound 応答を返す条件を調べる（Samba の設定・Windows の挙動）
- [x] 分割の実装とテスト（issue 106 の Commit 2。slice ごとの AEAD・署名・相関を wire 順の仮状態で検証し、全 slice が通ったときだけ確定する）
- [x] container Samba の smoke（Commit 2 で 3 profile とも pass）

- 2026-10-04: 分割は issue 106 の Commit 2（`feat(session): 未送信 request 退役 primitive の Commit 2 — 受信の土台と compound の相関 (issue 104 を含む)`）で入った。
  合成した compound の応答（平文の署名つき・暗号化・不正な NextCommand・duplicate final）のテストで固定した。
  - 残り: 実サーバが compound 応答を返す条件の調査（Samba の設定・Windows）。調べて実サーバで確かめたら done にする。
