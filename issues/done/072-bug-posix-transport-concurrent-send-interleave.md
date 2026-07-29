# 072 bug: POSIXSocketTransport の並列 send が frame バイトを交錯させ、サーバが接続を落とす

状態: **解決済み (2026-07-29、commit cd75c30)。送信 executor で直列化し、再現条件 (16 並列 readPrefix + list、4 MiB、encrypted Samba) で 3 run × 5,100 ops 無障害・サーバ側 DECRYPTION_FAILED 新規ゼロを確認 = 観測 A の因果も閉じた。派生の既存問題は issue 073 に分離。**
起票: 2026-07-29（wire 診断 + ストレスハーネスによる P2-0 計測で特定）
関連: `Sources/SMBee/POSIXSocketTransport.swift`（`send` / `sendBlocking`） /
`Sources/SMBee/SMBTransport.swift`（segments の default 実装） /
`Sources/SMBee/SMBClient.swift`（`resolvedTransportFactory` — **既定 transport は macOS でも POSIX**） /
obaket `macOS/issues/437` 観測 A / `issues/069`（巻き添え範囲の議論。069 の機構は victim 側で first fault ではなかった）

## 実測（2026-07-29、container Samba smb302-encrypted-required）

再現: `SMBeeWireStressE2ETests`（1 persistent session で readPrefix 16 並列 + list、prefix 4 MiB）。

- クライアント側 first fault: `[wire] first_fault type=SMBTransportError description=socketFailure("recv failed: errno 54")`
  （ECONNRESET）。直後に pending 17 件が victim として一斉 connection-lost（観測 A の「複数 op が
  同一ミリ秒で connection-lost」と同型）。
- サーバ側（log level 10）: `smb2_signing_decrypt_pdu: GNUTLS ERROR: GNUTLS_E_DECRYPTION_FAILED` →
  `Server exit (NT_STATUS_DECRYPTION_FAILED)`。別 run では `Server exit (NT_STATUS_INVALID_PARAMETER)` /
  `Server exit (failed to receive request length)`。DECRYPTION_FAILED は「届いた transform を
  key/nonce/tag で復号できなかった」ことの証明であり、交錯に一意化はできない（codex 反証レビュー。
  ただし nonce race / 署名鍵 race は actor 隔離 + suspension 前の同期実行で強く否定済み。残る代替解釈:
  send 途中の cancel / close による truncation、partial write 後の send error、key derivation 不一致
  （負荷依存性と整合しにくい）、Samba/GnuTLS 側の問題）。
- 従来仮説（`bestEffortClose` → `closeTransport` の巻き添え = issue 069 の機構）は first fault ではない:
  `cleanup_close_failed` は first fault の**後**にのみ出現した。

## 根因

`POSIXSocketTransport` は送信を直列化していない:

1. `send(_ segments:)` は detached task 内で segment を順に `sendBlocking` する。暗号化 frame は
   `[Direct TCP length + transform header, ciphertext]` の複数 segment なので、並列 send 間で
   segment 境界の交錯が起きる。
2. `sendBlocking` の partial-write ループも無保護（`fdLock` は fd 値の取得を守るだけ）。socket buffer が
   詰まる高負荷時（4 MiB READ 応答受信と並行した送信）には 1 segment 内でも交錯しうる。
3. `SMBSession` actor は `await transport.send(...)` の suspend 中に別の送信 task を進めるため、
   多重飛行（demux + credit window は対応済み）では並列 send が常態的に発生する。

**NWConnectionTransport はこの interleaving class を持たない**: segments default 実装が全 segment を
連結して 1 回の `NWConnection.send` に渡し、NWConnection は content 単位の contiguity と send 間の
全順序を保証する（TCP に message atomicity は無いので「atomic」ではなくこの 2 性質が正確な表現）。
しかし `resolvedTransportFactory` の既定は macOS でも POSIX であり、
**obaket も makeTransport 未指定のため POSIX を使っている**。

## consumer への影響（obaket 観測 A の説明）

スクロール = prefix read 4 並列 + list の並列送信 → 低確率で frame 交錯 → サーバが接続を落とす →
複数 op が同時に connection-lost → controller の retry で自己回復（観測どおり）。
並列度が低いと交錯確率が下がるため「たまにしか起きない」観測とも整合する。

## 対応方針（実装済み）

- **修正の本命: transport 層で「1 論理 frame = 1 atomic 送信」を保証する**。候補:
  (a) `POSIXSocketTransport` に送信 lock を持たせ、`send` 全体（segments ループ + partial write）を
  直列化する（最小・確実）。
  (b) `SMBSession` 側に send queue を置く（transport 実装非依存になるが変更が大きい）。
  実装では (a) の送信 executor により、1 論理 frame の全 segments と partial write を直列化した。
- 修正の要件（codex 反証レビューで追加）:
  - `send(bytes:)` と `send(segments:)` を**同じ primitive** で直列化する（lock 範囲は全 segments +
    全 partial-write ループ）
    実装で満たした。
  - frame を一部でも送った後の失敗 / cancel は、その接続を再利用せず必ず poison / close する
    実装で満たした。
  - `SMBTransport` の契約に「同時 send 可・各 send の byte 列は交錯しない」を明記する
    実装で満たした。
  - `writev` 化だけでは partial write が残るため lock の代替にならない
    実装で満たした。EINTR も送信実装で扱う。
- 検証: ストレス E2E だけでは弱い。**fake blocking writer で A/B の send を意図的に停止・再開し、
  交錯を決定論的に再現する unit**（修正前に落ち、修正後は frameA+frameB / frameB+frameA のいずれかに
  必ずなる）を足す。加えて修正後に `SMBeeWireStressE2ETests` の同条件で connection-lost が
  消える（または大幅減する）ことを確認し、消えたら観測 A の根因としての因果も閉じる。
- 併せて「既定 transport を macOS では NW にすべきか」は別判断（POSIX を直せば必須ではない。
  Linux は POSIX しか無いのでどのみち修正は必要）。
  fake writer の unit と Samba stress E2E を追加・実行し、交錯しないことを確認した（実装済み）。

## 再現手順

```sh
SMBEE_E2E_KEEP_CONTAINER=1 SMBEE_E2E_PORT=1446 bin/e2e/container-samba.sh
SMBEE_E2E=1 SMBEE_E2E_STRESS=1 SMBEE_E2E_PORT=1446 SMBEE_PERF=1 \
  SMBEE_STRESS_CONCURRENCY=16 SMBEE_STRESS_REPETITIONS=300 SMBEE_STRESS_PREFIX_LENGTH=4194304 \
  swift test --filter SMBeeWireStressE2ETests
# 16 並列 / 4 MiB で高確率、4 並列 / 64 KiB (250 ops) では未再現 (交錯確率が下がる)
```
