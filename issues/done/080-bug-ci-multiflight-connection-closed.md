# 080 bug疑い: CI の wire multi-flight ranged READ が future MessageId queue 直後に接続断する

- 種別: bug / wire protocol / CI-only timing
- 起票: 2026-08-13
- 状態: **調査完了 (2026-09-08)。「wire multi-flight の race」という bug 疑いは棄却**
- 関連: `Tests/SMBeeTests/SMBeeSharedSessionRangedReadE2ETests.swift`
  (`testSharedSessionRangedReadsHaveMultipleWireResponsesInFlight`) / `Sources/SMBee/SMBClient.swift` /
  [`075`](../075-perf-linux-aes-ccm-pure-swift-throughput.md) /
  [`086`](../086-design-cleanup-deadline-tears-down-shared-session.md) /
  [`done/062`](062-design-cancel-tears-down-shared-session.md) /
  [`done/065`](065-leak-cleanup-wire-operations-have-no-deadline.md) / obaket issue 462

## 調査方法

GitHub Actions のアーカイブログ (retention 内) を 4 run 分取得して照合した。**CI の追加 run は消費していない。**
`SMBEE_PERF` は当時どの run でも設定されていないため、`[wire] close_transport cause=` /
`request_timeout` / 復号の所要時間といった **SMBee 内部の計測値は 1 つも残っていない**。
以下の「確定」はログに現れた事実の範囲であり、内部計測が要る主張は「未確定」と明記する。

## 起票時の前提の訂正

### 訂正 1: 「512 KiB × 3 本の 3 テストは安定して green」は誤り

run 31588752225 では **3 本が同時に落ちている**。

| テスト | 所要 | 結果 |
|---|---|---|
| `...RangedReadsHaveMultipleWireResponsesInFlight` | 40.351s | `SharedSessionE2ETimeout()` |
| `...ConcurrentRangedReadsReturnExactBytes` | 64.714s | **`connectionClosed`** |
| `...ConcurrentRangedReadsRemainReusableAfterRepetition` | 67.779s | **`connectionClosed`** |
| `...ConcurrentRangedReadsSurviveOneCancellation` | 56.600s | pass |
| `...RangedReadCancelStorm` | 182.405s | pass |
| `...RepeatedRangedStreamingRead` | 17.717s | pass |

したがって「multi-flight テスト固有の問題」ではない。

### 訂正 2: 失敗の様態

4 run のうち **3 本はテスト自身の watchdog** (`sharedSessionAwaitWithTimeout`) で、
`connectionClosed` は 1 本だけ。

| run | commit | 失敗 | 所要 | error |
|---|---|---|---|---|
| 31588752225 | `a2efb8bf` | multiflight + 上記 2 本 | 40.4 / 64.7 / 67.8s | timeout / connectionClosed ×2 |
| 31607155666 | `aaee23fc` | multiflight のみ | 23.6s | `SharedSessionE2ETimeout()` |
| 31608937200 | `f20bb849` | multiflight のみ | 47.3s | `SharedSessionE2ETimeout()` |
| 31650773027 | `f725bd6` (1 MiB) | multiflight のみ | 12.4s | `connectionClosed` |

### 訂正 3: 「future id queue 直後に接続断」という時間的近接は成立しない

run 31588752225 では orphan (`SMB response queued for future message id 394`, 10:49:56) と
`CANCEL request failed: connectionClosed` (10:50:56) は **60 秒離れている**。

## 確定した事実

### 1 MiB の暗号化 response の前後に 18〜26 秒の実時間ギャップがある

run 31588752225 の GHA タイムスタンプの gap 上位: 26.5s / 25.6s / 20.7s ×2 / 20.6s ×3 / 18.3s ×3。
いずれも 1 MiB response の受信・復号か 1 MiB WRITE の前後。
**内訳 (復号なのか I/O なのか) は未計測**だが、issue 075 が実測した
「ubuntu-latest の debug ビルドで約 0.3 MiB/s」と整合する。E2E は `swift test` (debug) で走る。

**同じ CI の Performance workflow との対比 (2026-09-08 実測、run 34183254157)**:
同じ SMB 3.0.2 signing/encryption required・1 MiB payload で
**read 4.226 MiB/s / p50 236 ms、write 5.102 MiB/s / p50 196 ms**。
E2E (debug) の 18〜26 秒/MiB とは **約 100 倍**の差がある。
→ 「build configuration が支配的」という読みを支持する
(Performance job は専用ハーネスなので測定条件は完全には同一でない)。
これは下記「当面の扱い」の gate 解除条件 3 (release build で E2E を回す) の根拠にもなる。

### `closeTransport` は session 全体を落とす

`closeTransport` → `failWire` → `failAllPendingResponses` が
`pendingResponses` / `sentResponseMessageIds` / `orphanResponses` を全消去する
(`SMBClient.swift:6116-6148`)。この状態消去より後に dispatch された frame は
pending も sent も無いので orphan branch に入る (`SMBClient.swift:5884-5905`)。
**訂正 3 の orphan はこの形で説明でき、原因ではなく結果側である。**
(close 後に届く全 frame が必ず orphan になるわけではない。既に読み取り済みで後から dispatch された
frame に限る。receive loop は transport error を受けると `failWire` して終了する。)

### 64.7s / 67.8s の 2 本は 60 秒の request timeout と整合する

このテストは persistent `SMBee.connect` を使うため `SMBClient.defaultRequestTimeout` = 60 秒が渡る
(`SMBClient.swift:1867`, `1874-1916`)。`requestDidTimeOut` は対象 request を `timedOut` で解放した後、
**意図的に** `closeTransport(cause: "request_timeout")` を呼ぶ
(`SMBClient.swift:6033-6050`。CommandSequenceWindow に穴を作らないため)。
→ 同じ session の他の READ は `connectionClosed` になる。
(one-shot の static API は `requestTimeout` を渡さないので、この 60 秒は persistent 経路の話。)

### 12.4s の 1 本 — 5 秒級の cleanup deadline が最有力だが **cause は未確定**

`SMBSession.defaultCleanupTimeout = .seconds(5)` (`SMBClient.swift:4005`)。
run 31650773027 の失敗直前のログ順序:

```
1 MiB response ×3 を復号完了
SMB response direct-TCP header length=176        ← 復号後 124 byte。CLOSE response のサイズと整合
CANCEL request (68 bytes)
SMB response queued for future message id 76
CANCEL request failed: connectionClosed
```

12.4 秒なので 60 秒の request timeout ではありえない。ただし **12 秒台で transport を閉じうる経路は
5 秒 cleanup だけではない**。候補 (すべて `closeTransport` に至る):

`closeCreatedHandle` (`5320-5324`) / `bestEffortClose` (`5335-5344`) /
`bestEffortTreeDisconnect` (`5364-5368`) / `disconnect` の TREE_DISCONNECT + LOGOFF 各 5 秒 (`5404-5415`) /
child tree cleanup 後の `disconnect` (`755-760`) / caller 指定の `operationTimeout` / socket timeout /
keepalive failure (`814-830`) / send・setup failure (`5631`, `5674` 他)。

また `SMBOperationDeadline` は hard deadline ではなく、cancel 後に operation task の完了を待つため、
**5 秒時点で必ず close が走るわけではない**。
🚨 確定には `SMBEE_PERF=1` で `close_transport cause=` と timer 発火時刻を取る 1 run が要る。

## 棄却・限定した仮説

| 起票時の仮説 | 現時点の扱い |
|---|---|
| SMBee が不正 packet を送出し server が接続を終了している | **裏付けが無い**。run 31650773027 の失敗 job の Samba ログに `Terminating connection` は 0 件、`INVALID_PARAMETER` も 0 件で、観測された status は通常のもの (`NO_MORE_FILES` 55 / `INVALID_DEVICE_REQUEST` 5 / `CANCELLED` 2 など) だけ。ただし debuglevel=3 なので **「Samba が切っていない」ことの証明にはならない**。正確には「**server 側の明示的な切断理由はログから確認できなかった**」。方向 (FIN/RST) を確定するには packet capture か高い debug level が要る |
| credit 枯渇 | **持続的な枯渇は確認できなかった** (失敗時 balance 317/614)。`SMBEE_PERF` が無いため waiter 数・待ち時間は不明で、瞬間的な枯渇は未棄却 |
| 送信 Task spawn と `markRequestSent` の順序 race | `demuxedWireTransaction` は continuation 内で**送信前に同期的に** `pendingResponses` へ登録する (`5637-5651`)。送信完了後の通常 cancel は tombstone と sent ID を保持して最終 response を drain する (`5885-5893`, `6076-6094`)。→ **通常の論理 cancel 単独では orphan になりにくい**。ただし `sendStarted` → send 完了 → `markRequestSent` の窓と terminal failure の競合は**未棄却** |
| overlapping range / 5 ms polling が race 確率を変える | 上記の deadline 経路は range の重なりも polling も必要としない。**この仮説を支持する証拠は見つからなかった** |

## 結論

- **wire multi-flight の race を示す証拠は無い。** 起票時の 3 つの前提はいずれも成立しない。
- 落ちている実体は「**単一の wire 操作が SMBee の固定 deadline (60 秒 request timeout / 5 秒級 cleanup) を
  超え、その deadline が設計どおり transport 全体を閉じる**」形である。
  暗号 throughput が CI で極端に低い (issue 075) ことがそれを常態化させている。
- 4 MiB → 1 MiB に縮めても再現したのは、1 MiB でも 1 response の前後に 18〜26 秒かかるため。

## 当面の扱い

- local 専用 gate (`SMBEE_E2E_WIRE_MULTIFLIGHT=1`) は維持する。
  なお現在の CI は `DOCKER_RUN_ENV` にこの変数を含めていない (`.github/workflows/e2e.yml:76-90`,
  `test/e2e/run-swift-in-container.sh:28-35`) ので、**CI では skip されている**。
- **gate を外す条件は issue 075 の解決ではない** (multi-flight の回帰を守るのに production の
  CCM 性能を待つ必要はない)。次のどれかで足りる:
  1. multi-flight の主張を**決定論的な seam テスト**へ移す (実サーバに依存しない)。
  2. 転送量を deadline に対して十分小さくしたうえで、dispatch job で**複数回連続 green** を確認する。
     1 run の green は「そのとき速かった」以上を意味しない。
  3. release build か軽量 profile で E2E を回す。
  issue 075 は性能課題として別管理する。
- テストの skip メッセージと doc コメントが「タイミング依存で接続断する」という誤った理由を
  述べていたので、本 issue の結論に合わせて更新した。
- cleanup deadline 超過が共有セッション全体を落とす件は、issue 065 で**意図的に入れた
  session invalidation policy** であり、遅い実 NAS でも起こりうる。その再検討を
  [`086`](../086-design-cleanup-deadline-tears-down-shared-session.md) として切り出した。

## 進捗

- [x] アーカイブ CI ログ 4 run の取得と全数照合 (追加 CI run は消費していない)
- [x] 起票時の前提 3 点の訂正
- [x] Samba ログの確認 (server 側の明示的な切断理由は**確認できなかった**)
- [x] 失敗の実体の特定 (60 秒 request timeout 経路は確定 / 12.4s は 5 秒級 cleanup が最有力・cause 未確定)
- [x] codex による静的全数列挙 (transport terminal 経路 / `pendingResponses` 削除経路 / 登録されない messageId)
- [x] codex による本 issue の反証レビュー (P1 3 件 + P2 5 件 + P3 2 件をすべて採用して断定を弱めた)
- [x] テストの skip メッセージ / doc コメントの訂正
- [x] 製品側の懸念を issue 086 へ切り出し

## 残タスク (スコープ外)

- `SMBEE_PERF=1` の CI run 1 回で 12.4s の `close_transport cause=` を確定させる → issue 086 の着手時
- multi-flight の主張を決定論的テストへ移す (上記 gate 解除条件 1) → 未起票
