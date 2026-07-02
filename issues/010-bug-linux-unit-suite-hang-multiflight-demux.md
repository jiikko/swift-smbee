# 010 bug: Linux ユニットスイートが hang する (multi-flight demux の messageId 順 race + 未 resume continuation)

状態: **open** (bug / 優先度 高 — master の CI を赤くしている)
起票: 2026-07-03
関連:
- `Sources/SMBee/SMBClient.swift`: `demuxedWireTransaction` / `startReceiveLoopIfNeeded` / `receiveLoop` /
  `dispatchReceivedPacket` / `markRequestSent` / `failPendingResponse` / `failAllPendingResponses` /
  `reserveCredit` / `refundCredit`
- `Sources/SMBee/SMB2Header.swift`: `actor SMB2CreditWindow` (`reserve` / `grant` / `refund` / `resumeReadyWaiters`)
- `Tests/SMBeeTests/SMBeeTests.swift`: `testConcurrentReadChunksDemuxOutOfOrderResponses` / `awaitWithTimeout` /
  `waitForOutboundFrameCount`
- 起因コミット: `9cf1daf` "Add SMB2 credit window allocator" / `08dbcd6` "Add SMB2 multi-flight response demux"
- 先行 issue: [`issues/done/002-design-smbsession-concurrent-multiflight.md`](done/002-design-smbsession-concurrent-multiflight.md)
  (multi-flight 設計) / [`issues/done/007-ci-swift60-linux-test-stall.md`](done/007-ci-swift60-linux-test-stall.md)
  (前回の Linux stall。**下記「007 の結論訂正」で 6.2 について覆る**)
- 観測した CI run: https://github.com/jiikko/swift-smbee/actions/runs/28601793534/job/84811644475

## 症状 (事実のみ)

`Test` workflow の Linux ユニットジョブが `swift test --skip SMBeeE2ETests` 中に hang し、
step の `timeout-minutes: 10` で kill されて failure になる。

同一 run 内の切り分け:

| ジョブ | runner / 実行内容 | 結果 |
|---|---|---|
| `build-test` | **macOS** で full unit suite (`swift test --skip SMBeeE2ETests`) | ✓ pass (~2m) |
| `linux-build-test` | **Linux** docker `swift:6.2` で full unit suite | ✗ **hang → 10:12 で timeout kill** |
| `code-coverage` | **Linux** で full `swift test` (coverage) | ✗ 同じ hang (15分 timeout) |
| `test-registration-coverage` | Linux・`--list-tests` のみ | ✓ pass |
| `performance-regression` | Linux・`--filter` で一部のみ | ✓ pass |

→ **「Linux で全ユニットスイートを回すジョブだけ」が hang**。macOS の同一スイートは pass。
GHA インフラ障害ではなく、**Linux 固有・タイミング依存の concurrency hang**。
CI の step timeout 自体は正しく効いている (症状の緩和にはなるが原因ではない)。

補足: 最有力容疑テスト単体は **macOS ローカルでは 0.016 秒で pass** する
(`swift test --filter testConcurrentReadChunksDemuxOutOfOrderResponses`)。単体・macOS では再現しない。

## 根本原因

### A. 有力な主因 (Linux ユニット hang) — messageId 順 race × キャンセル不能な `awaitWithTimeout`

`08dbcd6` で追加された `testConcurrentReadChunksDemuxOutOfOrderResponses`
(`Tests/SMBeeTests/SMBeeTests.swift`) は 2 つの unstructured `Task` で `session.readChunk` を並行に呼ぶ。
`nextMessageId()` は **actor 到着順**で messageId を採番するため、割当順は **スケジューラ依存**。

テストは「`first` → messageId 0 / `second` → messageId 1」を暗黙前提にして、
先に `messageId: 1` の応答を enqueue → `awaitWithTimeout("second") { second.value }` で待つ。
Linux の global executor では **`second` が先に到着して messageId 0 を取る**ことがあり、そうなると:

1. enqueue した `messageId: 1` の応答は `first` の pending に渡り、
2. `awaitWithTimeout("second")` は「来ない `second` (messageId 0) の応答」を待つ循環になる。
3. watchdog は 5 秒で throw するが、`awaitWithTimeout` は `withThrowingTaskGroup` で
   **return 前に全 child を await** する。child は `try await second.value` で停止し、
   **`Task.value` の await はキャンセルで抜けない** (`group.cancelAll()` しても drain 不能)。
   → group が終われず **永久 hang → 10 分 CI kill**。

これは [`issues/done/007`](done/007-ci-swift60-linux-test-stall.md) のコメントが警戒していた
`awaitWithTimeout` の穴そのもの。`XCTAssertEqual(readUInt64LE(requests[0], at: 72), 0)`
(outbound 順は send 順であって messageId 順ではない) もこの反転時に fail するはずで、
CI ログ (in_progress 中は取得不可) には非 fatal assert の失敗が出ているはず。

**注意: A は「論理は妥当だが Linux 実機で backtrace 採取までは未確認」の仮説。**
着手時にまず A を確定させること (下記「着手手順」参照)。

### B. 実在する潜在デッドロック (本番) — credit ⇄ receive ⇄ send の循環待ち

ユニット hang の主因ではない (fixture は全て charge=1 / grant=1 で、`SMB2CreditWindow.reserve` は
credit があるうちは suspend せず同期 return するため決定論的には起きない) が、**本番で到達可能な循環待ち**が
構造として実在する:

- `SMB2CreditWindow.reserve` (`SMB2Header.swift`) は `available < charge` のとき
  `CheckedContinuation<UInt32, Never>` で **suspend してブロック**する。resume は `grant`/`refund` のみ。
- `grant` は `recordCreditGrant` 経由で **receiveLoop が inbound frame を処理したときだけ**呼ばれる。
- `receiveLoop` は `markRequestSent` からしか始まらず、`markRequestSent` は
  `demuxedWireTransaction` の spawn Task 内で **`send(packet)` 完了後**にしか呼ばれない。

→ **send が credit 待ちでブロック (idle パイプライン、または server が 0 credit grant) → その send が
完了しないので receiveLoop が起動/前進しない → credit が grant されない → send が永久ブロック**。
`refund` は send **失敗時**しか発火しないので、成功したが credit 枯渇の waiter は救済されない。
さらに `failAllPendingResponses` は pending **response** continuation は resume するが
**`SMB2CreditWindow.waiters` は resume しない** (しかも `Never` 型で fail 不能) → teardown で leak。

### 破れている不変条件 (A・B 共通)

> **session が作る全 continuation (pending response / credit waiter / receive) は、
> いずれかの終端イベント (応答・transport error・teardown・cancel) で必ず一度だけ resume される。**

- B: credit waiter に grant/refund 以外の終端が無い (teardown で resume されない)。
- A (テスト層): `awaitWithTimeout` が「wrap した operation は cancellable」を前提にしているが
  `Task.value` はキャンセルで抜けない。

### 参考: これは lost-wakeup ではない

`receiveLoopRunning` フラグ + `while !sentResponseMessageIds.isEmpty` の自己終了は、
最後の `await` (`receiveDecryptedFrame` 内) からフラグ reset までに suspension point が無く、
`markRequestSent` は同一 actor 上で走るため、古典的 lost-wakeup は成立しない。
問題はフラグではなく **loop の生存条件 (「送信済み要求がある間だけ生きる」) が、
credit waiter / 登録済み未送信 pending という別クラスの待ち手を養えないこと**。

## 修正方針 (推奨)

構造で潰す (timeout での症状マスクは不可)。**session ライフサイクルが所有する単一 reader + terminatable credit window**。

1. **単一 long-lived reader task を session が所有する。**
   - `connect()` で 1 つ `Task` を起動 (`receiveTask: Task<Void, Never>?` に保持)、
     `receiveDecryptedFrame` を transport error / cancel まで無条件ループ。
   - `closeTransport()` / `disconnect()` / `deinit` で cancel。
   - `receiveLoopRunning` / `startReceiveLoopIfNeeded` / `sentResponseMessageIds` /
     `while !sentResponseMessageIds.isEmpty` の自己終了を**撤去**。
   - これで「loop 生存 ↔ send 完了」の結合が消え、**全 sender が credit 枯渇でも reader が
     応答を処理して credit を grant できる**。
   - `orphanResponses` は残す (pending 登録は send 前なので orphan はほぼ dead code 化するが、
     interim / unsolicited packet の保険として維持)。
   - **移行コスト**: `InMemoryTransport.receive` が drain 後に `[]` を返す挙動だと reader が
     即 `connectionClosed` で終わる。**「空なら close まで block する」モードを opt-in flag で
     追加**する必要がある (下記テスト影響)。

2. **`SMB2CreditWindow` の waiter を terminatable にする。**
   - `reserve` を `CheckedContinuation<UInt32, Error>` (または `Result` return) に変え、
     `func fail(_ error: Error)` で `waiters` を drain。
   - `failAllPendingResponses` / `closeTransport` から呼ぶ → credit waiter の leak を解消し
     不変条件を回復。

3. **request timeout は defense-in-depth として release に入れる (`#if DEBUG` にしない)。**
   - `demuxedWireTransaction` で pending continuation と `Task.sleep(requestTimeout)` を race。
     default は寛容 (例 60s)、`SMBSession.init` で configurable、long-poll は除外 or 長め。
   - **release に置く理由**: 「server が応答を止める / 0 credit を grant し続ける / RST 無しの
     half-dead TCP」は**本番の失敗モード**。smbclient / macOS SMBX も request timeout を持つ。
     hang は呼び出し側にとって error より厳しく、DEBUG 限定 guard は bug が住む環境を見ない。
   - **あくまで二次**。主因は構造 (1+2)。timeout だけ入れるとデッドロックを「60 秒 stall/req」に
     変えるだけで消えない。

4. **テスト層の修正 (どの設計を採っても必要)。**
   - `testConcurrentReadChunksDemuxOutOfOrderResponses`: spawn 順 = messageId 順の前提を捨て、
     **outbound 2 本の header を decode して messageId→offset をマップしてから応答を enqueue**
     (どのスケジューラでも決定論的)。反転を強制する variant も可 (first の入場を signal で gate)。
   - `awaitWithTimeout`: uncancellable な `Task.value` を直接 await しない。
     `Task` を受け取り `task.cancel()` + detached drain にするか、構造修正で operation を
     `closeTransport()` 経由 (teardown block) で完了可能にする。

### 代替案

- **代替 A (小さい diff)**: 自己終了 loop を残し、生存条件を
  `!sentResponseMessageIds.isEmpty || !pendingResponses.isEmpty || creditWindow.pendingWaiterCount > 0`
  に拡張 + `demuxedWireTransaction` で登録時に loop 起動。~40 LOC・transport 変更不要だが、
  生存条件が cross-actor predicate (credit window は別 actor) になり suspension point で racy。
  結合を除去せず patch するだけなので脆い。**非推奨**。
- **代替 B**: credit accounting を `SMBSession` actor 内の state に畳む (別 actor を廃止)。
  teardown での waiter fail が自明になり、`balance` 読取と `reserve` の TOCTOU も消える。
  推奨案 (1+2) と併用可。

## 工数見積もり

| 項目 | ファイル / symbol | 目安 LOC | リスク |
|---|---|---|---|
| session 所有 reader / loop・flag・sent-set 撤去 | `SMBClient.swift`: `connect` / `closeTransport` / `receiveLoop` 除去 / `markRequestSent` 縮小 / `demuxedWireTransaction` | ~60-80 | 中 — wire 中核。`bin/e2e/container-samba.sh` 必須再実行 (CLAUDE.md: session/transport 変更) |
| failable credit window + teardown drain | `SMB2Header.swift` `SMB2CreditWindow` / `SMBClient.swift` `failAllPendingResponses` / send 経路 | ~40 | 低-中 — `reserve` が throwing に (呼び元は既に throwing context) |
| release request timeout | `SMBClient.swift` `demuxedWireTransaction` + `SMBSession.init` に `requestTimeout` | ~30-40 | 低 — **API 追加** (default 付き optional、非破壊) |
| `InMemoryTransport` block-until-closed モード | `SMBTransport.swift` | ~30 | 低 — `InMemoryTransport` は `public` なので default-off flag で外部非破壊 |
| テスト修正 (demux 順非依存 / awaitWithTimeout / teardown) | `SMBeeTests.swift` | ~40 | 低 |
| 回帰テスト (下記) | — | ~80 | — |

合計 ≈ **250-300 LOC / 1-2 日** (E2E smoke 込み)。**public API の破壊なし**
(`SMBSession` 内部 / `InMemoryTransport` は opt-in flag / init 引数は optional)。

## 回帰テスト (タイミングを追わず決定論化する)

1. **credit デッドロック class**: `SMB2CreditWindow(initialCredits: 1)` に対し `creditCharge: 2` の
   要求を idle パイプラインで 1 本投げ、hang せず fail/timeout することを assert (B の不変条件を固定)。
2. **teardown 不変条件**: `reserve` で task を park → `closeTransport()` / transport error →
   reserve が throw し `pendingWaiterCount == 0` を assert (修正 2 が前提)。
3. **demux 順**: 2-`Task` spawn をやめ、outbound header を decode して messageId で応答を返す
   (§修正方針 4)。反転を強制する variant も追加。
4. **手動検証**: `issues/done/007` の `--cpus 2` container ループを CI ではなく手動 recipe として残す。

## 着手手順 (この issue を見た人向け)

1. まず **A を Linux 実機で確定**する (blind fix しない)。Apple `container` で swift Linux イメージを
   起動し、backtrace 付きで hang 箇所を採取:
   ```sh
   # 初回のみ対話 (人間が 1 回): container system start
   container run --rm -v "$PWD:/work" -w /work swift:6.2 \
     bash -c 'swift build; timeout -s QUIT 180 swift test --skip SMBeeE2ETests 2>&1 | tail -120'
   # SWIFT_BACKTRACE=enable=yes を付けて停止スレッドの backtrace を採る
   ```
   (docker が使える環境なら同コマンドの docker 版でよい。CLAUDE.md によりローカルは Apple container。)
2. A が確定したら **§修正方針 4 のテスト修正で A を潰し**、Linux ジョブが green になるか確認。
3. **§修正方針 1+2 の構造修正**で B (潜在デッドロック) と不変条件を回復。
4. **§修正方針 3 の release request timeout** を defense-in-depth として追加。
5. 変更したら **必ず `swift build && swift test` → `bin/e2e/container-samba.sh`** (CLAUDE.md 必須)。
6. commit 粒度 1 マイルストーン = 1 commit、submodule push 後に親参照 bump。

## 併せて検討 (別スコープ可)

- **TOCTOU**: `creditAwareReadChunkSize` / `creditAwareWriteChunkSize` が `creditWindow.balance` を
  読んでから後で `reserve` する (`SMBClient.swift`)。charge が 1 に固定の今は無害だが、
  chunk が 64KiB を超えた日に静かに starvation 源になる。代替 B (credit を session に畳む) で同時に解消可。
- **`issues/done/007` の結論訂正**: 007 は「toolchain flaky・repo logic 正しい」で done にしたが、
  今回 **6.2 で repo logic 側 (demux の messageId 順前提 + awaitWithTimeout の穴) の bug** と判明。
  本 issue 完了時に 007 に「6.2 で結論が覆った、真因は 010」と追記すること。

## 再発防止 (linter / 契約)

- `awaitWithTimeout` に「wrap する operation は cancellable でなければならない (`Task.value` 直接 await 禁止)」を
  doc + 可能なら custom lint で明示。
- 「continuation を登録する箇所は、全終端経路で resume されることを保証する」不変条件を
  `SMBClient` / `SMB2CreditWindow` の該当箇所にコメントで残す (実装で強制できない設計契約)。
