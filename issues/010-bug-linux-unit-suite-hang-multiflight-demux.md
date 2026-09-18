# 010 bug: Linux ユニットスイートが hang する (multi-flight demux の messageId 順 race + 未 resume continuation)

状態: **一部対応済み** (A のテスト側修正 + §修正方針 2 + awaitWithTimeout の穴 = 2026-07-03 対応。
§3 (release request timeout) = **完了**: `55d635e` で opt-in 導入 (2026-08-01)、`18443c2` で
原設計どおり既定 60s に引き上げ (2026-08-02。opt-out は明示 `requestTimeout: nil`。
既定化の動機 = obaket issue 453: スリープ復帰後の half-dead TCP で read が無言に永久ハング)。
構造修正 §1 (session 所有 reader) のみ残)
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

## 対応状況 (2026-07-03)

- ✅ **A (テスト層)**: `testConcurrentReadChunksDemuxOutOfOrderResponses` を spawn 順 = messageId 順の
  前提から外し、outbound header を decode して offset→messageId map で応答を返すよう修正
  (§修正方針 4)。`requests[0] offset==0` の順序 assert も撤去。
- ✅ **awaitWithTimeout の穴**: task group をやめ resume-once box + watchdog に変更。
  uncancellable な operation は leak させて job hang を防ぐ (doc コメントに契約を明記)。
- ✅ **§修正方針 2**: `SMB2CreditWindow.reserve` は throwing + task cancellation 対応 (先行 commit)。
  本 commit で `failAllWaiters(_:)` を追加し `failAllPendingResponses` / `closeTransport` から drain。
  回帰 unit (`testSMB2CreditWindowFailAllWaitersDrainsParkedReserves`) あり。
- ⬜ **§修正方針 1** (session 所有 single reader / loop 生存条件の撤去) — 未着手。wire 中核の
  構造変更で container smoke 必須。B の循環待ちの根治はここ。
- ✅ **§修正方針 3** (release request timeout) — 2026-08-01 実装。`SMBSession.init` /
  `SMBClient.connect` / `SMBee.connect` / `connectFollowingDFS` に `requestTimeout: Duration? = nil`
  (opt-in・非破壊)。timer は wire 送信完了後にのみ開始 (未送信 MessageId を捨てると server の
  CommandSequenceWindow に穴が開くため)、発火は session-fatal (`closeTransport(cause: request_timeout)`、
  credit refund なし)。除外: longPoll (CHANGE_NOTIFY) / blocking LOCK (failImmediately なし) /
  named-pipe READ・TRANSCEIVE。敵対テスト 6 本 + ミューテーション 4 変異の検知確認済み。
- Linux 実機 backtrace での A 確定は未実施 (このマシンに container なし)。テスト修正後の
  Linux CI green 継続を代替観測とする。issues/013 の CI 観測 (sample/stdbuf) は継続。

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

## 現況監査 (2026-09-08) — 本文の 3 点を訂正する

codex 3 観点 (read-only) + Claude の裏取りによる監査。**本 issue の記述に誤りが 3 点あった**。

### 訂正 1: 主仮説 A は、観測された hang を説明していない

本文は `testConcurrentReadChunksDemuxOutOfOrderResponses` を「有力な主因」としていたが、
CI アーカイブログの全数勘定（[`013`](waiting/013-linux-ci-intermittent-hang.md) の「全数勘定」節）では:

- hang した 8 job のうち、そのテストに**到達した job は 0 件**（実行はアルファベット順で
  `ChangeNotify…` < `ConcurrentRead…`）。
- 同じ run (28601793534) の **macOS job では当該テストが pass している**。

A は「論理は妥当だが Linux 実機で未確認」と本文自身が但し書きしていたとおり、**未確認のまま**で、
かつ**観測はこれを支持しない**。テスト側の修正 (2026-07-03) 自体は正しい修正なので取り消さないが、
**hang の原因として扱わない**。

### 訂正 2: §B の「credit waiter が resume されない」は既に解消済み

本文 §B は `SMB2CreditWindow.reserve` が `CheckedContinuation<UInt32, Never>` で
「fail 不能・teardown で leak」と書いているが、現コードでは:

- `reserve` は throwing + cancellation 対応済み（`SMB2Header.swift:249`）
- `failAllWaiters` が在り、`failAllPendingResponses` / `closeTransport` から drain される
  （`SMB2Header.swift:303` / `SMBClient.swift:6116`）
- request timeout も既定 60s で入っている

「対応状況 (2026-07-03)」節が ✅ を付けているとおりで、**§B の本文だけが古いまま残っていた**。
現行コードに対する runtime の発火条件は無い。

### 訂正 3: §修正方針 1 の見積もりが小さすぎる（60-80 LOC → 250-350 LOC）

§1 が未着手であること自体は事実（`receiveTask` は存在せず、`connect()` は reader を所有せず、
`closeTransport()` は reader を cancel せず、`deinit` も無い。`receiveLoopRunning` /
`startReceiveLoopIfNeeded` / `while !sentResponseMessageIds.isEmpty` は現存する）。
しかし規模の見積もりが実態と合っていない。

- **`sentResponseMessageIds` は単なる loop の生存フラグではない**（`SMBClient.swift:4051` /
  `:5990`）。cancel 済み request の遅着 response 判定・CANCEL の可否判定・tombstone・
  テストの計測にも使われている。**「自己終了ループの撤去」で素朴に消すと CANCEL と
  遅着 response の意味論が壊れる**。ここが本文の最大の見落とし。
- reader task の所有・close / cancel・transport の receive 中断・`Task { await self.receiveLoop() }`
  の self 強捕捉と cycle 回避まで含めると **全体で ~250-350 LOC**。
- **既存テストへの影響が広い**: `InMemoryTransport` を「空なら close まで block」に一律変更すると、
  drain 後の EOF / `connectionClosed` を期待する **4 テスト**が壊れる。`ControlledReceiveTransport`
  の利用 26 件、performance suite 7 件 / 9 sites も影響範囲。opt-in flag か明示 close が要る。

### 代替 A の再評価: 「非推奨」を撤回して短期の選択肢に戻す

本文は代替 A（自己終了ループを残し、生存条件を pending / credit waiter へ拡張）を
「cross-actor predicate で racy・非推奨」としていた。監査の結論は**短期策としては実用的**:

- **pending は send の前に登録される**ので、「pending 登録直後に reader を起動し、pending が
  ある間 reader を生存させる」だけで、credit 待ちの sendTask が grant を受けられるようになる。
  §B の循環待ち（send → receive → credit → send）はこれで切れる。
- 残る未解決は reader task の所有・close・任意 transport の cancellation 契約で、これは §1 と共通。

つまり **§1 は「正しい構造」だが、循環待ちを切るだけなら代替 A で足りる**。どちらを採るかは
「今 hang を止めたいのか / 構造を直したいのか」で決める。

### この監査で新たに見つかったもの

`ControlledReceiveTransport.receive(maxLength:)`（`SMBeeTests.swift:1068`）に cancellation
handler が無い。最終応答を注入しないテストを書くと receive continuation が永久 pending になる。
現行テストは応答を注入しているので発火しない。詳細は [`013`](waiting/013-linux-ci-intermittent-hang.md)。

### 着手手順の更新

本文の「着手手順 1（まず A を Linux 実機で確定）」は**不要になった**。A は観測で否定された。
代わりに:

1. **hang の再現を待つか、待たずに構造を直すかを決める**（[`013`](waiting/013-linux-ci-intermittent-hang.md) は
   `waiting/` へ移した。真因は未確定）。
2. 構造を直すなら **§1 か 代替 A のどちらかを選ぶ**（上の再評価を根拠に）。
3. どちらでも `sentResponseMessageIds` の 4 つの役割を先に分離すること（これを飛ばすと
   CANCEL と遅着 response が壊れる）。
4. wire 中核なので `bin/e2e/container-samba.sh` の smoke は必須。

## 進捗チェックポイント — M1 完了 (2026-09-08)

ユーザーが選択肢 **A（§修正方針 1 = session 所有の単一 long-lived reader）** を選択。codex-drive で
D1（独立 4 案）→ D2（統合）→ D3（敵対 + 発見型）→ 承認ゲート → M1 実装、と進めた。

### 採用設計の要点（承認済み）

- `SMBSession` が単一の `readerTask` を所有。**最初の 1 本の send 完了までは起動しない**
  （orphan 上限 64 に対し perf fixture が 130 frame 超を preload するため。ユーザー決定 ①(a)）。
  それ以降は **individual な send の完了に依存せず**、cancel か transport error まで生存する。
- reader は framing だけを担当し、`transport` と `weak self` だけを捕捉（deinit cycle 回避）。
  復号・credit grant・demux は session actor 側で、**現行の順序を維持**する。
- `sentResponseMessageIds` を**撤去**し、`SMBPendingResponse.sendPhase` に畳む
  （D1 の 4 案のうち、台帳を増やさない案を採用。**却下**: 4 コレクションへの分割 /
  `SMBRequestLedger` 型の新設 / 集合を tombstone として残す案）。
- **response 受理を `sendPhase == .sent` で gate する**（既存の穴の同時修正。下記）。

### D3 で判明した重要事項

- **「未送信 request への応答配送」は既存の穴**。`pendingResponses` の登録は
  `withCheckedThrowingContinuation` の内側 (`:5638`)、`markRequestSent` は send 完了後 (`:5661`)。
  long-lived reader は窓を広げるだけで、原因ではない。
- **当初の回帰テスト案 (A4) は無効だった**。`initialCredits=1` + `charge=2` で park させるだけでは
  旧構造も新構造も grant が来ずに停止し、変異で red にならない。
  → **「queue 済みの grant を reader が消費する」刺激**に変える（M4）。
- **複雑性の主張を訂正**: 参照数は `sentResponseMessageIds` 11 ≒ `sendPhase` 11 で読む複雑性は
  減らない。減るのは「**同期すべきデータ構造が 2 → 1**」だけ。CANCEL 判定は O(1) → 2 段参照、
  count 観測は O(1) → O(n) に悪化する。

D3 が出した改訂 13 件は `[D2 v2]` として設計に反映済み（設計ファイルは `tmp/` なので、
実装時に効く項目は各マイルストーンの本文へ移す）。

### M1: characterization（完了・production 変更なし）

`Tests/SMBeeTests/SMBeeWireCharacterizationTests.swift`（新規 657 行）。
**assert は protocol 観測可能な値だけ**（decode した outbound ヘッダと continuation の結末）。
内部 count は M2 で意味が変わるため使わない。

| # | 固定した意味論 | 変異 | 結果 |
|---|---|---|---|
| 1 | send 完了前の cancel は wire に CANCEL を出さない | `guard wasSent` を外す | **red** |
| 2 | sync CANCEL は TreeId 0・MessageId 一致 | TreeId を非 0 に | **red** |
| 3 | interim 後の cancel は AsyncId 付き async CANCEL | 常に sync 形式に | **red** |
| 4 | cancel 後の遅着 final で二重 resume しない | 遅着分岐を殺す | **GREEN（観測不能）** |
| 5 | interim では resume せず final で一度だけ | interim を final 扱いに | **red** |
| 6 | **send 完了前に届いた future response が replay される** | orphan への投入を消す | **red** |

- baseline green / 各変異後 red / 復元後 green / `Sources/` 差分ゼロ を **Claude が素の環境で実測**
  （codex は `--disable-sandbox` でしか回せないため、その報告は主張として扱い再実行した）。
- **#6 は最初 GREEN だった**。orphan queue は `markRequestSent` (`:6013`) で**消費される**
  （send 完了時にその messageId 宛の先着 frame を replay する）のに、テストが
  「二度と使われない未知の messageId」を使っていて的が外れていた。書き直して red になった。
- **#4 は protocol 観測不能**と確定。遅着分岐を殺しても frame が orphan に入るだけで、
  replay もされず resume もされない。**残るのはメモリ衛生の差だけ**で wire にも呼び出し側にも出ない。
  観測 API は存在せず、追加は production への test seam になるので採らない。
  → 受け入れ条件を「6/6 red」から「**5/6 red + 1 件は観測不能と記録**」へ修正した。
  tombstone のメモリ衛生は M3/M4（reader lifecycle で orphan 圧力が観測可能になる段）で扱う。

### 次のマイルストーン

| # | 内容 | 状態 |
|---|---|---|
| M1 | characterization | **完了** |
| M2 | `sendPhase` 導入・`sentResponseMessageIds` 撤去（reader は現行のまま） | 未着手 |
| M3 | long-lived reader 導入（生存条件の切断・weak 捕捉・generation・close/deinit） | 未着手 |
| M4 | transport 契約 + fixture 移行 + credit 循環の回帰テスト | 未着手 |
| M5 | 全体検証（macOS / Linux / E2E smoke / verify-agent-push） | 未着手 |

M2 で最初に触るべき箇所（D3 + Claude の実測）: `pendingResponses` に tombstone を混在させると
意味が変わる **5 箇所** — `:5471` `:5480` `:5488` `:5515`（count ベースの待機・観測）と
**`:6117`（`failAllPendingResponses` の走査元。tombstone を resume すると二重 resume）**。
加えて `:6117` は tombstone の `sendTask` を cancel する必要がある（`continue` で skip すると
blocked send が残る）。

### M2: `sendPhase` 導入・`sentResponseMessageIds` 撤去（完了・2026-09-09）

**挙動を変えない純粋なリファクタに限定した。** D2 v2 の改訂 1（response 受理を `sendPhase == .sent` で
gate する = 既存バグの修正）は **M2b へ分離**した（挙動変更を混ぜると、テストが落ちたときに
「リファクタの誤り」か「意図した挙動変更」かの帰属が付かなくなるため）。

production の diff は **41 追加 / 40 削除**（`SMBClient.swift` のみ）。台帳が減ったので純減に近い。

| 旧 `sentResponseMessageIds` の参照 | 移行先 |
|---|---|
| 生存条件 `:5857` | `pendingResponses.values.contains { $0.sendPhase == .sent }`（**M3 でここを外す**） |
| 遅着判定 `:5885` `:5891` | tombstone が `pendingResponses` に残るので通常経路で処理 |
| CANCEL 可否 `:6024` `:6106` | `sendPhase == .sent` |
| 計測 `:5484` | `.sent && !continuationResumed` の projection |
| teardown `:6128` | 撤去 |

**tombstone 混在で意味が変わる 5 箇所を live-only に直した**（`:5471` `:5480` `:5488` `:5515` `:6117`）。
特に `:6117` は `sendTask?.cancel()` を `continue` の**前**へ移し、D3 敵対レビューが指摘した
「cancel 済み tombstone の blocked な sendTask が close 後も残る」を塞いだ。

`sendStarted` は**置換**（残して二重管理にしていない）。

#### 検証（すべて Claude が素の環境で実測）

- `swift build` rc=0 / `swift test` rc=0 — **468 tests / 37 skipped / 0 failures**
- **M1 のテストファイルは 1 行も変更していない**（移行前後で不変であるべき contract。
  触っていたら移行が挙動を変えた証拠になる）
- 変異検証 3 本すべて red → 復元後 green:

| 変異 | 結果 |
|---|---|
| MutA `failAllPendingResponses` の二重 resume ガードを外す | **red**（`testClosingAfterSentCancellationDoesNotResumeTombstoneTwice` が `SWIFT TASK CONTINUATION MISUSE` で trap。予測と一致） |
| MutB tombstone の `sendTask` を cancel しない | **red** |
| MutC 生存条件を `.sent` 以外も数える形に壊す（Claude が追加） | **red** |

🚨 **codex は「全体で 7 failures、既存の network 系」と報告したが、素の環境では 0 failures**
だった。sandbox（`--disable-sandbox` + loopback bind 失敗）由来の偽赤で、報告を鵜呑みにせず
回し直す規律がそのまま効いた事例。

#### diff 精読で見つけた、報告に無い挙動差 2 件

1. **遅着 frame の行き先が変わる**。`pendingResponses` から除去済みだが旧 Set には残っていた
   messageId（timeout / send 失敗の経路）宛の遅着 frame は、旧実装では**捨てられ**ていたが、
   新実装では `orphanResponses` へ積まれる。上限 64 + eviction で bounded なので受容する。
   Mut4 と同じ「protocol 観測不能なメモリ衛生」の類で、M1 では原理的に捕まらない。
2. **診断ログの後退（修正済み）**。`[wire] victim` 行が `resumed=0` 固定になり tombstone 件数が
   見えなくなっていた。「victim なし」と「victim は全部 cancel 済みだった」を事後解析で
   区別できなくなるので、`resumed` を復元した。

## 🔁 引き継ぎ（2026-09-09 時点。再起動・別セッション・別マシン向け）

### いまの状態

| 項目 | 状態 |
|---|---|
| ローカル commit | `7923d76`（M1）/ `178229f`（M2）。**どちらも未 push** |
| working tree | clean |
| 親 repo (`my-products`) の submodule 参照 | **未 bump**（submodule を push してからでないと bump してはいけない） |
| pre-push フック | 有効化済み（`git config core.hooksPath bin/hooks`）。M2 が wire を触ったので **push には smoke が要る** |
| Apple `container` | 初回セットアップ済み・running（`bin/e2e/container-samba.sh` が回せる） |

### 再開手順

```sh
cd lib/swift-smbee
git log --oneline -3          # 7923d76 (M1) / 178229f (M2) があるか
swift build && swift test     # 468 tests / 37 skipped / 0 failures が baseline
make smoke                    # wire を触ったので push 前に必須
git push origin master
bin/ci/verify-agent-push <full-sha>
# submodule を push してから親の参照を bump する
```

**設計ファイル `tmp/d010/codex-drive-design.md` は gitignore なので git には無い。**
残りのマイルストーンに要る判断は以下に全部写してあるので、無くても再開できる。

### 残りのマイルストーン（D2 v2 の改訂 13 件を割り付け済み）

#### M2b — response 受理を `sendPhase == .sent` で gate する（既存バグの修正）

`SMBClient.swift:5884` の `guard var pending = pendingResponses[header.messageId]` は
**record の存在だけで応答を受理する**。pending の登録は `withCheckedThrowingContinuation` の
内側 (`:5638`)、`markRequestSent` は send 完了後 (`:5661`) なので、**wire に出ていない request へ
応答が配送されうる**。これは**既存の穴**（long-lived reader が作るものではなく、窓を広げるだけ）。

- 受理条件に `sendPhase == .sent` を足し、未送信 id 宛の frame は `orphanResponses` へ回す
  （`markRequestSent` が replay するので失われない。M1 のテスト 6 がその経路を固定済み）
- 変異: gate を外す → 新テストが red になること

#### M3 — long-lived reader の導入（**生存条件の切断が本題**）

- `readerTask: Task<Void, Never>?` と `readerGeneration` を session が所有する
- **起動**: 最初の 1 本の send 完了まで待つ（ユーザー決定 ①(a)。perf fixture が 130 frame 超を
  preload するのに対し `orphanResponses` の上限が 64 のため）。以降は **individual な send の
  完了に依存せず** cancel か transport error まで生存
- `receiveLoop` の `while pendingResponses.values.contains { $0.sendPhase == .sent }`（M2 で
  派生述語にした箇所）を**外す**
- **cycle 回避**: reader closure は `transport` と `weak self` だけを捕捉。raw frame の読み取りは
  nonisolated helper に分け、1 frame ごとに session actor へ戻す。`Task { await self.receiveLoop() }`
  の形にしない
- **generation を frame / credit grant / error / CANCEL task / orphan key に通す**（完了通知だけの
  照合では不十分。D3 敵対 I5）
- **`readerState` を単一の真実にする**（cancel 済みで非 nil の handle を running と誤認しない）
- **`disconnect` の graceful cleanup 中は reader を生かす**（TREE_DISCONNECT / LOGOFF 完了後に停止。
  `SMBClient.swift:5399` は `Task.detached`）
- **`failWire` と `closeTransport` の責務を分ける**（reader の transport error が `failWire` だけを
  呼ぶと「reader は死んだが transport は生きている」状態になる。`:5420` / `:6151`）
- **close 由来の `CancellationError` を wire failure として記録しない**
- **`recordCreditGrant` → `dispatchReceivedPacket` の順序を維持**（`:5840`。別 Task へ投げない）
- 🚨 **移行で確実に壊れるテスト 2 箇所**: `SMBeeTests.swift:8293` と `:8596` が
  `while await session.receiveLoopRunningForTesting() { ... }` で **reader の停止を待っている**。
  long-lived reader では止まらないので**無限ループになる**。transport close 基準へ直す

#### M4 — transport 契約 + fixture 移行 + credit 循環の回帰テスト

- 「`close()` は待機中の `receive()` を起こす」を `SMBTransport` の doc に明記する。
  **必須メソッドは追加しない**（public API 非破壊）。外部 conformer には強制できないので残リスク
- `InMemoryTransport` に `.waitUntilClosed` を **opt-in** で追加（既定は現状の `.eofWhenDrained`）。
  drain 後は `throw` せず**空配列を返す**実装 (`SMBTransport.swift:40`) が前提
- `ControlledReceiveTransport`（テスト側）に **cancellation handler を追加**
- 🚨 **credit 循環の回帰テストの刺激**: `initialCredits=1` + `charge=2` で park させるだけでは
  **旧構造も新構造も grant が来ずに停止し、変異で red にならない**（D3 敵対が反証）。
  「**queue 済みの credit grant を reader が消費する**」形にすること
- 変異: reader の起動を `markRequestSent` に戻す → red

#### M5 — 全体検証

macOS / Linux unit / `bin/e2e/container-samba.sh` / `bin/ci/verify-agent-push` rc=0。

### 残リスク（設計では閉じない。実測か受容が必要）

- 外部 `SMBTransport` が `close()` で blocked `receive()` を解除する保証は**強制できない**
- Swift 6.2 の actor `deinit` から reader cancel / transport close ができるか（**未検証**）
- idle な long-lived reader の CPU / メモリ影響（**未測定**）
- CANCEL 後に server が final を返さない場合、tombstone が無期限に残る（回収方針が未定）
- **hang の真因は依然未確定**。本タスクは構造改修であって hang の修正ではない
  （[`013`](waiting/013-linux-ci-intermittent-hang.md) は `waiting/` で再現待ち）

### 却下済み（再提案を防ぐため記録）

- `sentResponseMessageIds` を 4 コレクションに分割する案 / `SMBRequestLedger` 型を新設する案 /
  集合を tombstone として残す案 — いずれも**同期すべき台帳が増える**ので却下（D1 の 4 案から選定）
- 当初の回帰テスト案（`initialCredits=1` + `charge=2` の park だけ）— 変異で red にならない
