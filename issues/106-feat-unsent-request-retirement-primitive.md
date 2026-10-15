# 106 (feat): 未送信 request 退役 primitive (request の識別・credit の所有・送信の直列化・drain の期限)

起票日: 2026-10-04

## 概要

送信前の request を、MessageId や credit を壊さずに退役させる仕組みを作る。
MessageId を割り当てる前は、ローカルで退役できる。割り当てた後は MessageId も credit も返さず、送信して drain するか、session を終わらせる。

次の課題の共通の土台になる。
- issue 010 の P2-2: cancel の後に final が来ないと、reader が session を保持し続ける。
- issue 069 M2: cleanup の soft / hard の期限、Tree の隔離。
- issue 104: compound の応答の分割。
- READ / WRITE の pipelining。

## 設計

承認済みの設計は下の「承認済み設計」節にある（v3 に 2〜4 周目のレビューの R1〜R5 を反映した版）。
設計の経緯（概要。成果物は gitignore された `tmp/retire/` 配下）:
- 設計 v1 は、revert 前の M3（常駐 reader）を前提にしていた。
- 入れ直した M3 に合わせて v2 を書いた。
- 敵対レビューを 4 周回した。P2 は 6 → 3 → 2 → 0 件と減り、P1 は一度も出なかった。
- 2026-10-04 に、ユーザーの委任（「codex と Claude が問題ないと思うなら承認でいい」）で承認した。

commit の分け方（各 commit が単独で契約を満たす）:

1. request の識別と credit の所有の準備（送信経路は旧経路のまま）— **完了**
2. 受信の土台と compound の相関（認証前に grant を適用しないようにする。issue 104 を含む）— **完了**
3. 新しい送信経路の有効化、取消、wire の drain の期限、reader の後始末（issue 010 の P2-2）— **完了**（2026-10-10、d085790）
4. issue 069 M2 の統合
5. READ / WRITE の ticket と delivery の統合（pipelining）

## 進捗

### Commit 1（2026-10-04、完了）

- commit `feat(session): 未送信 request 退役 primitive の Commit 1 — request の識別と credit の所有を準備する`
  と `fix(session): SMBRequestIdentity の memberwise と同じ init を消す (SwiftLint strict の unneeded_synthesized_initializer)`。
- 入れたもの:
  - `SMBRequestIdentity`。session instance と generation と session 内の連番の組。
    UUID にしなかったのは、Linux では request ごとに乱数源を読むため。
  - pending と `activeRequestIdentities` の対の管理。
  - `SMBUnsentRequestRecord`。credit の shrink、一回限りの refund、ack の後だけ閉じる receipt、
    session terminal の不可逆化、caller の完了権の一回取得を持つ。
  - `startCreditReservation(window:charge:)` / `(window:maximumCharge:)`。record が credit window を直接呼ぶ。
  - `SMBSessionMonotonicTime`。
  - `SMB2CreditWindow` のテスト専用 hook。
- 実装の敵対レビュー 4 周（P2 は 4 → 4 → 1 → 0 件）:
  - 2 周目: 受け取り枠の登録と Task の作成が別々の API だったのが根だった。1 つの操作にまとめる構造に直した。
  - 3 周目: 任意の closure を受け取る API だと、credit を取った後の throw で credit を失った。window を直接呼ぶ API に絞った。
- 検証:
  - テスト: macOS 627 件、Linux container 615 件を 2 回、失敗 0。make lint-analyze は 0 件。
  - 変異 19 本で red を確認した。smoke は 3 profile とも pass。
  - CI は Test / E2E / Performance とも success（[Performance run](https://github.com/jiikko/swift-smbee/actions/runs/37162884634)）。
    gate は同じ runner で交互に 20 組を測り、paired effect は read throughput −1.41%（95% CI −2.18〜−0.66%、Holm p=0.0123）、
    user CPU +3.10%（+1.60〜+4.61%、p=0.0083）。どちらも上限の内側。throughput の median は 1335.5 / 1361.3 MiB/s。
  - テストの件数はそれぞれ 37 件の skip（E2E など）を含む。
- 踏んだこと: 自分で後から入れた修正が SwiftLint の strict に当たり、最初の push で CI の Test が落ちた。
  手元では `make lint-analyze` しか回しておらず、CI の strict lint とは別物だった。

### Commit 2 の受信境界の脅威モデル（2026-10-04、敵対レビュー 2 周目の後に固定）

敵対レビューの 1・2 周目は、どちらも違う不変条件で P2 を 3 件ずつ出した。受信の攻撃面が広く、範囲が決まっていなかった。
3 周目からは次の線で判定する。
- **範囲内（commit を止める）**:
  - 設計 §5 が約束した検査。対象は、slice ごとの AEAD と署名、session 全体の保護要件、wire 順の仮状態、
    duplicate final の grant 前の拒否、未知 MID の discard、R1 の request ごとの protection policy。
  - master からの退行。
- **範囲外（記録に回す。commit を止めない）**: master と同じ既存の穴で、§5 が約束していないもの。

範囲外として記録した既存の穴:
- **AsyncId の identity 間の一意性**（2 周目 P2-2）。
  - 発火条件: signing required の平文 session で、request B の正常 interim を観測できる攻撃者が、
    まだ AsyncId を持たない request A に偽の interim を返し、B の AsyncId を流用させる。
  - 結果: A を cancel すると、クライアントが正しく署名した CANCEL（MID=A、AsyncId=b）が、AsyncId で検索するサーバで B を取り消す。
    既に記録済みの A の AsyncId を上書きする攻撃は拒否される。初回の記録だけが通る。
  - master も同じで、interim の AsyncId の照合は request の中に閉じている（`dispatchReceivedPacket` の interim 分岐）。
  - 直すには、wire outstanding の identity をまたいで AsyncId → identity を引く索引が要る。
    MS-SMB2 §3.3.4.2 の AsyncId の一意性と §3.3.5.16 の CANCEL の検索規則に合わせる。
  - 再提起に要るもの: この索引を設ける commit で、同一 compound の staged state と既存の pending の両方で
    別 identity の AsyncId を拒否するテスト。

### Commit 2（2026-10-04、完了）

- commit `feat(session): 未送信 request 退役 primitive の Commit 2 — 受信の土台と compound の相関 (issue 104 を含む)`。
- 内容:
  - compound の slice ごとに AEAD・署名・内外の SessionId・request ごとの protection policy・相関を、仮状態で wire 順に検証する。
    全 slice が通ったときだけ確定する。
  - 認証の前に grant を適用しない。
  - 未知の MID は捨てる。
  - early final は送信完了まで保持する。
  - STATUS_PENDING と MID 0xFFFF... の署名の例外を持つ。
  - VALIDATE_NEGOTIATE_INFO は署名か AEAD を必須にする（R1）。暗号化して送った request への平文の応答は拒否する。
  - 単一 frame では slice / effect の配列を作らない。
- 敵対レビュー 3 周。範囲内の P2 は 3 → 2 → 1 → 0。2 周目の後に上の脅威モデルを固定した。
- 性能:
  - CI（Linux x86_64、20 組）の paired effect は read throughput −0.87%（95% CI −1.56〜−0.21%）、user CPU +1.08%、
    system CPU +0.70%（[Performance run](https://github.com/jiikko/swift-smbee/actions/runs/37194519561)）。
  - 手元の Linux arm64 container の 5 組では −10.6% / +8.3% / +33% だったが、x86 の CI には出なかった。
    M3 では逆に x86 で大きく出たので、arm の container の数字は x86 の CI の予測に使えない。
  - 最初の実装は、単一 frame でも frame ごとに配列を 2 つ確保していた。macOS の Time Profiler で見つけて削った。
- c4d354e の CI の Test は「Cancel and teardown bounded stress」で落ちた。原因は Commit 2 ではなく issue 010 M3 の入れ直しの退行で、
  `fix(session): close が cancel 済みの keepalive ECHO の drain を待ってから graceful teardown を送る (issue 010 M3 の退行)` で直した。
  その commit の CI は Test / E2E / Performance とも success。
- Commit 3 へ申し送り: close は keepalive の ECHO だけ drain を待つ（上の fix）。cancel 済みの他の request への一般化は Commit 3 の drain の期限で行う。

### Commit 3（2026-10-05、push の後に revert）

- commit `feat(session): 未送信 request 退役 primitive の Commit 3 — post-auth の送信経路の有効化、取消、wire の drain の期限`（3d6eace）を、
  `revert: issue 106 Commit 3 を戻す — CI の Linux x86 で read -22% / user CPU +46%、P2-2 のテストが flaky` で戻した（ユーザー決定）。
- 機能: 受け入れ条件はすべて満たしていた。
  - 変異 13 本と、敵対レビューの指摘ごとの変異で red を確認した。
  - テストは macOS 669 件 / Linux 657 件で失敗 0。
  - stress は macOS 20 回 / Linux 10 回、Samba は 2 profile で通った。
  - 敵対レビュー: codex 1 周（範囲内 P2 4 件）と Claude opus 2 体（範囲内 P2 1 件）。どれも直した。
- **CI の性能 gate が FAIL**（Linux x86_64、20 組、[run](https://github.com/jiikko/swift-smbee/actions/runs/37240281391)）。
  - read: throughput −22.3%（95% CI −23.0〜−21.7%）、user CPU +45.8%、system CPU +40.1%。
  - write: throughput −7.8%、user CPU +21.4%。
  - 計測中の署名処理（SMB 3.0.2 / AES-CMAC、固定の key）は master の benchmark と揃えてある。新しい送信経路そのもののコストと見る。
  - 手元の macOS では read −0.75% / user CPU +1.2%（3 組）。arm64 の Linux container は 3 組でばらつきが大きかった。
    x86 の CI の数字は、どちらからも予測できなかった。
- **CI の Test も FAIL**: `testFinalDrainReleasesTimerBeforeCreditGrantAckAndReapsRecordAfterAck` が Linux で 1 回落ちた。
  record の数を見る時点が早く、ack の処理と競合する（レビュー 2 周目の P3 で指摘されていた箇所）。
- 性能の経緯:
  - 最初の実装は、benchmark が define なしでは新しい経路を通らなかった（gate の偽の緑）。
  - define つきの計測では、Linux arm64 で read −33.8% / user CPU +47%、macOS で −8〜−21% だった。
  - 次を入れて、macOS は −2% まで戻した:
    - credit に余裕があるときは予約を同期で済ませる。
    - 通常の request では drain の timer を作らない。
    - header を直接読む。
  - Time Profiler では、sender loop の起床と開始（frame ごとに約 5 µs、inclusive）と、response effect と dictionary の更新が残っていた。
    request ごとに `SMBSessionActiveRequestRecord`（class）を確保している。
- **入れ直しの条件**:
  - CI の 20 組の gate を通る（throughput −15% / user CPU +25%）。
  - 上の flaky なテストを直し、stress と同じように繰り返しても落ちないことを確かめる。
  - Linux の性能を x86 で測る手段を用意する。手元の arm64 と macOS では予測できない。
    候補: 変更を別の branch に push して、Performance の workflow を workflow_dispatch で回す。
- レビューの P3（commit を止めない後続の課題）:
  - P2-1 の close のテストは、snapshot の直後に完了数を見ていて競合する。join を待ちに入ったことを確かめてから見る。
  - compound の final の credit の ack で record が回収されることを確かめるテストが無い。credit の fast path のテストも無い。
  - source の形を見るテスト（`testSourceShapeSenderLoopHasNoNestedTasksOrGlobalExecutorHops`）は射程が狭い。
- codex の週の枠が 99%（2026-10-05）で、10-10 までは Claude で進める。

### 次（2026-10-05 にいったん停止。ユーザー判断）

- Commit 3 を入れ直す。条件は上の「Commit 3」節の「入れ直しの条件」。
  - 実装は 3d6eace に残っている（master の履歴の中。revert は 5b0d6c9）。
  - 再開の手順:
    1. `git revert 5b0d6c9` 相当で戻した差分を worktree に取り出す。
    2. CI の Linux x86 で user CPU +46% の原因を profile で特定して削る。
    3. flaky なテストを直す。
  - x86 で測る手段が要る。branch に push して workflow_dispatch で Performance を回す案は、branch を切るので
    ユーザーの許可が要る（この repo は指示なしに branch を切らない）。
- Commit 4（069 M2）と Commit 5（pipelining）は、Commit 3 の上に積むので待つ。

### Commit 3 の入れ直し（2026-10-09〜、codex-drive）

- 計測の手段: `performance.yml` の workflow_dispatch に `reference_sha` を足した（commit `ci(performance): workflow_dispatch で比較の相手 (reference_sha) を指定できるようにする`）。
  候補を branch `perf/106-commit3` に push し、master の先端を比較の相手にして同じ 20 組の gate を回せる。branch はユーザーの許可を得て作った（計測が済んだら消す）。
  - 同じ commit に手動起動の run が並ぶと verifier が掴んでいたので、`verify-agent-push` / `verify-agent-performance` を push の run だけ見るように直した
  - 🚨 master の ref で手動起動すると、concurrency で push の Performance の run が取り消される。手動起動は branch で行う
- M0: 3d6eace を今の master に載せ替えた（衝突 10 か所。pipelining の READ / WRITE の transfer ticket も post-auth の sequencer に載せた）。
  macOS 737 件 / Linux container 744 件が green、smoke 3 profile が通過。計測用の branch `perf/106-commit3`（2ef2a6c。master に入れた後に削除）
- M0 の x86 の計測（run 37916870148、20 組、比較の相手は master dfe6815）:

  | | throughput | user CPU | system CPU |
  |---|---|---|---|
  | read | −19.2%（95% CI −19.9〜−18.9%） | +39.3% | +34.0% |
  | write | −6.0% | +18.5% | +5.9% |

  gate（−15% / +25%）は read が両方で超える。前回（−22% / +46%）と同じ傾向で、pipelining の後でも新しい送信経路のコストはほぼ変わらない
- 途中で見つけて master で直した、別のテストの不安定さ:
  - WRITE の pipelining のテスト 2 本が request の Task を `.background` で起こしていて、macOS の単独実行で 5/10 失敗（issue 102 に記録）
  - `testReservationGrantedAfterOperationDeadlineIsRefunded` が CLOSE の応答の前に残高を読んでいて、CI の Linux で 1 回失敗
- M1 の観測（2026-10-09）:
  - callgrind（Linux container arm64、read_stream / write_stream の synthetic）の総命令数は read が master 75.06M → M0 78.71M（+4.9%）、
    write が 120.95M → 123.77M（+2.3%）。x86 の user CPU +39% / system CPU +34% を命令数では説明できない
  - codex が命令数を削った 4 段（m1〜m1d）は read を 77.52M（M0 比 −1.5%）までしか減らせなかった。差分は `tmp/c3/m1-partial-instr.patch`
    に退避して worktree からは戻した（codex の 5h 枠切れで途中終了）
  - CI の x86 の計測ログ（`/usr/bin/time -v`、テストの実行 19 回ずつ）の voluntary context switch の中央値は master 131,814 / M0 255,314（+94%、
    ばらつき ±0.4% 以内）。CPU の増分は命令の量ではなく、スレッドの待ちと起床の回数から来ていると見る
    （callgrind はスレッドを直列に走らせるので、起床・futex・context switch のコストを数えない）
- 手元の Linux container（arm64、swift:6.2、4G）で再現した（`/usr/bin/time -v swift test -c release --skip-build --filter SMBeeResourcePerformanceTests/<test>`、
  各 3 回、ぶれ ±1% 程度。手順: container の中で `swift test -c release --scratch-path /tmp/b --filter NoSuchTest` で build し、`/usr/bin/time -v swift test -c release --skip-build --filter SMBeeResourcePerformanceTests/<test>` を 3 回。worktree は削除済み）:

  | 1 回の実行 | voluntary context switch | system CPU | throughput |
  |---|---|---|---|
  | read_stream master | 約 560 | 0.02 秒 | 約 2,690 MiB/s |
  | read_stream M0 | 約 177,000 | 1.66 秒 | 約 2,300 MiB/s（−14%） |
  | write_stream master | 約 540〜640 | 0.03 秒 | 約 800 MiB/s |
  | write_stream M0 | 約 31,500 | 0.15 秒 | 約 850 MiB/s |

  READ の経路で request ごとにスレッドを眠らせて起こしている。この数を M1 の指標にする（目標は master の桁）
  - request 1 本あたり: read は 1 回の実行で READ 約 51,200 本（8 MiB を 64 KiB ずつ × 400 回）→ 約 3.5 回 / READ。
    write は WRITE 約 8,960 本 → 約 3.5 回 / WRITE。master は約 0.01 回 / request
  - 見立て（未検証）: 呼び出し元 → sender loop → 呼び出し元の受け渡しのたびに、眠っている worker thread を起こしている。
    第一候補の直し方は、競合が無いとき（queue が空で送り手がいない）に呼び出し元が送り手を兼ねる形（flat combining）。
    承認済み設計が sender loop を分けた理由（cancel の隔離・送信の所有）に触れるので、実装の前に設計レビューに通す
  - 🚨 フィルタは `SMBeeResourcePerformanceTests/<test>`（ファイル名の `SMBeePerformanceRegressionTests` ではない）。最初の 2 回は 0 件実行の空振りだった
- 帰属の実験（2026-10-10、arm64 container、各 3 回、`Executed 1 test` 12 件を確認。codex の報告の要点）:

  | 実験（M0 に当てる。捨てる前提） | context switch / READ | read の throughput |
  |---|---|---|
  | master | 0.011 | 2,672 MiB/s |
  | M0 | 3.46 | 2,288 |
  | E1: reader の起動を full-send の後へ（early final の契約が壊れる） | 1.28 | 1,001 |
  | E2: transport の send / receive を `nonisolated(nonsending)` に | 1.95 | 852 |
  | E3: READ の credit 予約の同期の近道 | 3.46 | 1,832 |
  | E4: 列が空なら呼び出し元の actor turn で直接送る | 3.21 | 1,597 |
  | E5: master に E2 | 2.27（master より増える） | 2,216 |

  - context switch を減らした変更は、どれも throughput を大きく落とした。**context switch の数は性能の向きの指標にならない**。主な指標は throughput と user + system CPU に戻す
  - 効果は足し算にならない（E1+E2 でも差 3.45 のうち 2.03 / READ）。境界を 1 つずつ削る方向は外れと見る
  - 実験の throughput は回によって揺れている可能性がある（E3 は context switch が変わらないのに −20%）。次の実験は master / M0 を同じ回で測り直して揺れを除く
- E6（2026-10-10）: session ごとの直列 executor（`SerialExecutor` + `TaskExecutor`、直列の DispatchQueue）を session actor の executor にし、
  sender / reader / cleanup の Task と READ / WRITE の driver を同じ executor に載せた（`Task(executorPreference:)` / `withTaskExecutorPreference`）。
  - 手元（arm64、同じ container の r2。裏で別セッションの obaket の負荷テストが走っていて r1 は揺れが大きく除外）: read は master 2,301 / M0 2,132 / E6 2,849 / master+E6 2,801 MiB/s
  - **CI x86（run 37958351629、20 組、比較の相手は master 735ac48）: read throughput +20.3%・user CPU −27.4%・system CPU −54.7%、
    write throughput +7.1%・user CPU −16.7%**。gate を大きな余裕で通る
  - 計測専用の commit（branch `perf/106-commit3-e6`、0d6f84c）。`TaskExecutor` は macOS 15、`ExecutorJob` は macOS 14 からの API で、
    package の最低対応版 macOS 13 では build できない。利用側の obaket は macOS 15 以上が前提
  - 未検討のリスク: READ の `onChunk` / WRITE の supplier など利用者の callback が session の直列 executor の上で走ると、長い処理が同じ session の
    cancel・close・期限の処理を待たせる
- 2026-10-10: ユーザーが E6 の採用と、最低対応版の macOS 13 → 15 への引き上げを承認した（利用側の obaket は macOS 15 以上）
- E6 の設計（codex sol-high が書き、敵対レビュー 2 観点を通した。全文は削除した worktree の `tmp/design-e6.md` にあった。要点をここに残す）:
  - session ごとに直列 DispatchQueue の `SerialExecutor` + `TaskExecutor` を 1 つ持つ。session actor と、sender / reader / cancel / timer / cleanup の Task、
    READ / WRITE の driver を載せる。enqueue は `runSynchronously(isolatedTo:taskExecutor:)` で両方の executor を runtime に渡す（E6 の計測版は serial だけで不完全）
  - 利用者の callback（onChunk・supplier・onEntry・onChange・onAction・直接の progress）は session から独立した共有の concurrent executor C で走らせる。
    長い callback が同じ session の cancel・close・期限を塞がないため。chunk ごとの往復の費用は計測で確かめる
  - transport の新しい契約: async の本体でブロックする syscall を呼ばない、close は短時間。POSIX（受信は detached、送信は専用 queue）・NW・in-memory は構造上満たす。
    外部の実装向けに doc へ書く
  - close の自己待ち: fault を起こした reader / sender / timer は同期の close と terminal 化だけを行い、join は別の terminalizer に渡して自分は終わる
  - session close は callback を join しない。callback が戻らないと operation の return とその参照は残りうる（既存の協調的 cancel の契約）
  - 敵対レビューで採用した 4 件: callback 中の close が配送中の slot を空にする（lease の回収を分ける）、transfer の drain 期限が join を driver に頼る（terminalizer へ）、
    通常 request の timeout の勝敗が job の順で決まる（絶対の応答期限を保存して同じ clock で比べる）、cancel の drain 期限に外側の操作の期限が入らない（登録時に捕まえる）。
    後の 2 件は executor と無関係な M0 の契約の穴
  - 実装の分割: M1a executor の製品化 → M1b callback の境界と lease → M1c 期限と後始末 → M2 flaky なテストと P3
- M1a（executor の製品化、macOS 15）: x86（run 38000931264、20 組、比較の相手は master 1857fe1）で read throughput +34.0%・user CPU −36.9%・system CPU −54.0%、
  write +12.1%・user CPU −21.3%。macOS 740 件 / Linux 747 件が green
- M1b（callback を executor の外の C へ）: 手元 arm64 の read が M1a 約 3,510 → 約 1,275 MiB/s（−63%、chunk あたり約 31.5 µs）。C を `globalConcurrentExecutor` に替えても
  約 1,250〜1,300 で変わらない（S を出て戻る往復そのものが高い）。write は変わらない
- 2026-10-10 ユーザー判断: **利用者の callback は session の executor の上で走らせ、契約を明記する**（「短く。重い処理は利用者が自分の Task / actor へ」を doc に書き、
  debug build で長い callback を診断する）。同期の callback が走る間は同じ session の cancel・close・期限が待たされる（master より悪い点として受け入れる）。
  M1b の lease の分離（callback の実行中に close されても配送中の slot を callback の後に一回だけ精算）は残す
- M1b'（callback を executor の上に戻し、契約を DocC `Callbacks.md` と各 API の doc に書いた。debug build でだけ 100 ms を超える callback を診断）:
  macOS 744 件 / Linux 751 件が green。x86（run 38009245555、20 組、比較の相手は master 6929bf5）で read +29.2%・user CPU −34.0%、write +12.0%・user CPU −21.1%
- M1c（6543df8）: A2 transfer の drain 期限の処理を独立した terminalizer の `closeTransportAndWait` へ、A3 通常 request の timeout を full-send 時に保存した
  絶対の応答期限と同じ clock で判定（exact な期限以降は timeout）、A4 request 登録時に外側の `SMBOperationDeadline` を捕まえ、初回 cancel で
  `min(cancelAt + grace, 外側の期限)` に固定。各修正を個別に戻すと対応するテストが red。hot path に増えたのは登録時の TaskLocal の読み取りだけ
- M2（f3e70d4）: `testFinalDrainReleasesTimerBeforeCreditGrantAckAndReapsRecordAfterAck` は ack の後の回収の event を待つ形に（macOS 30/30、Linux 10/10）。
  close のテストは reader の join が待ちに入った event を見てから検査。compound の final の credit ack での回収、credit の fast path のテストを追加。
  source の形のテストは sender の hot path の複数箇所に広げた（per-frame の nested Task の検出は executor の後も意味がある）。5 種類の変異で red を確認
  - macOS 749 件 / Linux 756 件が green
- 実装後のレビュー（2026-10-10、codex sol-high の 4 観点 + merger、14 件 → 12 件）。指摘ごとに HEAD で再現する失敗テストを書き、master と比べてから採否（M3、3625184）:
  - 直した（再現 + master からの退行 / 承認済み設計の違反）: D1 認証後の CLOSE の期限が credit 待ち・送信の列の待ちを覆わない、
    D2 止めた transfer の未送信 request が送られる（判定は MID の採番と同じ actor turn の同期の関数にし、返金だけを退役の経路で await）、
    D3 download の progress の二重通知、D4 通常 request の timeout / 送信失敗が独立した join を始めない、DL1 cancel の tombstone に旧経路の 64 件上限が無い、
    DL2 compound の final の期限に slice ごとの検証時刻を使う
  - テストの素通り 5 件を直した（新しい経路を通らない oracle、FIFO と LIFO を区別できない、timer の配置の未検査、Task の書き方で source の検査を抜ける、reconnect の oracle）
  - 記録のみ: D5 debug の sink を actor の上で同期に呼ぶ（master と同じ既存の挙動。debug の設定でだけ起きる）
  - 変異 16 本で red。FIFO のテストは 2 本の Task を同時に起こして列に入る順を前提にしていて、Linux で逆順になった（e4aae42 で、2 本目が列に入ってから 3 本目を起こす形に直した）
- 2 周目の敵対レビュー（M3 の修正が攻め口）: 3 件を再現して直した（M3b、2c26827）: drain の完了の判定で時刻を取り直していた（経路ごとの成立時刻で比べる）、
  期限で退役した CLOSE の記録を enqueue / catch が消していた、M3 の D3 の修正が progress の既知のサイズと速度を落としていた（stream の emitter の一経路に戻した）。
  D2・D4・DL1 の修正は壊せなかった
- 3 周目（M3c、c2850e0）: 期限による退役の helper が送信済みの `.draining` を上書きしていた → cleanup の FileId の台帳の書き込みを `transitionCleanupLedger` に寄せ、
  遷移表で固定し、関数の外での書き込みを source の検査（`testSourceShapeCleanupLedgerIsMutatedOnlyThroughTransitionFunction`）で止めた（外で書き込む変異で red）。
  download はエラー・cancel・short read のときも progress の通知の完了を待つ（master の静的な download にあった、戻った後に通知が届く穴も塞がる）
- 4 周目（M3d、ec3ca64）: 台帳に試行の識別子が無く、遅れた CLOSE A が同じ FileId の CLOSE B を退役させる → 台帳は 3 周続けて破られたので、条件の継ぎ足しをやめ、
  各記録に所有者（`SMBRequestIdentity`）を持たせて所有者が一致する遷移だけを適用する構造にした。M3c で progress の待ちを CLOSE・ファイルの後始末より前に置いた
  順序の誤り（指示の誤り）も直し、後始末を先に済ませる
- macOS 767 件 / Linux 774 件が green。smoke は M2 の時点（f3e70d4）で 3 profile 通過（M3 以降は未実施）
- 5 周目（M3e、2026-10-10）: 台帳の所有者・遷移表・download のエラー経路は壊せなかった（収束）。新しく 1 件: 静的な `SMBClient.read` が progress を
  `withSession` の再試行の外で作っていて、再接続の後に前の試行の受信量が残った（master は試行ごとに作っていた。退行）→ 試行ごとに作る。
  修正前の複製で red・修正後 green・外へ戻す変異で red。この周の修正は判定のロジックを新設せず直接の実測で確かめたので、規定の例外として周回を打ち切った
- 仕上げで見つけたテストの不安定さ 2 件（どちらもテスト側。観測で確定）: cleanup の配置のテストの helper が pending の登録を件数の waiter に通知していなかった
  （単独で 25 回中 18 回失敗 → 登録後の合図を待つ。macOS 50/50・Linux 20/20）、同期の READ callback のテストが transfer の停止を「cancel の適用」の代わりに待っていた
- **master へ（d085790、1 マイルストーン = 1 commit に squash）**。macOS 768 件（3 回連続）/ Linux 775 件（2 回連続）が green、smoke 3 profile、
  CI x86 の 20 組（run 38038353368、比較の相手は master de6e32e）: read throughput +20.1%・user CPU −28.3%・system CPU −54.7%、
  write +8.5%・user CPU −17.5%
- master の push の `verify-agent-push`（d085790）は rc=0。Performance（run 38040191798、前回の成功した master との 20 組）: read throughput +19.4%・user CPU −27.6%、
  write +7.8%・user CPU −16.2%。issue 010 の P2-2 はこれで閉じた（010 を done へ）
- 計測用の branch `perf/106-commit3` / `perf/106-commit3-e6` は削除した
- Commit 4（069 M2）と Commit 5（READ / WRITE の ticket と delivery の統合）はこの上に積む

### Commit 4（issue 069 M2 の統合、2026-10-11〜、codex-drive）

- 設計の差分（codex sol-high が今の master に対して書いた。本体の checkout の `tmp/c4/design-c4.md`（ignore されていて手元にしか無い。§13 が最新の決定）。要点をここに残す）:
  - 所有者を 3 種類にする: request（既存の `SMBRequestIdentity`）、Tree の incarnation（session・generation・TreeId・連番。TreeId の再利用と reconnect で取り違えない）、
    facade / close / operation の lease。Tree の状態も cleanup の台帳と同じく遷移を 1 関数に寄せる
  - 実装は P1（operation lease と parent-child barrier の型と harness）→ P2（資源の discriminator・Tree 単位の credit の取消の型）→
    A（一体の有効化: Tree の隔離と受付、scoped TREE_DISCONNECT、soft / hard の期限を intent 時に固定、cleanup の結果の報告 = 102 #9）
- 設計の敵対レビュー（2 観点）で採用: 列で待つ cleanup が softAt の後に MID を得る（採番の直前に照合）、解放済みの lease を継承した Task の close が join を省く、
  P1 を単独で production に入れると credit 待ちと循環待ちになる（P1 は harness まで、接続は A へ）、外側の operation の期限が保存した body のエラーより優先する
- ユーザー判断（2026-10-11）: 公開のエラーを 2 つ足す（`treeUnavailable` と後始末の失敗を包む case。watch の再接続・withSession の再試行の対象にしない）、
  使用中の lease を持つ callback の中からの close は後始末を始めて戻る（外からは完了を待つ）、後始末の hard の期限は既定 60 秒で必ず有限
- 準備段（P1 / P2、9e31197）: operation lease・barrier・Tree の incarnation・固定の soft / hard の期限・Tree 単位の credit の取消の型と harness。production は未接続
- 有効化（A、0fc688b）: Tree の隔離と受付、scoped な後始末と結果の報告（102 #9）、固定の soft / hard の期限、公開のエラー 2 つ。R1〜R10 の変異はすべて red。
  macOS 799 件 / Linux 806 件が green、smoke 3 profile
  - x86（run 38123382488、20 組、比較の相手は Commit 3 を含む master 129eb64）: read throughput −6.8%・user CPU +9.3%、write −1.3%・user CPU +3.5%。
    すべて gate（−15% / +25%）の内側（"within noise" 判定）。Commit 4 で増えた判定の分の上乗せと見て、深追いしない（ユーザー指示）
  - 懸念（実装後のレビューで判定する）: A で M3d の production の A/B 所有者のテスト（`testLateCleanupDeadlineCatchForCloseADoesNotRetireCloseBForSameFileId`）と
    M3b の 2 本を消したが、`retireCleanupFileIdForDeadlineIfNeeded` はまだ在る
- 実装後のレビュー（2026-10-11、4 観点 + merger、25 件 → 15 件）。P1 が 6 件:
  - F2 / F3: 設計の中核の Tree の barrier（wire / retirement の receipt）が production に接続されていない（`beginBarrier` / `completeBarrier` の呼び出しが無い）。
    File CLOSE の wire の drain が残っていても TREE_DISCONNECT を送る。試験は receipt を手で登録していて素通りした
  - F1: transfer の credit の待ちが、残高を見た後に消費されると scope の無い経路で park し、Tree の隔離で解除されない
  - F4: callback の中で始めた親の close が、子の close まで「開始だけ」で戻り、子の lease を待たずに後始末へ進む
  - F5: Tree の後始末が成功しても、その incarnation の File の台帳が残り、64 件に達すると共有 transport を閉じる
  - F6: full-send の成立時刻と owner の回収時刻を区別できない
  - P2: lease / facade の記録が履歴に比例して増える（F7）、64 件の上限を File と Tree の合計で数えない（F8）、消した A/B の所有者の production の試験（F9）、
    遅れて届く soft の callback（F10 / F11）、テストの素通り 4 件（F12〜F15）
- 指摘 F1〜F15 の修正（worktree の 5145816、codex luna-max）:
  - Tree の barrier を production に配線した。Tree の隔離の時点で、committed の request に wire の receipt、未送信の request と credit 待ちに retirement の receipt を張る。
    完了は最終応答の除去・refund・送信前の catch・session terminal の各経路で行う
  - transfer の credit: 即時に取れなければ必ず取消の token を作って Tree 単位の台帳に入れる（正の残高を見た後に枯れた場合も）。即時に取れる通常の経路は token も lock も作らない
  - 公開の親 close は子の Tree の lease を待つ（期限は cleanup の期限で有限）。成功した TREE_DISCONNECT の後は、その incarnation の retiredUnknown の File 台帳を消す
  - full-send の成立時刻を記録し、soft の期限の判定に使う（送信中に soft が来ても full-send が soft より前なら draining）。final は soft の timer の identity を無効にする
  - File の登録は File + Tree の合計で 64 件の上限を数える。soft の期限を過ぎた File の owner を final / catch で回収する。lease は解放で消し、facade は close の join 後に退役させる
    （lease と barrier の数は祖先ごとの件数で持ち、判定を O(1) にした）
  - 消した A/B 所有者の production のテストを復元した。F12〜F15 のテストは production の経路を通るように直した
  - 変異: F1〜F15 の各指摘に、修正を戻す変異を当てて対象のテストが red（codex が実行）。初回に green だった F4・F8・F9・F12・F13・F14/15 は、
    production の修正そのものを戻す形に当て直して red。codex の判定式が出した `compile_error=True` は XCTest の assert 失敗の行（`file:line: error:`）を拾った誤検知で、
    実際にはテストが実行されて落ちている（log で確認）
  - 検証: macOS 812 件 green・strict lint 0（自分で再実行）。Linux 819 件 green・analyzer 0 は codex の報告
  - codex の最後の段（手元の container で master と 20 組を比べる計測）は Bash の時間上限で止まった。手元の負荷で数字が汚れるので container を止め、性能は CI の x86 gate で見る
- 修正への敵対レビュー 2 周目（2026-10-11、3 観点。barrier・台帳の観点は codex の使用上限で落ち、23:34 のリセット後に再実行する）:
  - 期限・credit の観点（P1 が 4 件、P2 が 1 件）:
    - final を soft の前に受けると、send owner が残っていても soft の timer の identity を消すので、send が戻らなければ期限を超えて待つ
    - draining の後に owner の回収が hard を過ぎても、`hardAt` を照合しない
    - `fullSendCompletedAt` を `sendEncrypted` で記録しない（暗号化 profile で F6 の修正が効かない。裏取り済み）
    - soft と hard の間に final を受けたときは full-send の時刻を見ず terminal にするので、soft の callback と final の到着順で結果が変わる
    - P2: 残高の snapshot を hook の外で毎回取る・full-send の時刻を cleanup 以外でも取る（hot path の lock と時計の読み。裏取り済み）
  - テストの観点（P2 が 3 件）: positive snapshot の試験は旧条件へ戻しても通る（競合の順序を固定していない）、Tree 台帳の回収の試験は別 Tree の誤回収を検出しない、
    lifecycle の回収の試験は `facadeParents` などの件数を数えていない
  - 壊せなかった: fast path の隔離後の予約、token の refund の二重と漏れ、final 後の nil の identity を timeout と誤読する経路
  - barrier・台帳の観点（リセット後に再実行。P1 が 2 件、P2 が 2 件）:
    - 親の close の barrier が body の lease を待つが、子の Tree の隔離と credit 待ちの取消は barrier の後の `performClose` にあるので、grant が来なければ期限まで循環待ちする
    - sender が列から取り出した転送の request を隔離で拒否する経路は、refund の後に record の回収も receipt の完了もしないので、Tree の close が soft の期限まで待つ
    - P2: final を受けた時点で wire の receipt を完了するので、credit の grant の精算より前に TREE_DISCONNECT が出うる
    - P2: acquire の後に親を登録し直すと、祖先ごとの件数が食い違う（production での到達性は未確認）
- 2 周目の指摘の修正（worktree の c374f62、codex luna-max。12 件すべて再現した。テストの 3 件は production の不具合ではなくテストの素通り）:
  - cleanup の期限の判定を `SMBCleanupDeadlines.disposition` の 1 関数に寄せ、soft の callback・final の受理・send owner の回収のどの順で届いても、
    固定の softAt / hardAt と同じ規則で比べるようにした（1 周目の修正で 3 経路に分かれて食い違ったため）
  - full-send の時刻は平文・暗号化の両経路で共通に記録し、cleanup の request に限る。公開の親 close は lease を待つ前に子の Tree の隔離を準備する。
    隔離で拒否した転送の request は refund の後に receipt を完了する。wire の receipt は credit の grant の精算まで保持する。facade の親の付け替えで件数を移す
  - 変異: 12 件それぞれに修正を戻す変異を当てて red（codex が実行）
  - 検証（自分で実行）: macOS 823 件・Linux 830 件 green、strict lint 0、期限の 3 テストを 20 回連続 green
  - codex が開発の途中で起こした xctest が 1 つ、T4 のテストの待ちで止まったまま孤児で残っていた。最終の版の 20 回の繰り返しでは止まらなかったので、途中の版の残骸と判断した（stack は採ってから止めた）
- 3 周目の敵対レビュー（c374f62 に対して 3 観点）:
  - 期限の判定は収束した。`disposition` を 192 組（event 4 種 × full-send 3 区分 × final 4 区分 × owner 回収 4 区分）で列挙して、§9・§10 に反する組を見つけられなかった。
    同じ request に event が複数届いたときの二重の caller 再開・二重の hard timer・台帳の二重遷移も見つからなかった
  - wire の receipt の完了の判定で再び破られた（2 周目に続いて 2 回目）:
    - P1: final の受理で record が先に回収され、`markOperationBarrierComplete` の guard が `nil == 0` で失敗し、receipt が terminal まで残る（2 観点が独立に指摘）
    - P2: grant の精算だけで receipt を外し、send owner が未回収のまま Tree の後始末が進む
    - P2: 親の付け替えの後に旧親の waiter を起こさない
  - テストの素通り: ack が先・owner の回収が後の順序が無い、拒否した request の record の回収を見ていない、`disposition` の `== softAt` の境界、
    付け替えの旧祖先の減算、子の期限の callback の完了を待たない（P2 が 4 件、snapshot の source の検査の範囲が P3）
  - 次: receipt の完了の判定が 3 か所（final・ack・refund）に分かれて続けて食い違ったので、条件を継ぎ足さず、「wire の仕事が全部済んだか」を判定する 1 関数に寄せ、
    record の回収より前に評価する形にする（codex luna-max に指示、実行中）
- 3 周目の指摘の修正（worktree の 100cde8）: receipt の完了の判定を `completeOperationBarrierIfWireWorkIsComplete` の 1 関数に寄せた。record を回収する前に評価し、
  record が無いことを「済んだ」と推測しない。final の受理・send owner の回収・grant の ack・refund・precommit の拒否・catch・cleanup の期限・terminal の join から呼ぶ。
  親の付け替えの後に旧親の waiter を起こす。テストの素通り 6 件を直した（`disposition` の D−1ns / D / D+1ns の表のテストを含む）
  - 変異: 各指摘の修正を戻す変異で red（codex）。receipt の評価を reap の後へ移す変異は、動作のテストでは緑のままで、source の形の検査が red にする
  - 検証（自分で実行）: macOS 829 件・Linux 836 件 green、strict lint 0、race 系の 2 suite を 10 回連続 green
- 4 周目の敵対レビュー（100cde8 に対して 2 観点: receipt の取りこぼしと早すぎる完了 / テストの素通り。期限の判定は 3 周目で収束したので外した）:
  - 判定の関数そのものの早すぎる完了・取りこぼしは見つからなかった（record を更新する全箇所を照合した表つき）
  - P1: Tree の隔離の refund が suspend している間に request の catch が走ると、未精算の credit のまま record を消し、後の refund の側が判定できず receipt が残る
    （cleanup の soft の退役の経路にも同型）。record を消す箇所が 7 か所に散っていて、catch の 1 か所は判定の関数を呼んだ後、判定が「まだ」と返しても消していた
  - P2: catch の経路の判定の呼び出しを消してもテストが通る。P3: snapshot の件数の検査が表記の揺れを数えない
  - 次: 「record を消す前に receipt を判定する」が 3・4 周目と別々の箇所で破られたので、record の回収も 1 関数に寄せ、
    それ以外の removeValue を source の形の検査で禁じる（codex luna-max、実行中）
- 4 周目の指摘の修正（worktree の d3822e7）: active record の回収を `reclaimActivePostAuthRequestRecordIfEligible` の 1 関数に寄せ、直接 removeValue していた 6 か所を置き換えた。
  catch は credit の refund が終わるまで record を残す（`creditRefundPending`）。record の削除と snapshot の参照は source の形の検査で固定した
  - 検証（自分で実行）: macOS 832 件を 5 回連続 green（各 10 分の上限つき。hang なし）、Linux 839 件 green、strict lint 0
  - codex の作業の途中で、最終の版より前の binary の xctest が既存のテスト（`testEarlyFinalThenCancellation...`）で止まったまま孤児で残っていた（2 回目）。
    stack は async の待ちしか映らず原因は読めなかった。最終の版の 5 回の全件の実行では止まらなかった
- 5 周目の敵対レビュー（d3822e7 に対して 2 観点）:
  - production は収束した。request の終わり方ごと（成功・エラーの final、cancel、credit 待ちの拒否、Tree の隔離、cleanup の soft / hard、terminal、
    READ / WRITE・compound・暗号化・STATUS_PENDING の後の final）に record の最後の状態と最後の回収の遷移を表にして、残る record・呼ばれない回収・
    `creditRefundPending` の下ろし忘れを反証できなかった
  - テストの穴（P2 が 2 件）: `creditRefundPending` を立てる行を消しても落ちない（accept 前の grant を soft で取り消す順序が無い）、
    Tree に拒否された request の record が残っても落ちない（session の close の removeAll が隠す）→ テストだけを足す（codex、実行中）
  - 記録のみ（P3 が 2 件、直さない）: source の形の検査は、別名の変数を通した `balanceSnapshot` の参照と、呼ばれないクロージャの中の receipt の判定を見分けない。
    この検査が止めるのは書き戻しの退行で、意図的な迂回は対象にしない（振る舞いは実行型のテストが別に押さえる）
  - 周回の打ち切り: 5 周目の修正はテストの追加だけで、判定のロジックを新設せず、各テストは変異で直接確かめるので、
    規定の例外として周回をここで打ち切る
- 5 周目のテストの穴の修正: Tree に拒否された request の record が session の close の前に 0 件になる assert、accept 前の grant を soft で取り消して
  refund が終わるまで record を残すテスト（決定的に止めるため testing hook を 1 つ足した。codex は未設定でも claim と accept の間に suspension を作る
  呼び方をしていたので、既存の hook と同じ optional chaining に直した）。`creditRefundPending` を立てる行を消す変異で red（`mutate-verify` で自分で確認）
- **master へ（29359db、1 マイルストーン = 1 commit に squash）**。macOS 833 件（3 回連続）/ Linux 840 件 green、strict lint 0、smoke 3 profile
  - CI: Test・E2E は success。Performance（run 38165701238、前回の成功した master との 20 組）: read throughput −6.1%・user CPU +7.7%、
    write −2.4%・user CPU +2.1%。すべて gate の内側（PASS）
  - issue 069 の完了条件のテストを続けて足した（fef6c44。Tree の後始末が soft を過ぎて drain している間も別の Tree の操作が成功する）
  - fef6c44 の CI の Test で 2 本が落ちた（どちらもテストの待ち方。29359db の CI と手元の繰り返しでは通っていた）→ c03014c で直した:
    - `testTreeQuarantineCatchKeepsRecordUntilCreditRefundAcknowledgement`（macOS）: credit の actor の hook で suspend すれば Tree の隔離の refund が止まる、
      という前提が actor の再入で崩れ、refund が catch より先に済む順序で record が先に回収された。refund の直前の hook と catch の両方の合図を待つ形にした。
      修正前は手元の連続実行の 9 回目に CI と同じ形で落ちた
    - `testGracefulDisconnectKeepsTheReaderUntilLogoffResponse`（Linux。issue 010 M3 の既存のテスト）: 待つ合図（frame の記録）と assert する事象（reader の起動）の
      すき間。手元では再現しなかった。送信の完了を待ってから assert する（retro 110 の 5 と同じ形）
- 2026-10-12: Commit 4 の後に CI の Cancel の stress（`KeepAlive|Cancel` を 20 回）で `testCallerCancellationDrainsCommittedWritesWithoutNewCommitOrCancel` が 1 回落ちた
  （過去 25 回の失敗した run では初めて。手元の 40 回では再現せず）。原因はテスト側: WRITE を待つ helper が「要求が無い」を確かめてから signal の件数を読み、
  その間の signal を取りこぼしていた。cancel の後の待ちも、Commit 4 から CLOSE の後始末の timer が同じ sleeper を使うので drain の timer と区別できなかった。
  commit `test(write): CI の cancel の stress で 1 回落ちた WRITE の cancel のテストの待ち方を直す`（CI は Test・E2E・Performance が success）
- Commit 5（READ / WRITE の ticket と delivery の統合）がこの上に積む次の段。**着手前に要否と範囲を洗い直す**: 承認済み設計（2026-10-04）の後に、
  READ / WRITE の pipelining が issue 102 の #14〜#16（2026-10-07〜09、`done/102` の「進捗チェックポイント」節）で別に入った。
  §8 の Commit 5 の受け入れ条件のうち、どれが既に満たされ、どれが残る（delivery terminal・lease receipt・共通の commit core への載せ替え）かを、今のコードと突き合わせてから設計する
- Commit 5 の洗い直し（2026-10-12、codex sol-high の read-only 2 本: 受け入れ条件 / red mutation。master bc401ac）:
  - 既に満たす / 不要: READ / WRITE の pipelining と、共通の sender・MID の採番（認証後の `nextMessageId` は placeholder で、実の採番は sender の `commitNextMessageId`）。
    20 組の Performance gate は issue 102 の M2 / M4 と Commit 3 で通っている（Commit 5 の変更には改めて要る）。転送の cancel で CANCEL を送らないのは issue 102 の設計で決めた変更で、未実装ではない。
    独立した byte の枠の管理は issue 102 で採らないと決めた（最大 4 slot × 1 MiB の slot をそのまま使う）
  - 一部 / 満たさない:
    - 未送信の ticket の退役が receipt を持たない: `retireStoppedTransferRequestBeforeCommit` は slot を空けて通知してから、別の関数で refund を待つので、
      epoch の切り替え（`beginNextEpoch` は wire の drain と全 slot の空きだけを見る）が refund の完了を待たない窓がある（静的に確認。実行での再現はまだ）
    - stop は queue から直接除かず、sender が取り出すまで待つ
    - File の拒否は Tree と違い局所退役にならず、sender の precommit の catch から session の terminal へ進む（`terminateTransferAdmissionFailure`）
    - record の回収が delivery より先に起きうる: `reclaimActivePostAuthRequestRecordIfEligible` は delivery と slot の解放を見ない（§2.2・§9.16 と食い違う）。
      既存のテスト `testSuspendedAsyncReadCallbackDoesNotHoldSessionOrTerminalWireLease` は「terminal の join の後、callback 中でも active record = 0、delivery lease = 1」を明示的に求めている
  - 欠けているテスト: delivery と slot の解放を待たずに epoch を進める変異を落とす負例、READ / WRITE / 通常の request が混ざったときの MID の列、
    正常終了の後に session を開いたまま record・transfer の状態が 0 に戻ること（今は terminal の removeAll が隠す）、refund を止めたまま epoch を進めない順序
  - 設計の判断が残る: canonical な record を delivery の終わりまで保持するか（§2.2 どおり。既存のテストを変える）、wire の record と transfer の ticket の所有者を分けるか
  - 次: codex-drive の設計（D1〜D3）→ ユーザーの承認 → 実装
- Commit 5 の設計 D1（2026-10-12、sol-high の独立 4 案）: 4 案とも同じ結論に収束した。
  - Q1: canonical な record を delivery の終わりまで保持する（§2.2 どおり）。既存の 2 本のテスト（READ の suspended callback / WRITE の suspended supplier）の
    「terminal の後 active record = 0」を「wire の owner・pending・barrier = 0、callback / supplier の所有の record だけ残る、返却後に全部 0」に変える。wire の barrier と transport の join は callback を待たない
  - Q2: receipt の正本は record。window は epoch ごとの未決着の owner 数を持つ。未送信の slot は refund などが決着するまで空けない
  - Q3: File / Tree の拒否を型付きの admission refusal にし、同じ局所退役を通す（`SMBCodecError` を一律に局所扱いしない）
  - Q4: p4 の 4 段（所有期間 → 未送信の退役と epoch → 局所 scope → 統合検証。receipt と epoch の接続は同じ milestone）を土台にする
- D1.5（p3 と p4 へのクロス批評、sol-high 2 本）: 両方が同じ穴を挙げた。
  - P1: terminal の後始末（今は最後の removeAll が、send が `.committed` で owner が残る record を隠している。回収の条件を増やすなら、join で何を何に固定するかの表が要る）
  - P1: sender が取り出して precommit で止まっている item の packet の所有が receipt の条件に無い
  - P1 / P2: ticket を作らず終わる準備（EOF・charge 0・retry・supplier の失敗）の終端が未定義。chunk の caller と転送の caller を分けないと待ちが循環する
  - P2: 古い ack と再利用された slot、既存の receipt（lock 付き）との整合と shell の寿命、charge 0 の終了で lock / Task を使わないこと（R7）、
    冗長な guard で変異が隠れること、M1 で既存の Tree の経路を新しい入口に通すこと
  - D2（統合と詳細化）でこの 8 点に答えさせた
- D2（2026-10-12、luna-max。設計書は本体の checkout の `tmp/c5/d2/design.md`。ignore されていて手元にしか無いので、要点をここに残す）:
  - G1: terminal で removeAll に頼らず、join を根拠に send / wire / credit / timer を固定する表で終端化し、外部 owner（callback / supplier / decode）を持つ転送の record だけ残す。通常の request にも同じ表を当てる
  - G2: sender が取り出した item は、選択済みの owner として receipt の条件に入れる（packet を手放して返却の ack を出すまで閉じない）
  - G3: chunk の record の caller と転送の caller を分け、ticket を作らない終端（EOF・charge 0・retry・supplier の失敗）は内部の `noWireWork` で同期に閉じる（receipt・lock・Task を作らない）
  - G4: event の有効性（record と effect）と slot を変える資格（slot の binding の完全一致）を分ける。G5: 既存の SMBRetirementReceipt を使い、handle が receipt を保持し、session に履歴を残さない
  - G6: 外部の joiner がある退役にだけ、需要駆動の pump を 1 つ使う。G7: 変異ごとに、残る guard と独立した fixture を表にした。G8: M1 から既存の Tree の経路を新しい遷移の入口に通す
- D3（sol-high、敵対 / 整合の 2 本）: P1 が 2 件（外部 owner の無い転送の終端の行が G1 に無い、short READ の後に readiness の判定を破棄の前に置くと永久に待つ）、
  P2 が 6 件（pump が await 中に足された work を拾わない、M1 と M2 の中間状態で refund の前の rebase の窓が残る、最後の ack で waiter を起こす規則が無い、
  変異の表が epochReady の定義と合わない、chunk ごとに UUID を作る記述（既存の requestSequence と食い違う）、M1 の receipt の oracle が M2 に依存）、P3 が 1 件（allocation は artifact で測れない）。
  FileId の再利用の前提は、cleanup 台帳ではなく「CLOSE の前に転送を await する規則」が支えている（READ の公開経路で確認。全 File 操作は未確認）
  - 全部を設計の改訂（D2 v2）で直した。主な変更: G1 に転送の終端表（外部 owner の無い配送待ちは discarded・未送信は notApplicable）、転送の完了処理を「破棄・終端・slot の解放」→「readiness の判定」の順に分ける、
    pump の終了と再起動を非 suspension 区間で確定、**M1 と M2 を 1 つの有効化単位にする**（M1 だけだと owner の数が epoch を guard しない）、最後の ack で owner 数が 0 になったら同じ transaction で waiter を起こす、
    preparation key は既存の SMBRequestIdentity（requestSequence）、allocation は artifact で未計測と明記
- D3 の 2 周目（改訂した部分への敵対 1 本）: P1 なし。P2 が 2 件:
  - 境界外の committed B の破棄の資格を grant ack に依存させると、ack の後も slot が occupied のまま owner 数が 0 にならず循環する → 破棄は ack に依存させず、record だけを ack まで残す（設計に反映した）
  - FileId の前提: watch の cancel の経路では、caller だけ先に返って CHANGE_NOTIFY の wire の owner が残ったまま `bestEffortClose` が CLOSE を送る。「CLOSE の前に利用の完了を await」は caller の完了でしか成り立たない → **ユーザー決定: M3 で直す**（cancel / timeout の catch から CLOSE の前に、その request の wire の barrier を固定期限の中で待つ。File incarnation は足さない）
- **ユーザーが設計を承認した（2026-10-12）**。実装の順: M1+M2（1 つの有効化単位）→ M3（局所 scope と watch の cancel → CLOSE の待ち）→ M4（統合検証と性能 gate）
- M1+M2 の実装（2026-10-12〜13、codex luna-max。worktree の cd52b72、未 push）:
  - 所有の変更を `transitionTransferRequest` に集め、preparation の開始で request key・handle・canonical な record を登録。terminal の join は設計の表で終端化し、外部 owner の残る record だけ保持して返却の後に回収。
    no-ticket の終端は同期に閉じる。Tree の refusal は共通の遷移を呼ぶ adapter。未送信の退役の receipt を共通化し、slot は refund の ack まで `retiringUnsent`。epoch の readiness は 3 条件
  - 設計で未指定だった判断: refund の effect の pump の worker を 2 に固定（A の refund の ack の待ちで B を塞がないため）→ 敵対レビューで見る
  - 変異 21 本（G7 の M1・M2 の分）がすべて red（codex）。検証（自分で実行）: macOS 851 件 × 2 / Linux 858 件 green、cancel の stress 10 回 green、strict lint 0、smoke 3 profile
  - macOS の全件の所要が 11 秒 → 23〜31 秒に見えたが、マシンの負荷（load average 9 前後）だった。master と交互に 3 回ずつ回した pipeline のテスト（52 / 54 件）は 5.6〜6.0 秒 / 5.8〜6.1 秒で差は無い
- M1+M2 の敵対レビュー 1 周目（2026-10-13、sol-high 3 観点 + merger。8 件 → 5 件）:
  - D1（P1、2 観点が独立に指摘。main agent が裏取り）: terminal の join（terminalSendOwnersJoined）の前に callback / decode が返ると、`releaseTerminalOwnedSlot` が false を返し、
    `finishDelivery` も false で戻って返却の event が失われる。driver は再送しないので、slot / record が残り epoch も転送も終わらない
  - D2（P2、3 観点）: refund の effect の pump の worker を 2 に固定したため、A と B の refund の await の間に C が dispatch されない（設計 G6 の「ack 待ちで別の effect を塞がない」に反する）
  - D3〜D5（P2、テストと検査）: 旧い ack のテストが production の ack の経路を通らない、既存 2 本が設計 §5 の 3 段を全部見ていない、所有の書き込みの source 検査の正規表現が optional chaining を拾わない
  - 5 件すべてを直した（worktree の b524e31。D1: join の前の返却も遷移で記録し slot は join で解放、D2: 退役のときだけ effect ごとに Task）。
    検証（自分で実行）: macOS 853 件 × 2 / Linux 860 件 green、変更したテストを 20 回連続 green、cancel の stress 10 回 green、strict lint 0、smoke 3 profile
  - 2 周目の起動は codex の weekly 枠の上限で一度落ちた（2026-10-13 未明。ユーザーが枠を戻して再開）
- M1+M2 の敵対レビュー 2 周目（2026-10-13、sol-high 2 観点）: D1・D2 の修正そのものは壊せなかった。P2 が 4 件・P3 が 2 件:
  - D2 の修正が ticket 化の前の preparation の refund（Tree の隔離）に届いていない（逐次の await のまま）
  - 退役の effect ごとの独立した Task で、大量の退役で Task が一度に 4N 本できる → main agent の判断: 退役は hot path ではないので Task は許容するが、pump の Task を 1 つにしてその中の task group の子で回す（固定の worker 数には戻さない）
  - テスト: pump のテストの待ちに上限が無く退行で hang する、D1 の decode の返却の経路のテストが無い、source 検査が `!.` を素通りする、READ の回収の assert が operation の完了より先に走りうる
  - 6 件を直した（worktree の 393c78b。pump は session ごとに coordinator の Task 1 つ + structured な task group の子。preparation の refund も共通の effect の work）。
    検証（自分で実行）: macOS 857 件 × 2 / Linux 864 件 green、変更したテストを 20 回連続 green、cancel の stress 10 回 green、strict lint 0、smoke 3 profile
- M1+M2 の敵対レビュー 3 周目（2026-10-13、sol-high 2 観点。所有と並行の観点は一度「model is at capacity」で落ちて起動し直した）:
  - 所有と並行: production で壊せる経路を見つけられなかった（coordinator の二重起動・起床漏れ・終了と登録の競合、terminal の中の追加 work、grant の accept と取消の競合、ack の二重・漏れ）。**production は収束**
  - テスト: P2 が 3 件（preparation の credit の返却を省いても通る、source 検査が `Task.detached` を数えない、preparation の fixture が coordinator の join の失敗を `try?` で握り潰す）
  - 周回の打ち切り: 直すのはテストと source 検査だけで判定のロジックを新設せず、各テストは変異で直接確かめるので、規定の例外としてこの修正で周回を打ち切った（b5f58fe）
  - 実装中に 1 回だけ、全 suite が既存の `testCloseFromReconnectOverflowCallbackStopsBeforeNextWatchIteration` で 90 秒以上止まった。単体 50 回（M1+M2 / master とも）・全 suite 5 回では再現せず。未確認のリスクとして CI の hang の watchdog で観測する
- **master へ（988bcba、1 commit に squash）→ x86 の性能 gate を超えたので revert した（e8e248c、ユーザーの判断。Commit 3 と同じ扱い）**:
  - 988bcba の CI: Test・E2E は success。Performance は Release のテストのビルドで落ちた（`testWriteDrainDeadlineJoinsWireOwnersWhileAsyncSupplierIsSuspended` が #if DEBUG の中にだけある API を guard 無しで呼んだ）→ cd6355c で関数ごと #if DEBUG に入れた。
    手元の検証（main agent も codex も）に Release のテストのビルド（`swift build -c release --build-tests -Xswiftc -enable-testing`）が入っていなかったのが漏れの原因（M3 以降の指示に足した）
  - cd6355c の CI: Performance（run 38363228813、20 組、直前の成功した master と比較）で read_stream が gate を超えた: throughput −19.3%（−15%）、user CPU +29.2%（+25%）。
    write_stream は throughput −9.0%・user CPU +11.2%（内側）。RSS・system CPU は雑音の範囲。macos-tsan で `testLateReadGrantAcknowledgementUsesCanonicalOwnerAfterSlotReuse` が 1 回落ちた（phase の待ちのずれの疑い）
  - 次: worktree で、手元の arm64 container で master と交互に計測して再現 → 主要な指標（user CPU）の増加を chunk ごとの処理の内訳（callgrind 等）で説明 → 直す → 再計測 → 入れ直す（codex、実行中）
- **性能の調査（2026-10-14、codex。worktree `swift-smbee-wt-c5m12-20261012-204015-38570` の a89bc8a、未 push）**:
  - 再現: arm64 の Linux container で master と 5 組交互、read throughput −16.5% / user CPU +26.1%。handle → record の weak 参照で hash lookup を避ける案は効かず戻した
  - Callgrind（1 run・1 iteration の synthetic read。XCTest の fixture と 1 MiB の warm-up を含む）: 候補は master 比 +6.88% Ir。上位は `transitionTransferRequest`（+622k）、enum tag の操作（+474k）、`swift_beginAccess`（+495k）、`swift_retain` / `release`（+446k / +411k）。
    送信・応答・decode・delivery のたびに単一の遷移関数を通り、そのたびに exclusivity check・retain/release・enum の payload の処理が走る
  - 直したこと（a89bc8a）: ticket が request key を handle から読む（2 重に持たない）、`SMBRequestIdentity` の hash を requestSequence だけにする（等価比較は 3 つ組のまま）、owner を class にして遷移ごとの値コピーと書き戻しをやめる。
    reclaim の条件・receipt・epoch の owner 数・単一の遷移関数は変えていない。main agent が差分を読み、owner を控えてから使う箇所（`treeRefusalPreparation` 等）で class 化が結果を変えないこと、ticket の等価比較が key ベースのままであることを確かめた
  - 計測（arm64 container、5 組）: read throughput −11.45%（95% CI −12.11〜−10.92%）、user CPU +12.89%（+10.33〜+15.37%）。write は −1.91% / +4.55%。目安の ±10% には届いていない
  - 効かずに戻した案: ticket の hash を MessageId だけにする、read の経路で write の map の lookup を省く
  - 検証: macOS の unit 859 件・失敗 0、strict lint 違反 0、Release のテストのビルド成功（main agent が実行）。Linux arm64 の unit と Release のビルドは codex の報告のみ（main agent は未実行）。TSan のテストは B の slot が fullySent かつ sendOwnerFinished になるまで待つ形に直し、20 回連続で通過（codex の報告）
  - **x86 の gate は未実測**。前回は arm64 の −16.5% / +26.1% が CI の x86 で −19.3% / +29.2% になった。同じ比率なら今回は x86 で約 −13.5% / +14.5% の見積もり（gate は −15% / +25%）。throughput の余裕が小さい
  - **x86 の実測（2026-10-14）**: 一時 branch `tmp/issue106-c5-perf-candidate` に a89bc8a を push し、Performance を手動起動（run 38470270865、reference_sha=304f77f、20 組）。
    gate は PASS だが余裕が無い: read throughput −14.7%（paired −14.43%、95% CI −15.08〜−13.72%）、user CPU +22.7%（+22.09%、+20.66〜+23.49%）。write は −5.4% / +6.8%。
    artifact を落として `bin/ci/compare-resource-performance --fail-on-regression` を手元で当て、同じ判定を再現した（`verify-agent-performance` は push の run しか見ないので使えない）。
    arm64 の −11.5% / +12.9% は x86 では縮まなかった（前回の比率から見積もった −13.5% より悪い）。smoke（3 プロファイル）と Linux（unit 866 件・失敗 0、Release のテストのビルド）は通過
  - 判断（ユーザー、2026-10-14）: このまま入れず、slot table まで詰めて x86 で余裕を作ってから入れる
  - **slot table を試して効かなかった（2026-10-14、codex。戻した）**: session 内の generation 付き slot table を作り、handle から slot を引いて generation・identity・owner handle を照合して record に届く形にした
    （古い handle が同じ slot の新しい record に届かないテストを足し、generation の照合を外す変異で red を確認）。
    - Callgrind: slot ありは identity の map だけの版より約 79k Ir 少ないだけで、master 比 +6.61M Ir（+7.30%）。事前の見積もり（0.3〜0.8M Ir 減）を大きく下回った。
      上位は `transitionTransferRequest`（+632k）、`swift_beginAccess`（+577k）、`swift_retain`（+544k）、enum tag の store（+471k）、`swift_release`（+469k）、`AccessSet.insert`（+429k）。**hash lookup は主因ではなかった**
    - arm64 の 5 組: read −13.0%（95% CI −13.11〜−12.91%）、user CPU +17.2%（+14.81〜+19.52%）。a89bc8a（−11.5% / +12.9%）より悪い
    - owner を struct に戻す案は class より約 474k Ir 悪かった
    - 判断: 効かなかった変更は戻す原則に従い、worktree を a89bc8a に戻した
  - 分かったこと: 退行の本体は lookup ではなく、chunk ごとの各遷移（送信・応答・decode・delivery）が canonical な record を通るたびに走る exclusivity check・ARC・enum の payload の処理。
    遷移の回数か、1 回の遷移の重さを減らす形にしないと縮まない
  - **正常系の遷移を 1 回にまとめる（2026-10-14、codex。ユーザーが選んだ方針。worktree に未コミットで残し、差分を tmp/c5/impl/coalesce-attempt.patch に控えた）**:
    - 正常な READ の 1 chunk の遷移を 16 → 12 回にした。まとめたのは 4 組（`admitReadTransferRequest` の beginPreparing＋reservationPending と reservationSettled＋commit、
      `runSenderLoop` の selectedPrecommit＋wireCommitted、`stepReadTransfer` の finishDecode＋beginDelivery）。suspension を挟む境界はまとめていない
    - Callgrind: master 90.66M Ir → 候補 96.29M Ir（+6.21%）。**a89bc8a（96.81M）からの減りは約 0.5M Ir だけで、退行の約 1 割**。retain/release・beginAccess・AccessSet.insert は減ったが、enum の tag の store はほぼ減らない
    - arm64 の 5 組は計測が成り立たなかった（同じ計測の中で master の read が 626〜2357 MiB/s と揺れた。マシンが混んでいた）。効果は主張できない
    - テスト: slot の再利用のテストに finishDecode と delivery の開始の順序の assert を足し、`deliveryOwned = true` を落とす変異で red を確認。macOS unit 859 件・Linux unit 866 件・strict lint・Release のテストのビルドは通過（codex の報告。main agent は未実行）
  - 見通し（main agent の見積もり）: まとめで消せるのは退行の 1 割程度で、x86 で −10% 以内に縮む見込みは低い。残りは遷移ごとの enum の payload・exclusivity・ARC で、単一の遷移関数と canonical な record を保つ限り大きくは減らない
  - **x86 をサポート対象外にした（2026-10-14、ユーザー判断。issue 112）**。CI の Linux の job は arm64（ubuntu-24.04-arm）で回す
  - **arm64 の CI の gate（2026-10-14）**: 候補（a89bc8a と同じコードを 6af8706 の上に載せ直した 6cdcf20）を branch で手動起動（run 38553263839、20 組、cpu_model は両側とも arm64 implementer 0x41 part 0xd49）。
    gate は PASS: read throughput −10.7%（paired −11.18%、95% CI −12.21〜−9.90%）、user CPU +15.5%（+15.79%、+14.00〜+17.44%）。write は −6.2% / +9.8%。
    上限（−15% / +25%）まで throughput で約 3.8 ポイント、user CPU で約 9 ポイントの余裕。artifact を落として `compare-resource-performance --fail-on-regression` で同じ判定を再現した
- **master へ入れ直した（2026-10-14、ユーザー判断）**: commit `feat(session): issue 106 Commit 5 の M1+M2 — 転送の chunk の所有期間と未送信の退役の receipt を canonical な record に統合する`（2d3923c、1 commit に squash）。
  - 性能（2d3923c の push の Performance、arm64、20 組、reference は c938d1a）: read throughput −8.5%（95% CI −9.61〜−7.34%）、user CPU +12.0%（+9.57〜+13.06%）、write −3.4% / +4.3%。gate PASS
  - 2d3923c の CI で macos-tsan の `testStoppedReadRetiresQueuedUnsentRequestsBeforeMIDCommit` が落ちた（4 vs 1）。退役した record の回収は refund の子 task の後なのに、queue が空になった時点で数えていた。
    commit `test(read): issue 106 — 送らずに退役させた READ の record が refund の後に回収されるのを待ってから数える`（b1ce109）で直した
  - b1ce109 の CI: code-coverage の 1 本と network 性能テストの crash（issue 113）が単発で落ち、回し直しで両方通った。`verify-agent-push` rc=0
  - 採らなかったもの: slot table（効かず）と正常系の遷移のまとめ（Callgrind で約 0.5% 減のみ）。後者の差分は tmp/c5/impl/coalesce-attempt.patch に控えたが、一時領域なので消えうる
  - **Commit 5 の残り: M3（型付きの拒否、watch の cancel → CLOSE の待ち）と M4**
- **M3 の進捗（2026-10-15、codex-drive。worktree `swift-smbee-wt-c5m3-20261014-230108-11038` の 15ad018、WIP・未 push）**:
  - codex（luna-max）が実装の途中で 5h 枠を使い切って止まり（weekly も 100%）、続きを Claude のサブエージェントが引き継いだ（ユーザー指示）
  - 型付きの admission refusal: `SMBTransferAdmissionRefusal`（scope・operation・caller error）。File は `SMBFileIdLedgerKey`、Tree は `SMBTreeIdentity` で照合し、CLOSE intent と final の admission guard の両方から同じ遷移を通る。File の refusal は session を terminal にしない
  - **ユーザー判断（2026-10-15）**: 「cancel / timeout の後、wire が決着してから CLOSE する」を watch だけでなく、FileId を使うすべての通常の要求（stat / list / rename / ACL / copy など）に広げた（`awaitAbandonedFileIdUseOwners`）。
    これらの cancel は wire が決着するまで（最長で既存の drain の期限まで）戻らない。待ちは record の回収で起こされ、回収の関数を通らない record の消去は無い（1 か所だけ）。
    新しい失敗の形: record が回収されずに残ると、これまでは漏れるだけだったのが、cancel した呼び出し元が戻らなくなる
  - codex が入れた「すべての CLOSE が同じ FileId の利用の終わりを期限なしで待つ」機構は設計から外れていた（期限なし・callback の owner まで待つ・chunk ごとの経路に処理を足す）ので撤去した
  - fake の `respondToCreate` が毎回同じ FileId を返していたのを、CREATE の MessageId から一意に作る形に直した（同時に開いている handle が同じ FileId を持つことは実サーバでは起きない）。
    同じ FileId のせいで `testAsyncSupplierReentersSessionAndOversizedChunkSplitsUntilEOF` が落ちていた。原因の推定（stat の CLOSE intent が upload の準備中の record を拒む）は観測していない
  - 検証（サブエージェントの報告。main agent は macOS の unit 873 件・失敗 0 を再現）: Linux arm64 の unit 880 件・失敗 0、Release のテストのビルド（macOS / Linux）、strict lint・lint-analyze 違反 0、E2E（SMB 3.0.2）、変異 M1〜M7 がすべて red、新しいテスト 13 本を 20 回連続 green
  - **レビュー 1 周目（2026-10-15、Claude のサブエージェント 3 本・read-only、15ad018 が対象）の台帳**:
    | # | 観点 | 指摘 | 判定 |
    |---|---|---|---|
    | A | 素通り | 通常の経路（`signedWireTransaction`）の cancel の待ちにテストが無い | **確認済み**: 待ちの 1 行を消す変異で 873 件が緑（mutate-verify rc=6）。テストを足す |
    | B | 壊す | `cleanup_ledger_limit` の 3 か所は同期の `closeTransport` で終端し join を起こさない → record が回収されず、cancel 後に待つ caller が戻らない（以前は漏れるだけ）。operation barrier と `discardedOnTerminal` の組も同じ根 | 未再現。3 か所が同期の `closeTransport` を呼ぶことは確認。再現テストを先に書く |
    | C | 発見型 P2 | CLOSE が commit 前に放棄されても、通常の要求に付けた `admissionRefusal` が残り、後の cancel を codec error にすり替えて待ちを外す | 未再現。再現テストを先に書く |
    | D | 発見型 P3 | CLOSE の admission に suspension 点が増え、generation を確かめずに `registerPendingResponse` へ進みうる | 実害未確認 |
    | E | 発見型 P3 | 通常の CLOSE ごとに record を全件走査 | 性能。判断して記録 |
    | F | 素通り | timeout のテストは待ちの有無を区別しない / `reclaimWaiters == 0` の assert は空振り / M7 は既存の終端化を見ているだけ / source-shape は M5 の箇所を見ていない | 対応する |
    | G | 素通り | fake の FileId を一意にした件の原因の推定は未観測。同じ FileId の使い回しの場面のカバレッジが減った | 観測して確かめる |
    壊せなかった攻め口: reclaim 以外で record が消える経路（1 か所だけ）、待ち始める前の回収、reconnect / close の join、自分の CLOSE との deadlock、queue の中の cancel、refund の二重化、committed ticket の退役、descriptor と refusal の混同、hot path への追加
- **M3 を master へ入れた（2026-10-15）**: commit `feat(session): issue 106 Commit 5 の M3 — 型付きの admission refusal と、FileId を使う要求の cancel / timeout の後に CLOSE を wire の決着まで待たせる`（736f9ea）。
  - レビュー 1 周目の対応: A（通常の経路の待ちにテスト）・B（`closeTransport` を同期の終端と terminal join の予約に分け、どの経路で終端しても join に届く。再現テストで hang を確認してから直した）・
    C（放棄された intent の refusal で commit 後の error をすり替えない。再現してから直した）・D（到達しない：CLOSE は認証後は必ず placeholder の経路を通る）・E（直さない理由をコードに記載）・F・G（旧 fake で原因の推定を観測して確認）
  - レビュー 2 周目（敵対 2 本）: 製品のコードを壊す経路は組めなかった。テストの穴（待ちを record の回収より早く起こす退行・呼び出し元を join なしの終端に差し替える退行・C の前提）を埋め、
    join の予約を 1 か所に寄せた。修正はテストと挙動を変えない整理だけで、それぞれ変異で確認したので 3 周目は回していない
  - 検証: macOS unit 878 件・Linux arm64 unit 885 件（失敗 0）、strict lint、Release のテストのビルド、smoke 3 プロファイル。main agent が A・B・R1 の変異を当て直して red を確認
  - CI（736f9ea / 6f3308c、`verify-agent-push` rc=0）: arm64 の性能 gate PASS。M3 の上乗せは read −3.9% / user CPU +4.3%、write −0.4% / +0.8%
- **M4 を master へ入れた（2026-10-16、codex-drive）**: commit `test(session): issue 106 Commit 5 の M4 — mixed MID、競合、正常時の回収の統合テスト`（1731eef）と
  `test(session): issue 106 M4 — 使われなくなったテスト用の helper（SMBM4OwnershipRecorder.waitForSnapshot・SMBKeyedManualSleeper.fireAll）を消す`（5d34f7f）。
  - 製品の実行経路は変えていない（足したのは #if DEBUG のテスト用 API と hook だけ。テストで製品の不具合は見つからなかった）
  - 実装は codex（luna-max）。レビューは codex（sol-high）の 2 周: 1 周目（発見型・素通り・壊す）で 7 件、直した差分への 2 周目（素通り）で 4 件。すべてテストの検知力の指摘で、
    どれも直す前に変異ですり抜けることを確かめてから直した。1 周目の重複 ack のテストは、hook が CREATE で止まり ack 0 件のまま何もしない dispatch を数えていた（codex の初回報告の「二重減算で red」は誤りだった）
  - 1731eef の CI で SwiftLint analyzer（unused_declaration）が 2 件で落ちた: 2 周目の修正で使われなくなった helper。codex は「関数を消していない」として make lint-analyze を最後まで回しておらず、
    main agent も strict lint だけで analyze を回していなかった。消して 5d34f7f で直した
  - 性能（1731eef の push の Performance、arm64、20 組、reference は M3 の 69fefaa、cpu_model は両側とも記録）: read +2.2% / user CPU −3.4%、write +1.3% / −0.5%、RSS ±0%。gate PASS（製品の変更が無いので揺れの範囲）
  - 5d34f7f の CI: Test / E2E / Performance / Issues とも success、`verify-agent-push` rc=0
- **Commit 5（M1〜M4）が終わり、設計 §8 の Commit 1〜5 がすべて master に入った（2026-10-16）**

## 関連

- issue 010（M3 と P2-2）、069（M2）、104（compound）、105（M3 の reader の idle 時の懸念）
- `Sources/SMBee/SMBClient.swift`（`SMBUnsentRequestRecord` / `SMBRequestIdentity` / `SMBSession`）、`Sources/SMBee/SMB2Header.swift`（`SMB2CreditWindow`）

## 承認済み設計

# 未送信 request 退役 primitive — 設計 v3

## v3 からの変更点 (R1〜R3、3 周目の R4・R5)

- **R4 — §2.2・§4.1:** session terminal の確定時に、その generation の未選択 control item を queue から除去して ownership を解放し、回収判定をやり直す。oracle: `original send stall → cancel enqueue → final なし → D` で、join 後に control queue=0・active record=0。
- **R5 — §4.1:** 期限前の drain 完了を sticky に記録してその場で deadline を解除し、record は credit ack 後に回収する。oracle: `drain < D、credit ack > D` で session 継続・timer 解放・record 回収。

- **R1 — §2.2・§3・§5・§8 Commit 2・§9–10:** request 固有の response protection policy を登録時に固定し、VALIDATE_NEGOTIATE_INFO の署名または AEAD 必須条件を final・grant・pending removal の確定前に検証する。
- **R2 — §2.2–2.3・§4.1・§8 Commit 3・§9–10:** CANCEL demand の作成時と選択時に finalSeen を再確認し、未選択 control item が無いことを record 回収条件に加える。
- **R3 — §4.1–4.3・§8 Commit 3–4・§9–10:** send completion／owner 回収も固定期限と非 suspension 区間で競合確定し、期限到達後の terminal を sticky にする。

## v2 からの変更点

- **N1 — §2.3・§4.1・§8 Commit 3・§9–10:** drain 完了を original final の受理と original send／選択済み CANCEL の送信所有権回収の両方で定義し、いずれかが残る間は初回 cancel で固定した期限を維持する。
- **N2 — §2.2・§5・§8 Commit 2–3:** AsyncId などの受信相関状態を caller の送信完了 gate から分離し、compound は RequestIdentity ごとの仮状態を wire 順に進め、全体検証後に確定する。同一 MID の二つ目の final は grant 適用前に拒否する。
- **N3 — §4.1–4.2・§5・§8 Commit 1–4:** final 受理時刻と期限の勝敗を session actor の非 suspension 区間で決め、credit await の復帰順を勝敗に使わない。共通の単調 clock と sleeper を注入し、soft／hard deadline の D−ε・D・D+ε を検証する。
- **N4 — §5・§9–10:** 未知 MID を保存して将来 replay する規則を削除し、受信時に bind 済みの RequestIdentity にだけ early response を結び付ける。未知 MID は MS-SMB2 §3.2.5.1.2 に従って discard する。
- **N5 — §6・§8:** preparatory commit は現行経路を維持し、受信 foundation（認証前 grant の除去を含む）を有効化より前に置く。有効化 commit に handle cancellation・postcommit terminal policy・drain deadline を同梱し、各 commit が単独で契約を満たす受け入れ条件を追加する。
- **N6 — §2.3・§8・§9:** sender を session actor 内の需要駆動 drain loop に固定し、別 actor と request ごとの global hop を禁止する。loop の起床回数を観測し、production path を有効化する各 commit に Performance CI の 20 組比較 gate を必須化する。
- **N7 — §2.2・§3.2・§8:** foundation の record を identity、credit owner、send／wire／caller state、必要な timer に限定し、slot・byte lease・delivery・epoch は pipeline milestone へ送る。canonical record の回収条件と drain loop の idle 終了条件を定義する。

設計基点は master 75efe4d56746c4c3c0d1e40f8d03eda569a36836。本書は設計であり、実装・テスト・性能測定は行っていない。N1〜N7 はすべて採用し、未採用項目はない。

## 1. 現行コードと変更先

| 現行の場所・symbol | 現状と v3 での扱い |
|---|---|
| Sources/SMBee/SMBClient.swift: SMBSession | mutable wire state、pendingResponses、cleanupLedger、creditWindow、reader／send task を所有する actor。foundation では最小 request record と identity index、必要な timer を所有する。有効化後は session actor 内の需要駆動 sender drain loop も所有する。generation は session instance 内の wire generation と結び、reconnect は既存どおり新 SMBSession を作る。 |
| SMBSession.nextMessageId(charge:) | 現在は単調 counter を進め、通常 post-auth packet の encode 呼出し元から先に使われる。有効化 commit で post-auth 呼出し元から外し、sender drain loop の非 suspension commit だけで max(1, CreditCharge) 幅を割り当てる。NEGOTIATE／SESSION_SETUP の preauth path は exact-byte hash 制約を保ち、通常 path から分離する。 |
| signedWireTransaction／unsignedWireTransaction／demuxedWireTransaction | 現在は MID 付き packet を受け pending 登録後に performDemuxSend を起動する。preparatory commit では旧経路を維持する。有効化 commit で MessageId-free intent／descriptor を入口にし、TREE_CONNECT、VALIDATE_NEGOTIATE_INFO を含む全 post-auth command を統合する。preauth NEGOTIATE／SESSION_SETUP と target-ID CANCEL は例外。 |
| SMBPendingResponse.sendPhase、markSendStarted、markRequestSent、reconcileSuccessfulSend | 現行 registered は MID 割当後である。v3 は RequestIdentity と MID index を相関に使う。受信相関は sending 中も進めるが caller への response release は full-send gate に残す。未知 MID を後続 pending に replay しない。 |
| activeSendTasks、performDemuxSend、sendPlaintext／sendEncrypted、SMBTransport.send | 現在は per-request Task が send し、frame byte の非交錯以外に同時 send 順序の保証がない。有効化後は session actor 内の単一需要駆動 loop が queue を drain する。別 sender actor と request ごとの Task／global hop は設けない。一 frame の full-send または terminal まで writer ownership を持ち、response final までは占有しない。 |
| SMBPreReservedCredit、claimOrReserveCredit、refundUnclaimedCredit、refundCredit | 現在の claim は shrink surplus を返すが claim 後の actual residual は返せない。最小 request record を credit owner とし reserved(max) → prepared(actual) → committed(actual)／refunded／discardedOnTerminal を一回性 token として管理する。 |
| SMB2CreditWindow の Waiter、reserve、cancelWaiter、refund | waiter は現在 RequestIdentity／Tree scope を持たない。identity と Tree scope を waiter・reservation に伝え、one-shot cancellation と late grant attach/refund ack を receipt から待てるようにする。failAllWaiters は session terminal 専用で、Tree quarantine では使わない。 |
| startReaderIfNeeded、runActorRawReader、hasSentResponseOutstanding、makeReaderDormantIfIdle、readerDidExit | 需要駆動・actor-isolated reader は現 master の前提で維持する。caller cancel 後の wire record は drain 完了まで reader を維持する。send ownership を含め drain が未完了なら deadline が session close に到達させる。 |
| readerTasks、closeTransport、closeTransportAndWait、SMBReaderLifecycle | close は先に terminal 化して transport を閉じ、reader／sender drain／CANCEL send／connect／credit waiter を止める。reader 自身を join しない。deadline terminalizer は reader 外から closeTransportAndWait を完了し、overlapping reader handle も join する。 |
| processRawFrame、SMBReceivedFrame、recordCreditGrant、dispatchReceivedPacket、verifySigned | 現在は frame 先頭 header の grant を署名／相関検証より先に適用し、dispatch は一 header を処理する。受信 foundation で compound を slice 化し、slice ごとの認証・wire 順の仮相関・全体合格後の一括確定を行う。認証前 grant と未知 MID replay を除く。 |
| cleanupLedger、SMBCleanupAttemptState、cleanupTimeoutDidFire、markRequestSent | 現在の cleanup は FileId 専用で、full-send 時に ledger を draining にする。069 M2 では FileId／TreeId discriminator とし、send success は send phase だけを変える。初回 cleanup soft timeout で caller timeout・tombstone・draining・固定 hard deadline を同時に作る。 |
| READ/WRITE entry points | 現在は可変長 packet 作成前に credit を予約し、encode 時に MID を進める。共通 request foundation に pipeline slot・byte lease・delivery・epoch は載せず、後続 milestone で ticket と寿命管理を追加する。 |

現行 master に常駐 weak reader、reader claim/catch 責務、SMBRequestLedger、TransferTicket、post-auth single sender loop、Tree-scoped credit waiter、compound response slicer はない。これらを現行実装として記述しない。

## 2. 契約と状態

### 2.1 境界

credit 残高と MessageId sequence window は別資源である。client は利用可能な最小 MessageId を選び、通常 request の有効幅は max(1, CreditCharge) の連続 range とする。CANCEL は対象 request の MessageId／AsyncId を使い、新しい MID も credit も消費しない。CreditRequest は server への希望 grant であり予約ではない。credit 数値を refund して MID counter を進めたまま接続を継続する実装は許さない。

- MID 割当前は local intent。退役すれば MID を持たず caller を完了し、credit／waiter／queue item／timer を一回だけ解放する。foundation に pipeline slot／byte lease／delivery／epoch は作らない。
- MID 割当後は MessageId range と実効 credit が不可逆。request を full-send して original response を drain するか、wire／send ownership が不確かなら固定 deadline で session generation 全体を terminal にする。
- 現行 registered を MID 未割当の意味に流用しない。
- commit と local retire は同じ session actor の非 suspension 区間で線形化する。commit 後に MID／credit を戻さない。

### 2.2 canonical record

foundation record は将来の pipeline outcome を格納する汎用台帳ではない。

RequestIdentity = (SMBSession instance / generation, requestUUID)  
Scope = (treeId?, fileId?, command, cleanupResource?)  
ResponseProtectionPolicy = sessionResolvedSnapshot | signatureOrAEADRequired  
CreditOwner = (waiter?, reservation?, surplusRefund?, residualRefund?)  
SendOwner = (queuedRequestItem?, unselectedControlItem?, originalFrameSend?, selectedCancelSend?)  
TimerOwner = (requestTimeout?, wireDrainDeadline?, cleanupSoftAt?, cleanupHardAt?)

各 post-auth request は MID 取得前に安定した RequestIdentity を得る。credit waiter／reservation、queue item、pending MID index、deadline はその identity を参照する。wire pendingResponses[MessageId] は demux index のままでもよいが、session 内 active record が send／wire／caller state の正本となる。pipeline milestone までは transferEpoch、bulk slot、byte lease、delivery queue／receipt を record に加えない。

responseProtectionPolicy は request の final response に対する保護要件であり、request 登録時に command と negotiated session の保護要件から解決して immutable value として record に固定する。sessionResolvedSnapshot は登録時点の session 要件を値として保持し、後の session 設定参照で変化しない。VALIDATE_NEGOTIATE_INFO は signatureOrAEADRequired を使う。

record は次の独立・sticky state を持つ。

- caller: pending／success／local refusal／cancel／timeout／transport error。continuation resume は一回。受信 response は相関できても caller release は full-send gate まで保留できる。
- send: notStarted／neverSubmitted(reason)／committed(messageId, charge)／fullySent／failed。fullySent と send ownership 回収は別イベントで、transport send の戻りと frame owner release を確認する。
- wire: waiting、STATUS_PENDING と AsyncId、受理済み original final と受理時刻、session terminal。cancel、CANCEL send success、未送信退役は wire final ではない。
- credit: waiting／reserved(max)／prepared(actual)／committed(actual)／refunded／discardedOnTerminal。surplus と precommit residual は別 one-shot refund receipt を持つ。
- 必要な request／wire drain／cleanup timer identity と絶対期限。

受信相関 state（AsyncId、finalSeen 等）は send phase／caller release gate と分ける。STATUS_PENDING は final ではなく、その slice を検証した時点で仮相関 state に AsyncId を設定し、compound 全体合格後に確定する。平文 interim の署名 exception は維持する。pipeline delivery state は foundation に含めない。

handle は RequestIdentity と immutable completion／retirement receipt を外から参照できるが、session の active record 全体を保持させない。

**回収条件:** 未commit retire は caller terminal、queue 除去、waiter removal ack、late grant settlement、refund ack、timer cancel がすべて済み、send ownership と MID index が無い時に session index から除く。commit 済み record は caller terminal、wire final または session terminal、original send と選択済み CANCEL の所有権回収、identity の未選択 control item が無いこと（session terminal の確定時に、その generation の未選択 control item はすべて queue から除去し ownership を解放して、回収判定をやり直す。§4.1）、pending MID index 除去、必要な grant／credit ack、timer cancel が揃った時に除く。pipeline milestone 以降だけ delivery terminal を追加条件にする。

### 2.3 状態別退役と sender loop

| 状態 | wire identity | retireUnsent／cancel の意味 |
|---|---|---|
| intent／credit wait／send queue（未commit） | MID range・pending MID index なし | neverSubmitted を固定し、Tree／File／caller／deadline guard を session actor で線形化する。waiter ack、late grant refund、queue removal、timer release を receipt が join。CANCEL・tombstone・wire final は作らない。 |
| commit | 同一非 suspension actor transaction で MID range、frame、pending bind、original send ownership を確定 | 外部から取消可能な「MIDあり・未送信」を公開しない。build／sign／encrypt failure も range を戻さず session terminal。 |
| committed／sending | MID と charge 固定、original frame send owner あり | cancel は caller outcome を一回返し、send ownership を奪わず固定 deadline を作る。CANCEL demand を作る直前に同じ非 suspension 区間で確定済み finalSeen を確認し、final 済みなら item を作らない。受信相関は sent 前でも進める。credit refund なし。 |
| fully sent／sent | pending correlation と必要な tombstone を保持 | valid final 後も original send／選択済み CANCEL owner が残れば drain 未完了。未選択 control item は final 到着時に除去し、sender loop の選択直前にも同じ actor 非 suspension 区間で finalSeen を再確認して final 済みなら破棄する。選択済み CANCEL は期限まで owner として扱う。 |

採番と send は session actor 内の単一需要駆動 drain loop が担う。request は credit reservation、payload length、CreditCharge、CreditRequest snapshot、scope guard を準備して FIFO queue に入る。loop は queue が idle から non-empty になった時に起動し、各 item の最終 admission guard、MID、frame build、pending bind、send ownership を非 suspension commit で確定する。commit に actor／credit await、callback、別 actor hop を挟まない。current frame の full-send または terminal まで次 frame を送らない。CANCEL は同じ loop の control lane で frame 境界に送る。control item を選択する直前にも対象 identity の finalSeen を非 suspension 区間で確認し、final 済みなら drop して選択 owner を作らない。selection が final acceptance より先なら、その後の final でも選択済み owner は維持する。

request ごとの Task 起動や sender 用別 actor は作らない。session-level wake は drain 中に一つだけとし、item ごとの追加 wake をしない。queue empty かつ current frame／選択済み control item の owner が無い frame 境界で loop を終了し、running flag を解除する。wire final 待ちだけの record は loop を保持しない。次の enqueue／CANCEL demand が idle loop を再起動する。queue empty・owner none・running false が idle 終了条件で、close は active loop を join する。

第一版 outbound は NextCommand == 0 の単一 request packet に限定する。compound outbound 将来対応時は全 member の scope／guard／MID を一 transaction にし、採番後 frame から member を抜かない。

## 3. credit ownership と概念 API

foundation は以下の意味を持つ。pipeline-specific slot／lease／delivery API は後段まで追加しない。

- registerUnsent(intent, scope, deadline, timeoutPolicy, responseProtectionPolicy) → RequestHandle（保護 policy をここで解決・固定）
- reserveCredit(handle, maxCharge, priority) → CreditReservation
- prepareCredit(handle, actualCharge) → PreparedCredit
- retireUnsent(handle, reason, callerError) → RetirementReceipt
- enqueue(handle, frameDescriptor)
- commitSend(handle, frameBuilder) → CommitResult（同期・非 suspension）
- cancelCommitted(handle, reason) → DrainHandle
- acceptAuthenticatedChain(slices) → ReceiveReceipt（相関確定前は非 suspension）

### 3.1 reservation の一回性

現 SMBPreReservedCredit の claimed bit と releaseUnclaimed() だけでは claim 後の precommit actual residual を返せない。最小 record を唯一の credit owner とし、次を守る。

1. maxCharge > actualCharge の surplus は payload preparation で返す。refund 開始前に record が ownership を取り、credit actor ack を receipt に加える。
2. commit 前に retire が勝てば actual residual を一度返す。surplus と residual refund が並行しても二重返却しない。receipt は双方の ack を待つ。
3. commit が勝った actual charge は wire-consumed へ移り、その後 local refund 不可。採番後の send／encode／crypto failure は generation terminal とし、balance を戻さない。
4. grant と retire が競争し reservation が遅れて返った場合、retired identity に attach せず一度 refund する。waiter 取消 ack だけで receipt を閉じず、late effect も待つ。

actualCharge は body と header で一致し、CreditCharge == 0 は effective charge 1 とする。CreditRequest snapshot は commit 前に作り、採番後に別 actor await をしない。

### 3.2 retirement と receipt

retireUnsent は commit と同じ SMBSession actor で線形化する。結果は retiredLocally(receipt)、alreadyRetired(receipt)、committedNeedsWireDrain(handle) を区別する。局所 receipt は caller result、waiter removal／late grant settlement／credit refund／queue removal／timer release の完了を表す。foundation に slot／byte lease／pipeline delivery receipt は含めない。二回目の retire は同じ receipt を共有し、副作用を再実行しない。

committedNeedsWireDrain は local Tree／File refusal の成功を意味しない。未確定 caller outcome は cancel／error を一回返し、wire outcome は session deadline と valid final／terminal に任せる。commit 後を neverSubmitted と言い換えない。閉じた receipt は handle 側に残し、session 内の完了 record は蓄積しない。

## 4. deadline と close

### 4.1 通常 request cancellation: P2-2 と drain 完了

現 master の requestTimeout は Duration? で full-send 後から始まる。cancel 時に timer が外れ sent tombstone が残るため、これだけでは final 不在に上限がない。

wireDrainGrace は有限・非 optional（初期値案 60 秒）とする。最初の cancelCommitted が共通の単調 clock で cancelAt を読み、一度だけ wireDrainDeadline = min(cancelAt + wireDrainGrace, enclosingAbsoluteDeadline?) を固定する。send 中にも有効。繰返し cancel、CANCEL send 完了、STATUS_PENDING、final 後の credit ack は期限を延長しない。requestTimeout == nil でも deadline はある。

cancelCommitted は caller outcome と期限を通常どおり確定したうえで、CANCEL demand を作る直前に確定済み finalSeen を同じ非 suspension 区間で確認する。final 済みなら CANCEL item は作らない。original send owner が残っている間はその owner を D まで拘束する期限として維持する。

**drain 完了は original final の受理と次の全 send ownership 回収の論理積である。**

- original request frame send ownership が回収済み。
- 選択済み CANCEL frame があれば、その send ownership が回収済み。

original final 到着時に未選択の CANCEL は queue から取り除く。さらに sender loop は選択直前に finalSeen を再確認し、final が先に確定していれば item を破棄する。選択済み CANCEL の transport send owner は final だけでは消えない。original request send がまだ transport send 中でも同じ。いずれかが残る間、初回 D を維持し timer を cancel しない。

full-send completion と各 send owner 回収は、所有権 state を変更する前に同じ actor 非 suspension 区間で単調 clock を読み、固定 D と勝敗を確定する。回収時刻が D 未満なら owner を解放できる。now >= D なら、解放で drain が完了する場合も deadline 側を sticky にして先に session terminal を確定し、reader 外の terminalizer に close／join を渡す。通常 drain 完了の timer cancel、timer identity の無効化、record 回収で期限勝者を覆さない。期限 timer／terminalizer が close と join を完了するまで、その timer identity を有効な generation fence として保つ。D で owner が残れば original final が受理済みでも terminal にし、transport close で停止中 send を解放して sender／reader を join する。新しい grace は足さない。

CANCEL は original request frame の full-send 後、同じ writer control lane で対象 MID／AsyncId を使う。CANCEL response は待たず、send success を original final と見なさない。caller と wire drain outcome は独立する。

deadline callback は RequestIdentity／generation／timer identity を再確認する。D 到達で drain 未完了なら reader 外から closeTransportAndWait 相当を実行し、transport、original／CANCEL send、sender loop、credit waiter、reader Task を join する。reader fault 経路は自分自身を join しない。timer は弱い session capture とする。D 前に drain が完了したら（final 受理と全 send owner 回収）、その時点で drain 完了を sticky に記録し、record の回収を待たずに deadline を解除して timer を cancel する。record 自体は grant／credit ack が揃った後に回収する（期限の勝敗と record の回収時刻は分ける）。deadline 側が sticky になった後は terminalizer の close fence が効くまで無効化しない。既存 absolute hard deadline があれば最短を採り、queue／send／drain 中に期限を再設定しない。

session terminal を確定するときは、その generation の未選択 control item（CANCEL）をすべて queue から除去し、ownership を解放してから close／join する。queue に残った item が record の回収を止めないようにする。

### 4.2 069 M2 cleanup: soft caller deadline と hard wire deadline

cleanup intent の t0 で同じ monotonic clock から絶対時刻を固定する。

- cleanupSoftAt = t0 + cleanupTimeout（既定 5 秒案）。credit／queue wait を含む。未commitなら local retire、commit 後の send が未完／曖昧なら session terminal、full-sentなら caller timeout と wire tombstone。
- cleanupHardAt = cleanupSoftAt + min(requestTimeout ?? cleanupDrainGrace, cleanupDrainGrace)。soft 発火時に grace を足さない。soft 後 hard 前の正規 final は該当 Tree／File を片付け他 Tree を保つ。hard 到達時に drain が残れば session terminal。

cleanupLedger の sending は File／Tree resource state で wire sendPhase の別名ではない。precommit intent から full-send 後の初回 soft timeout まで ledger は sending。full-send だけでは draining にしない。hardAt は t0 で記録するが drain sleeper は full-sent request が soft timeoutし draining へ移る時にだけ登録する。sleep duration は hardAt - now。soft 前の full-send は ledger sending／caller pending／drain sleeper なしとする。

M2 の retiredUnknown は pending なし・hard drain timer なし。正規 final status failure は resource だけ retiredUnknown にして session を保つ。malformed／auth／correlation fault、committed send stall、hard expiry は session-wide terminal。

full-send completion も固定 cleanupSoftAt と actor 非 suspension 区間で比較する。softAt 未満に fullySent が確定した request は既定の soft timeout policy に進める。now >= softAt で record がまだ sending なら、遅れてきた completion を先に full-send 確定して sent soft-timeout 経路へ変えず、soft 側の session terminal を sticky にする。soft 後の drain では同じ規則を cleanupHardAt に適用し、hardAt 以降の最後の owner 回収は hard terminal を取り消さない。

### 4.3 clock・sleeper と reader 解放 oracle

SMBSession に単調 clock と sleeper を一組で注入する。production pair と test fake pair は同じ時刻軸を使う。request timeout、ordinary drain、M2 soft／hard、final acceptance は同じ clock を参照する。sleeper fire だけで期限到達を決めず、actor 上で now >= D を判定する。D ちょうどは期限側が勝つ。

slice の認証・相関が完了した時刻を記録する。compound は slice ごとの時刻を仮記録し、chain 全体が合格した時に session actor の同じ非 suspension 区間で相関状態・final acceptance・期限勝敗を確定する。acceptedAt < D は deadline callback の実行順に関係なく final 側、acceptedAt >= D は timer callback が未実行でも期限側である。credit actor grant await は確定後だけ行い、その復帰順で勝者を変えない。

send completion／owner reclamation も固定期限との勝敗を状態変更前の同じ actor 非 suspension 区間で確定する。期限前に回収済みと確定した owner だけが通常 drain を成立させる。D 以降の回収は terminal を sticky にし、後着または先着 callback の順で期限勝者を変えない。M2 の full-send は cleanupSoftAt に対して同じ比較をし、softAt 以降の completion が sender-still-active の soft expiry を sent request の timeout に書き換えない。

ordinary wire drain、M2 soft deadline、M2 hard deadline のそれぞれで D−ε／D／D+ε を試す。D−ε は期限前、D と D+ε は deadline policy。仮想時刻を保ったまま sleeper callback 順を逆にしても結果を一致させる。final 受理後に grant await を止める mutation でも acceptance winner が維持される。

さらに次の 2 本を必須 oracle にする。(1) `original send stall → cancel enqueue → final なし → D`: terminal の後、close／join が完了し、control queue=0・active record=0。(2) `drain 完了 < D、credit ack > D`: session は継続し、timer は D 前に解放され、record は ack の後に回収される。

追加 oracle: final を D−ε に確定し、最後の original／選択済み CANCEL owner 回収を D−ε／D／D+ε に置く。各回で deadline callback を owner completion より先／後に実行する。D−ε 回収だけが通常 drain と timer cancel を許し、D／D+ε 回収では callback が遅れても terminal が sticky で terminalizer 適用前に timer identity を無効化しない。M2 では full-send completion を cleanupSoftAt−ε／exact／+ε に置き、soft callback 順も逆転して soft expiry の勝者と terminal／sent policy が一致することを確認する。

P2-2 回帰は ordinary request 一件、transfer pump なし、final を返さない transport で行う。

1. requestTimeout nil で full-send し、reader start と sent pending を確認。
2. caller cancel 後 caller は一回だけ cancel error。original final を止め、CANCEL success だけで wire outcome が終わらないことを確認。
3. CANCEL を選択して send 中に止めた後 original final を受理する。D は維持し、D で terminal／transport close／send owner 回収／sender・reader join／pending 0 を確認。
4. 別 fixture で original request send 自体を full-send 前に止め、期限 terminal と owner join を確認。
5. D より前に final と全 owner を回収する対照では timer cancel、reader dormant／exit、session close なし。repeated cancel と STATUS_PENDING は期限を延長しない。
6. 最後の外部 SMBSession reference を外し deinit event を待つ。probe は session を保持しない。
7. early final → cancel → original send 完了を試し、CANCEL demand／send が作られず、send owner 回収で通常 drain が完了することを確認する。別順序では CANCEL demand 後・選択前に final を確定し、item が捨てられることを確認する。

reader exit・join・session deinit を別 event として確認する。test transport は close 契約どおり未完了 receive／send を解放する。

## 5. 受信・wire final boundary（issue 104）

現 processRawFrame は decrypt／header decode 後に frame 先頭の CreditResponse を適用し、一つの header／MID を dispatch する。v3 は response slice ごとに相関し、sent gate を correlation gate として使わない。

受信順:

1. transform 復号後に NextCommand chain 全体の bounds、8-byte alignment、最低 header 長を検証して slice 化する。不正 chain は wire fault とし部分成功にしない。
2. 各 slice の transform AEAD と存在する署名を検証し、session 全体の保護要件を強制する。平文 STATUS_PENDING interim の署名 exception は維持し、仮検証状態には確認した保護方式を記録する。request 固有 policy の評価は identity bind 後に行う。この時点では grant／caller completion／pending removal を適用しない。
3. MID を受信時の pending index で照合し、bind 済み RequestIdentity を固定する。active committed request がない未知 MID は MS-SMB2 §3.2.5.1.2 に従って discard し、orphan／future replay に保存しない。未知 slice の CreditResponse も適用しない。
4. identity ごとの一時 correlation state を作り、slice を wire 順に検証する。command／session／tree／MID／AsyncId／STATUS_PENDING／final を仮状態に照合する。sending 中の STATUS_PENDING は AsyncId を仮状態に設定し、後続 slice／frame の検証に使う。caller release は sent gate で別に保留する。
5. 同一 identity で一 final を仮記録した後、同一 compound の二つ目の final は chain を拒否する。どの slice の grant も先に適用しない。first final 確定後の後続 frame は outstanding request のない未知 MID として discard し grant しない。
6. chain 構造・認証・既知 slice の相関・final を含む各 identity の immutable responseProtectionPolicy が全て合格した時だけ、仮状態を wire 順に record へ確定する。`signatureOrAEADRequired` は final に対し有効な plaintext signature または transform AEAD を要求する。従って signing optional の session でも無署名・非暗号化 VALIDATE_NEGOTIATE_INFO final は拒否し、session terminal にする。平文 STATUS_PENDING interim の既存署名 exception は保つ。この検証を通る前に final／deadline winner／pending removal を確定せず、CreditResponse も適用しない。final acceptance time と deadline winner も同じ非 suspension 区間で確定する。sending record の早着 slice は同じ RequestIdentity に保持し、caller success は full-send gate 後に渡す。replay 時に MID 再検索で別 identity に付け替えない。
7. 合格 slice の CreditResponse を各一回適用する。grant actor await は状態と期限勝敗の確定後だけに行う。receipt は再処理による二重 grant を防ぐ。
8. 後続 malformed／bad signature／既知 identity の不正 correlation があれば、chain 先行 slice の success／grant／pending removal も確定せず session terminal にする。未知 MID の discard 自体は future replay を作らない。

同じ MID の STATUS_PENDING → async final は、同一 chain／別 frame の両方で request が sending 中に到着しても AsyncId を引き継ぐ。AsyncId を sent gate まで遅らせない。CANCEL の MID／AsyncId も確定済み相関 state から作る。

必須 oracle: cancelled R + live X の chain、sent R + sending X、同一 MID の interim＋finalを同一 chain／別 frame の sending 中に返す、同一 chain duplicate final の grant 前拒否、plaintext signed slice ごとの署名／padding、encrypted compound、後続 malformed NextCommand、未知将来 MID discard 後に同 MID の request を送っても過去 response が結び付かない、signing optional で無署名・非暗号化 VALIDATE_NEGOTIATE_INFO を final／grant／pending removal なしで拒否する。caller／send／wire outcome、grant 回数、credit await 後 balance、pending 数を確認する。単独 response test は first-slice-only mutation を検出しない。仕様背景は issue 104。

## 6. issue 069 M2 との依存・順序

069 M2 は tmp/m2/d2/design.md §9 Commit 1〜4 を基礎にする。現 registered + scalar refund による未送信 MID の局所退役は本 v3 境界で置き換える。tmp/m2/d3b/review.md N1〜N5 を次のように扱う。

| M2 review | v3 の決定／順序 |
|---|---|
| N1: 未送信 MID が戻らず他 Tree の next MID が window 外 | MID range を返す allocator は作らない。local refusal 有効化前に post-auth path を未採番 handle + commit に移す。Tree quarantine 先行なら MID なし退役、commit 先行なら send + drain または terminal。sequence reuse 案は採らない。 |
| N2: File CLOSE と Tree quarantine | file self-gate exemption と Tree exemption を分ける。File CLOSE は自分の File quarantine には対応できるが同 Tree quarantine は通らない。未commitなら File ledger／timer を retiredUnknown にし Tree ledger は変えない。commit 済みなら送信／terminal のみ。 |
| N3: 既存 credit waiter | waiter に RequestIdentity／Tree scope を持たせ、Tree A quarantine は A の未commit waiter／queue だけを取消す。B long-poll waiter／transport を維持し failAllWaiters を使わない。receipt は late reservation と credit ack を待つ。 |
| N4a: top-only parent ancestry mutation | d2 Commit 1 child close と分け、P-owned A callback → Q-owned B callback → P.close の別 owner nesting で全 ancestry scan を検証する。 |
| N4b: TaskLocal mutation が lease drain bypass を証明しない | active lease counter の drain を event gate で試す。detached worker を構造条件にするなら worker-entry seam で TaskLocal nil を直接 assert する。 |
| N5: full-send だけで ledger が draining | markRequestSent は send phase だけ sent にする。初回 soft timeout 前は File／Tree ledger sending、caller pending、drain timer なし。soft timeout が caller timeout + tombstone + draining + 固定 hard timer を同時に作る。 |

依存関係:

1. M2 high-level operation lease／parent-child close barrier（d2 Commit 1）は preparatory に先行できるが、現行 post-auth 経路と best-effort Tree cleanup を保ち、local-success policy を有効化しない。
2. 本書 Commit 1 は最小 request identity／credit ownership の準備で、post-auth request は旧経路のまま。単独 commit で旧 wire／cancel 契約を変えない。
3. 本書 Commit 2 は受信 foundation を先に導入する。認証前 grant を除去し、per-slice correlation、compound 仮状態、unknown MID discard を完成させる。sender は旧経路のまま。
4. 本書 Commit 3 が初めて post-auth send path を有効化する。handle cancellation、postcommit terminal policy、ordinary drain deadline、全 entry point の sequencer 移行を同じ commit に含める。
5. M2 d2 Commit 2 の scoped cleanup discriminator／reporting、Commit 3 の Tree admission/local refusal、Commit 4 の soft/hard policy は、本書 Commit 4 で一体導入する。Commit 3 の handle を使うが、M2 の局所退役契約を部分的に有効化しない。pending guard は intent 登録、waiter cancel、commit 最終 guard とし、MID 採番後の registered cleanup にしない。
6. pipeline ticket は Commit 5 で共通 request／credit／commit core に載せる。M2 専用 refund、READ/WRITE 専用 MID allocator、foundation 時点の pipeline lease／scheduler は作らない。

production request／receive path を有効化する各 commit は単独でその契約を満たす。受信 foundation 前の新 sender、取消／terminal policy／drain deadline を欠く sender、有効化と後追い修正を分けた intermediate commit は作らない。

## 7. READ/WRITE pipeline への適用

現 readChunkReportingRequestedLength と writeChunk は可変長 packet 作成前に variable credit を予約し、encode 時に MID を進める。有効化後は各 post-auth chunk が pre-MID RequestIdentity と session sender loop を使う。

pipeline slot／byte lease／delivery／epoch は foundation record に先行追加しない。専用 milestone で ticket owner extension として加え、immutable scope に treeId、fileId、transferEpoch、offset、length を持たせる。

- cancel、source/sink failure、short-read rebase、File／Tree quarantine は uncommitted ticket を retireUnsent し queue から除去する。delivery を discard／not-applicable とし、その receipt で epoch drain を完了する。未送信 ticket に wire final を作らない。
- committed READ／WRITE は send + authenticated final／terminal を待つ。cancel は必要な CANCEL と original final drain を行い、transfer absolute deadline より後に wire deadline を延ばさない。
- short-read rebase は旧 epoch の未採番 ticket receipts を join してから新 offset を作る。送信済み旧 epoch request は final／terminal まで drain する。
- pipeline record は caller terminal、wire／send owner 回収、credit ack、delivery terminal、slot／byte lease release が全て揃った後に回収する。

## 8. commit milestone と受け入れ・mutation oracle

event／barrier／manual sleeper で事象順を制御し、caller result、MID／range、credit balance／refund count、pending／waiter／ledger、send有無、transport、reader、sender loop、deinit を別々に観測する。実時間 polling loop は追加しない。既存 request-sent／pending／credit waiters、transport frame gates、event sleeper を使い、operation wait は hang guard で囲む。wall-clock は失敗時の hang guard に限り、競合順序や deadline を進めない。

production path 有効化または hot path 変更を含む各 commit は CI Performance gate を必須とする。20 組の alternating current／previous-master 比較を同じ runner で行い、run URL、medians、effect size、95% confidence interval、Holm-adjusted p-value、observed spread を記録する。単一 raw sample／p-valueだけで判断しない。metadata 不整合で gate が skip された場合は未検証と明示し、比較可能な測定が完了するまで performance-sensitive work を完了扱いにしない。prep-only Commit 1 は旧 hot path を変えない。

### Commit 1 — preparatory request identity と credit owner

内容: RequestIdentity、最小 caller／send／wire／credit state、one-shot credit token、waiter cancellation／late attach ack、retirement receipt、共通 monotonic clock／sleeper を準備する。現行 pending に identity を関連付けるが、packet 作成・MID 採番・send は旧経路のまま。pipeline state と sender loop は追加しない。

受け入れ条件:
- 単独で現行 wire sequence、cancel caller outcome、credit balance、reader lifecycle を変えない。全 post-auth caller が旧経路を使う。
- max4 reservation → actual1 shrink を surplus refund 前／後に重複退役する。最終 balance=4、MIDなし、surplus3／residual1 各一回。receipt は late grant／refund ack 後だけ完了。
- duplicate retire は同 immutable receipt。closed receipt 後に session record が蓄積せず回収される。
- production clock／sleeper adapter は従来時刻動作を保ち、fake pair は同一仮想時刻を返す。

red mutation: route を先に切り替える、claim後 residual refund を落とす、max4を丸ごと返す、waiter ack で早く receipt close、duplicate refund、foundation に pipeline field を追加。

### Commit 2 — 受信 foundation と compound correlation

内容: response chain slicer、per-slice signature／AEAD、RequestIdentity bind、wire 順仮 correlation、grant receipt を processRawFrame／dispatchReceivedPacket に導入する。認証・相関前の header grant を除く。旧 sender／pending registration route を維持し、未知 MID は保存せず discard する。

受け入れ条件:
- 単独で §5 の受信契約を満たし、旧 send／cancel 契約を維持する。
- sending 相当の STATUS_PENDING → AsyncId final を同一 chain／別 frame で検証し caller gate と相関 state の分離を確認する。
- duplicate final は仮状態で拒否し、先行 slice を含む grant／caller completion を一度も確定しない。
- 認証前 grant がなく、未知 MID は grant／pending completion／future replay を作らない。同じ MID を後 request が使っても結び付かない。
- signing optional の session で無署名・非暗号化 VALIDATE_NEGOTIATE_INFO を拒否し、final／grant／pending removal を一切確定しない。
- per-slice grant は一回。credit actor await を止めても final acceptance time は変わらない。
- production receive path 変更として20組 Performance gate を通す。

red mutation: header grant先行、first-slice-only、compound全体を一署名扱い、request protection policy を登録後に決める／検証後に適用する、仮状態をwire順に進めない、sent前にAsyncIdを反映しない、未知MIDをorphan保存、duplicate検査前にgrant。

### Commit 3 — post-auth activation、cancel、wire drain、reader teardown

内容: post-auth nextMessageId call sites を除き、全 post-auth command を MessageId-free descriptor／session actor sender loop に移す。最終 admission guard、MID range、sync frame build、pending bind、send ownership を非 suspension commit にする。同じ有効化 commit に handle cancellation、postcommit terminal policy、有限 wireDrainGrace、固定 deadline、send／CANCEL ownership、close join を含める。preauth NEGOTIATE／SESSION_SETUP と target-ID CANCEL は例外。

受け入れ条件:
- Tree A uncommitted retire 後、A に MID／send／pending／CANCEL がない。初期 credit 2・window {100,101} で A retire → Disconnect MID100/grant0 → B MID101 を確認する。charge3 retire 後は V が100..102、残 credit1 の W が103 を使う。
- 全 post-auth endpoint が新 route。send queue は frame を直列化するが response final を待たず次 frame を進める。
- MID後の build/sign/encrypt/send failure は session terminal、MID／creditを同 generationに戻さない。precommit retire は MIDなしで終わる。
- sending 中 cancel は caller outcome一回、send owner維持、初回固定D。CANCEL は target MID／AsyncId、追加 MID／creditなし。選択前の final なら queue item を除ける。
- early final → cancel → original send 完了では CANCEL demand／send が作られず、owner 回収で通常 drain が完了する。CANCEL demand 後・selection 前の final でも item を捨て、selection が先なら選択済み owner を保持する。
- 選択済み CANCEL send stall + original final と original send stall の両 fixture で、finalのみでは完了せずDで terminal／close／send join／reader join／deinit。ordinary drain の D−ε／D／D+εを検証。
- final を D−ε に固定し、最後の owner 回収を D−ε／D／D+εで試す。deadline callback と send completion の順を逆転しても、D−ε だけが通常 drain、D／D+εはsticky terminalとなり terminalizer 適用前に timer identity を無効化しない。
- sender wake count、loop start／exit、frame count を観測。per-request Task／別 actor hop なし。idle 終了後に loop が残らず、新 demand で再起動。
- この activation commit 単独で契約を満たし、同一 runner の20組 current／previous-master Performance gateを通す。

red mutation: eager MID escape、guard除去、range幅誤り、MID後refundして続行、別actor／per-request global Task、cancelでoriginal send放棄、CANCEL successをfinal扱い、CANCEL 作成／選択前のfinalSeen確認を省く、finalだけでtimer cancel、期限後owner回収でtimerを無効化、期限延長、owner回収前にrecord／loopを破棄。

### Commit 4 — issue 069 M2 integration

内容: cleanup resource file/tree、scoped TREE_DISCONNECT、cleanup reporting、Tree quarantine、Tree／File admission、per-Tree waiter cancel、soft／hard deadline をhandleに結ぶ。M2 operation lease／parent-child barrier oracle も揃え、cleanupFileId専用経路を discriminator にする。

受け入れ条件:
- d2 Commit 1〜4 の public/error-priority/TreeId 0/setup/reconnect 契約を保つ。P-owned A → Q-owned B → P.close で全 ancestry scan を検証。worker lease counter drain gate 解除前に cleanup を送らない。
- Tree A quarantine は A の precommit credit wait／queue だけを grantなしの tree-local error にし、A waiter=0。Tree B long poll と transport は残す。failAllWaiters を使わない。
- File CLOSE(F,A) 未commit × Tree A quarantine は caller一回、File ledger retiredUnknown、File timer／waiter除去、Tree quarantine維持、B継続。self-file exemption が Tree guard を飛ばさない。
- full-send直後・soft前は pending sent、ledger sending、caller pending、drain sleeperなし。soft到達時だけ caller timeout + tombstone + draining + 既固定 hard timer。soft／hardの各D−ε／D／D+εをcallback順と独立に試す。
- full-send completion を cleanupSoftAt−ε／exact／+εに置き、soft callback 順を逆転しても、softAt 未満の full-send と softAt 以降の sending terminal が入れ替わらないことを確認する。hardAt 付近の最後の owner 回収も同様に比較し、期限以降の回収で hard terminal を取り消さない。
- soft／hard は intent 時点で固定し、hard expiry は session terminal。他 Tree 維持条件を確認する。
- hot path activation として20組 Performance gateを通す。

red mutation: scalar refund／eager MID、全cleanup Tree exemption、全credit waiter fail、A waiter残存、top-only ancestry scan、lease drain bypass、markRequestSentで早期draining、soft時にhard grace積増し、softAt以降の full-send で送信中 terminal を sent timeout に変える、exact-Dを期限内とする。

### Commit 5 — READ/WRITE ticket と delivery integration

内容: read/write entry points と streaming transfer の各 chunk を共通 request record に載せ、この段階で bulk slot／byte lease／transferEpoch／delivery を追加する。short-read rebase／source-sink failure／cancel を retireUnsent に接続する。

受け入れ条件:
- credit wait／queue の未採番 ticket はreceipt後epoch drainし、wire final timerを待たない。full-sent ticketはfinal／terminalとdelivery terminalまでslot・byte lease保持。
- old epoch未採番ticketとcommitted ticketをgateし、short-read rebaseで前者だけ退役、後者のfinal後に次offset。delivery／offset／byte countの重複欠落なし。
- source/sink failureとcancelを競合させてもterminal／caller outcome／lease releaseは一回。期限にgraceを足さない。
- delivery／lease receipt後にactive indexから回収し、sessionに完了ticketを蓄積しない。
- pipeline activationとして20組 Performance gateを通す。

red mutation: queue item残存、notStartedとneverSubmittedを混同、deliveryをepoch receiptから外す、cancelでslot早期解放、別MID allocator、delivery完了後もrecordを保持。

## 9. 共通不変条件

1. **Stable identity:** waiter／reservation／timer／queue／pending index／receipt は同じ (session,generation,requestUUID) を使う。
2. **Commit boundary:** precommit retireだけがMIDなし完了を許す。commitとretireはsession actorで線形化し、commit後はfull-send＋drainかsession terminal。
3. **Sequence conservation:** 最小許容MID range、幅 max(1,CreditCharge)。未採番退役でcursorを動かさず、後続charge1 oracleまで見る。
4. **Writer ownership:** MID割当順=frame送信順。writerはfull-send／terminalで解放しresponse待ちに占有しない。CANCELは同じloop、target identity、新MID／creditなし。
5. **Credit exactly once:** surplus、actual residual、server grant、late reservationを各owner tokenで一回。postcommit refundなし。
6. **Correlation split:** AsyncId／STATUS_PENDING／finalSeen は sent caller release gate と別。compoundはidentityごとの仮状態をwire順に進め、全体合格後に確定。
7. **Authenticated final:** sliceごとのgeneration／correlation／auth と登録時固定の request responseProtectionPolicy の成立まで valid final／grant／pending removal を確定しない。VALIDATE_NEGOTIATE_INFO は署名または AEAD を要求する。同一MID二つ目finalはgrant前に拒否。STATUS_PENDINGはfinalではない。
8. **Bound early response:** early responseは受信時にbind済みRequestIdentityへ固定。未知MIDはdiscardしfuture replayしない。
9. **Separate outcomes:** caller／send／wireは独立sticky。cancelのみでsend owner／tombstoneを外さない。pipeline後はdeliveryも独立し、caller cancelだけでslot／byte leaseを外さない。
10. **Deadline winner:** final受理時刻と send completion／owner 回収時刻は固定期限と同じ injected monotonic clock で actor 非 suspension 区間に比較する。final acceptedAt < D と最後の owner 回収 now < D だけが期限前。acceptedAt／回収時刻 >= D は期限側で sticky とし、callback／credit await順は使わない。M2 full-send も固定 softAt と比較する。
11. **Finite wire ownership:** ordinary drainはoriginal final acceptedかつoriginal sendと選択済みCANCEL owner回収。どれか残れば固定Dを維持し、D以降の最後の owner 回収も terminal にする。期限側で terminal 化した後は timer を無効化しない。M2 soft／hardはintent時に固定し、softAt以降の full-send 完了で送信中 terminal を sent timeout に変えない。
12. **Local scope:** Tree／File refusalは該当intent／waiter／ledgerだけ。他Tree pending／credit／transportを壊さない。session terminalはgeneration全体に作用。
13. **Generation fence:** old timer／grant／send completion／early responseは旧session／credit windowだけに作用する。
14. **Cleanup phase:** markRequestSentはsend phaseのみ。draining／tombstone／drain timerは初回soft timeoutで同時に作る。retiredUnknownにpending／timerなし。
15. **Bounded lifecycle:** deadline terminalizerはreader外。close join後reader／sender loopが残らない。queue empty・frame owner noneでloop idle終了しwire final待ちで保持しない。
16. **Record reclamation:** §2.2のsend／wire／caller／credit／timer条件と identity の未選択 control item 不在を満たした後にactive indexから回収。pipeline後だけdelivery／lease receiptも加える。closed receiptはhandle側に置き、session recordを蓄積しない。

## 10. 失敗と terminal policy

| 競合／failure | 結果 |
|---|---|
| Tree quarantine と commit | actor順で勝者一方。quarantine先行はMIDなしtyped refusal。commit先行はsend/drainまたはsession terminal。 |
| grant と retire | reservation attach/refund owner token一回。receiptがcredit ack／late effectをjoin。 |
| ordinary cancel後 finalなし | 固定wireDrainDeadlineでterminal、transport close、original／CANCEL send、sender／reader／credit waiterをjoin。 |
| original final後もselected send ownerあり | drain未完。Dを維持し、D到達でfinal受理済みでもterminalize。未選択CANCELはfinal時と選択直前に確認して除ける。最後のowner回収がD以降ならcallback順によらずterminalをstickyにし、timerを無効化しない。 |
| cleanup soft/hard | 未commit soft expiryはlocal retire。committed send ambiguousはterminal。soft前に確定済みfull-sendのsoft expiryはcaller timeout＋draining tombstone、hard expiryはterminal。softAt以降のfull-send callbackで送信中terminalをsent timeoutに変えない。D−εは期限前、D／D+εはdeadline policy。 |
| final／send completion と期限 | acceptedAt < D と最後のowner回収 now < D だけが期限前。acceptedAt／回収時刻 >= D は期限側でsticky。callback／credit await順で変えない。 |
| MID後のencode/sign/encrypt/send failure | MID／range／creditを戻さずsession terminal。 |
| cancel済みfinalのbad signature／wrong correlation | valid final／grantにせずwire faultでsession terminal。 |
| 未知MIDまたは後着duplicate final | MS-SMB2 §3.2.5.1.2 に従いdiscard。grant／future replay／別identity completionなし。 |
| 同一compoundのduplicate final／後続slice failure | chainのgrant／caller／pending effect確定前に拒否しsession terminal。 |
| late timer／grant／send completion | requestUUID + generation + timer identity を再確認し一回だけeffect。caller outcomeを後着成功で上書きしない。 |
| pipeline delivery failure（Commit 5以降） | wire／caller と分けdelivery terminalを一回記録し、lease receipt後にrecord回収。 |

## 確認範囲

入力 tmp/retire/d2/design.md と tmp/retire/d3v2/review.md の N1〜N7、「実装前に固定する最小差分」を照合した。基点 master は 75efe4d56746c4c3c0d1e40f8d03eda569a36836。現行対応は SMBClient.swift／SMB2Header.swift、docs/architecture.md の session reader（issue 010 M3）、issue 010 の M3再導入・P2-2、issue 104、069 M2 d2／d3b review を前提とする。ビルド、テスト、mutation、性能測定、commit、push は行わない。
