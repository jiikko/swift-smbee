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
2. 受信の土台と compound の相関（認証前に grant を適用しないようにする。issue 104 を含む）
3. 新しい送信経路の有効化、取消、wire の drain の期限、reader の後始末（issue 010 の P2-2）
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

### 次

- Commit 2: 受信の土台と compound の相関（設計の §5 と Commit 2 節）。
  - 受け入れ条件に R1 を含める: 署名 optional の無署名 VALIDATE を、final・grant・pending removal を一切確定せずに拒否する。

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

必須 oracle: cancelled R + live X の chain、sent R + sending X、同一 MID の interim＋finalを同一 chain／別 frame の sending 中に返す、同一 chain duplicate final の grant 前拒否、plaintext signed slice ごとの署名／padding、encrypted compound、後続 malformed NextCommand、未知将来 MID discard 後に同 MID の request を送っても過去 response が結び付かない、signing optional で無署名・非暗号化 VALIDATE_NEGOTIATE_INFO を final／grant／pending removal なしで拒否する。caller／send／wire outcome、grant 回数、credit await 後 balance、pending 数を確認する。単独 response test は first-slice-only mutation を検出しない。仕様背景は issues/104-bug-compound-response-chain-not-split.md。

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
