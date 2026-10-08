# 102 (task): 全体の構成・設計レビュー（2026-10-01）の指摘と裏取り

起票日: 2026-10-01

## 概要

codex（gpt-6-luna、effort max）に、HEAD `ae4c92d` のスナップショットで全体の構成・設計をレビューさせた。
観点は 6 本（レイヤーとモジュール境界 / 並行性 / 公開 API とエラー / テストと CI / セキュリティ / transport と性能）で、
merger が 23 件を 21 件に統合した（全数採用、脱落 0）。各レビュワーには `docs/architecture.md` と `docs/api-stability.md` を先に読ませ、
文書に理由のある設計を行数だけで作り替えないよう指示した。

この issue は指摘の一覧と裏取りの結果を残すためのもの。**個々の対応は、着手するときに別 issue に切り出す**（この issue では直さない）。

## 裏取り済み（Claude が実コードで確認）

| # | 重要度 | 指摘 | 確認した事実 |
|---|---|---|---|
| 1 | P1 | SMB 3.0.x で、中間者が NEGOTIATE 応答の「署名必須」ビットを消すと、署名なしの応答を受け入れる（downgrade） | `FSCTL_VALIDATE_NEGOTIATE_INFO` の実装が無い（`grep` で 0 件）。[`done/021`](done/021-security-signed-session-accepts-unsigned-responses.md) の主題は「署名した session が署名なし応答を受け入れる」で、NEGOTIATE の段階の改ざんは別の経路（なお 021 は done/ にあるが本文の状態表記は open のまま）。SMB 3.1.1 は preauth integrity で守られる |
| 10 | P2 | profile 別の E2E が、filter の空振りや XCTSkip でも緑になる | `.github/workflows/e2e.yml` で `required_test`（`bin/ci/require-xctest-passed`）を持つのは smb302-encrypted-required だけ。smb311-signing / smb311-encrypted / guest / msdfs / smb422-reparse の 5 profile は終了コードだけを見る |
| 11 | P2 | `SMBClient.connect(..., credential:)` が平文の credential を保持し続ける | `SMBClient.swift` の overload が `credentialProvider: { credential }` で値を closure に閉じ込め、`ReconnectInfo` に残る。[`done/037`](done/037-security-session-retains-plaintext-credentials-after-authentication.md)（done/ にあるが本文の状態表記は open のまま）の対象は下位の `SMBSession` 側で、この closure は残る |
| 7 | P2 | auto-reconnect が `close()` の後に session を開き直せる | `reconnect()` は `connect()` / `treeConnect()` を await した後に `session` を差し替え、その間に `isClosed` が立ったかを見直さない |
| 8 | P3 | `STATUS_CANCELLED` が経路によって別の型で返る | 一般の経路は `SMBErrorMapper.throwIfFailure`（`CancellationError`）、SESSION_SETUP#1 だけが `SMBErrorMapper.map`（`SMBError.cancelled`）を直接呼ぶ。レビュワーが挙げた IOCTL は、許可外の status を `SMB2ReadCodecs` で `throwIfFailure` に渡しており該当しない（反証レビューで訂正） |
| 12 | P2 | ACL の `AceCount`（最大 65,535）で、中身の検証前に容量を確保する | `SMB2ReadCodecs.swift` の `decodeACL` が `aclSize` の検証の後、`entries.reserveCapacity(aceCount)` を ACE を読む前に行う。[`done/027`](done/027-robustness-ndr-count-validation-allows-inconsistent-arrays.md) は NDR 配列が対象で、この経路は含まない |
| 13 | P3 | SMB 署名の比較が constant-time でない | `verifyResponseSignature` が `expected == header.signature`（`Array ==`）。CCM の tag は `constantTimeEqual`。遠隔からの測定可能性は未確認 |
| 16 | P2 | POSIX の部分受信のたびに、残りの全量を確保してゼロ初期化する | `POSIXSocketTransport.receiveBlocking(maxLength:)` が毎回、`maxLength` 個のゼロで初期化した配列を作る。小さい部分読みが続くと確保と初期化が残量に比例して繰り返される（効果の大きさは未実測） |

## 未検証（レビュワーの静的な主張のまま。着手前に裏を取る）

| # | 重要度 | 指摘 | 既存 issue |
|---|---|---|---|
| 2 | P2 | `docs/api-stability.md` が「actor が呼び出し全体を直列化する」と読める（actor は await をまたいで排他しない） | — |
| 3 | P2 | handle の cleanup 失敗が共有 session の全操作を終わらせる | [069](069-bug-cleanup-failure-kills-shared-session.md)（対応中） |
| 4 | P2 | 公開の入口（`SMBee` と `SMBClient`）と安定性契約が揃っていない（custom transport は `SMBClient.connect` からしか渡せない） | — |
| 5 | P2 | credit waiter が永久に待つ順序がある（CreditCharge 未満の grant を返すサーバの存在は未確認） | [010](010-bug-linux-unit-suite-hang-multiflight-demux.md) |
| 6 | P2 | 送信後に cancel した request の tombstone に終端の期限が無い | [010](010-bug-linux-unit-suite-hang-multiflight-demux.md) |
| 9 | P2 | `withTree` が TREE_DISCONNECT の失敗（transport を閉じる）を結果に反映しない | 069 で後回しにした TREE_DISCONNECT の経路と関係（069 本文の「M2」） |
| 14 | P2 | READ streaming が 1 request ずつ応答を待つ（RTT のある経路で帯域を使い切れない。未実測） | — |
| 15 | P2 | WRITE も 1 chunk ずつ応答を待つ（未実測） | [done/015](done/015-perf-upload-write-chunk-and-pipeline.md)（本文の 64 KiB の上限の記述が今の実装と食い違う、とレビュワー） |
| 17 | P3 | 並行に呼んだ 2 回目の `close()` が、1 回目の後始末の完了を待たない | — |
| 18 | P3 | 転送 API の間で、全体の deadline の指定方法が揃っていない | — |
| 19 | P3 | `SMBEE_TRACE_WIRE_FULL=1` で、暗号化 session でも平文のファイル内容が stderr に出る | — |
| 20 | P3 | NWConnection の segment 送信が frame 全体を連結する | — |
| 21 | P3 | NWConnection 経路の TCP_NODELAY が未設定・実効値が未確認 | — |

## 「変えない方がよい」とされた点（再提起を防ぐために残す）

- `SMBClient.swift`（6,448 行）の大規模なファイル分割は勧めない。8 つの機能群に分けられるが、`SMBSession` の command 処理と wire 処理は session ID・鍵・credit・
  pending response を共有するので、ファイル移動では依存も状態の共有も減らない。責務を本当に減らすには wire lifecycle の所有者を別の collaborator にする必要があり、
  それは 010 / 069 に関係する中規模以上の変更になる（観点 1）
- `SMBSession` が具体的な transport でなく `SMBTransport` に依存していること、Direct-TCP framing を transport の外に置いていること、codec と crypto が専用ファイルに分かれていること

## 出典

レビューの原文と digest は `tmp/arch/out/`（ローカルの一時領域。消える前提で、結論はこの issue に移した）。

## 付随して見つかったこと

- `done/021`・`done/037`・`done/027` は done/ に置かれているが、本文冒頭の状態表記が open のまま（位置と表記が食い違う）

## 次の一手

裏取り済みのうち、着手する価値が高いのは #1（security、P1）と #10（CI の素通り）。どれを別 issue に切り出すかはユーザーの判断。

## 進捗

- **#1（対応済み、2026-10-02）**: SMB 3.0 / 3.0.2 で、匿名でない session は TREE_CONNECT が成功するたびに `FSCTL_VALIDATE_NEGOTIATE_INFO` を送り、
  NEGOTIATE の 4 値を照合する。応答は暗号化か署名を必須（`signingRequired` を見ない）。失敗・非対応はすべて接続の失敗（fail-closed。ユーザーの判断）。
  匿名の資格情報は検証を省く（SMBee のポリシーの例外）。資格情報を渡したのに guest / null にされた 3.0.x 接続は失敗。
  commit `security(negotiate): SMB 3.0.x で TREE_CONNECT ごとに FSCTL_VALIDATE_NEGOTIATE_INFO を送り、NEGOTIATE の downgrade を検出する (issue 102 #1)`。
  手順と方針の正本は `docs/smb-protocol.md`。実機（macOS SMBX・Windows・NAS）での確認は未実施（Tier 3）。非対応の機器には 3.0.x で接続できなくなる可能性がある
- 設計レビューの途中で見つけた既存バグも直した: 共有の暗号化必須の判定が Capabilities の `0x8`（`SMB2_SHARE_CAP_DFS`）も見ていた。
  commit `fix(tree): 共有の暗号化必須の判定から Capabilities 0x8 (SMB2_SHARE_CAP_DFS) を外す`
- **#10（対応済み、2026-10-01）**: `e2e.yml` の 6 profile と `samba-compat.yml` の 7 profile すべてで、その profile のための test が 1 回 pass したことを必須にした。
  commit `ci: profile 別の E2E は、その profile のための test が 1 回 pass したことを必須にする (issue 102 #10)`。e2e.yml は CI のログで 6 profile 分の `passed once` を確認。
  samba-compat.yml は週次の定期 run で確認する（手動起動は費用のため見送り）
- #7 #8 #11 #12 #13 は「裏取り済みの対応」節、#2 #4 #17 #18 #19 #20 #21 は「残り 7 件の対応」節
- #5 #6 は issue 010 M3 の入れ直し（2026-10-03、`feat(session): issue 010 M3 を入れ直す — session の reader を需要駆動・actor 隔離にして Linux の退行を詰める`）で対応済み。CI の Test / E2E / Performance は success
- 残り: #9（069 M2）、#14 #15 #16（READ/WRITE パイプライン化）

## 未検証 13 件の裏取り（2026-10-02、codex luna 5 本 + merger。#3 は 069 そのものなので除外）

12 件すべて本物と判定（偽物 0）。判定根拠の原文は tmp/t3/out/（一時領域）。要点:

| # | 判定 | 重要度 | 要点 / 扱い |
|---|---|---|---|
| 5 | 本物 | P2 | READ 長と CreditCharge を残高のスナップショットで固定して packet を作るので、2 本の並行 READ が同じ残高を当てにし、片方が 1 credit しか grant されないと他方は永久に待つ。未送信の request には request timeout が効かない。サーバがその grant を返すかは未確認。issue 010（常駐の受信ループ）で扱う |
| 6 | 本物 | P2 | 送信後に cancel した request の tombstone には、069 の cleanup tombstone のような drain 上限も件数上限も無い。サーバが final を返さないと残り続ける。010 で扱う |
| 9 | 本物 | P2 | `withTree` は本体の結果の後に `child.close()` → `bestEffortTreeDisconnect` が失敗を飲み込み transport を閉じる。本体は成功として返り、次の操作で失敗する。069 M2 で扱う |
| 14 | 本物 | P2 | `streamRead` は `readChunk` と `onChunk` を await してから次の READ を送る（1 flight）。遅延つきの性能は未実測。READ/WRITE パイプライン化で扱う |
| 15 | 本物 | P2 | WRITE も各 chunk の応答を待つ。done/015 の「64 KiB 上限」の記述は今の実装（1 MiB）と食い違う。パイプライン化で扱う |
| 2 | 本物 | P3 | `docs/api-stability.md` の「Calls are serialized through actor isolation」は呼び出し全体の排他と読めるが、実装は await をまたいで別の呼び出しが進む。文書の修正 |
| 4 | 本物 | P3 | 安定性契約は `SMBClient` を列挙しないが、custom transport を使う一部の経路は `SMBClient` の API を使う（`read` / `withReadStream` / `download` には `makeTransport` がある — custom transport は connect だけ、という元の主張は一部反証） |
| 17 | 本物 | P3 | 2 回目の `close()` は `isClosed` を見て即 return し、1 回目の後始末の完了を待たない。公開契約上の要件かは未確認 |
| 18 | 本物 | P3 | `withReadStream` と単一ファイルの `download` に全体の deadline（`operationTimeout`）が無い |
| 19 | 本物 | P3 | `SMBEE_DEBUG=1` + `SMBEE_TRACE_WIRE=1` + `SMBEE_TRACE_WIRE_FULL=1` で、暗号化 session でも平文のファイル内容が stderr に出る（3 つとも明示的に有効にしたときだけ） |
| 20 | 本物 | P3 | NWConnection の transport は segment 版の send を持たず、protocol の既定実装が frame 全体を連結する（性能への影響は未実測） |
| 21 | 本物 | P3 | NWConnection の経路で TCP_NODELAY を明示していない（実効値・遅延差は未実測） |

## 裏取り済みの対応（2026-10-02、codex-drive の軽量パス）

| # | 結果 | commit |
|---|---|---|
| 7 | 対応済み。再接続を 1 本の共有処理にまとめ、close で全 waiter を解放して候補 session を閉じる。watch は毎周回・通知のたびに close を確かめる。cancel は伝え、CancellationError は吸収しない | `fix(client): close と並行する再接続が session を開き直さない …` と追補 `fix(client): close が共有の再接続の待ちを解放し …` |
| 8 | 対応済み。SESSION_SETUP#1 も throwIfFailure を通し、STATUS_CANCELLED は CancellationError | `fix(session): SESSION_SETUP#1 の失敗 status も throwIfFailure に通し …` |
| 11 | ユーザーの判断で挙動は変えず、`credential:` 版が再接続のために資格情報を保持することを docs/api-stability.md に明記 | `docs(api): credential: で接続した session は …` |
| 12 | 対応済み。reserveCapacity を min(aceCount, (aclSize - 8) / 4) で抑える | `fix(acl): ACE の件数で過大に確保しない …` |
| 13 | 対応済み。署名の比較を constant-time に | `fix(signing): SMB 署名の比較を constant-time にする` |
| 16 | issue 010 M3（常駐の受信ループ）で受信経路を作り直すので、READ/WRITE パイプライン化と一緒に計測つきで扱う（未着手） | — |

不採用（記録）: 匿名 session でサーバが署名必須を示しても、匿名には署名鍵が無いので署名なしの応答を受け入れる（MS-SMB2 の匿名 session の扱い。
VALIDATE_NEGOTIATE_INFO の匿名の例外と同じ方針）。#7 の設計・実装は sol の敵対レビューを計 3 周（設計 1・実装 2）通し、最後の周は指摘 0 件。

## 残り 7 件の対応（2026-10-02、codex-drive。設計 D1 → sol の敵対レビュー D3 → 4 worktree で実装 → 各件に sol の敵対レビュー）

ユーザーの判断: #19 は暗号化 session の平文を full trace でも伏せる / #4 は既に public な SMBClient の高レベル API を契約に載せる（コード不変）。

| # | 結果 | 主な commit（subject の先頭） |
|---|---|---|
| 2 | 対応済み。「actor が呼び出しを直列化する」を、actor が守るのは isolated state で await の間に別の呼び出しが進む・複数 request の操作は原子的でない、に直した | `docs(api): actor は await をまたいで別の呼び出しを進めると直し …` |
| 4 | 対応済み。SMBClient の公開の高レベル API を 0.x の互換の範囲に明記し、makeTransport で注入できる入口を表にした。約束する入口の named call を compile-only のテストに置いた | 同上 |
| 17 | 対応済み。最初の close が共有の close task を持ち、後の close はその完了を待つ。reconnect の waiter 解放・candidate の所有権移転・cancel は最初の await より前。withTree の TREE_CONNECT 待ちは close 所有の期限 (5 秒) で有限にする | `fix(client): 2 回目以降の close が最初の後始末の完了を待つ` と `test(client): 並行 close の join …` |
| 18 | 対応済み。withReadStream と単一ファイルの download（SMBClientSession / SMBClient / SMBee）に operationTimeout。session API は nonisolated の外側で actor に入る前から期限を測る。一時ファイルは O_EXCL で作り、mode は umask に従う | `feat(transfer): withReadStream と単一ファイルの download に全体の deadline …` ほか 3 本 |
| 19 | 対応済み。暗号化鍵のある session の平文の dump は full trace でもラベルと長さだけ。判定は encryptionKey != nil。不正な protocol id のエラー文言から受信バイトの hex も外した（復号した平文が perf log / smbcli に漏れていた） | `security(debug): 暗号化 session の平文を …` と `security(debug): 不正な SMB2 protocol id のエラー文言から …` |
| 20 | 対応済み。frame を連結せず segment ごとの Data を 1 つの batch で enqueue し、frame の直列化は FIFO の gate。close → connect をまたいで旧 frame が新接続へ流れないよう接続の同一性を確かめる。本物の NWListener の loopback で、frame ごとに別の ContentContext だと後続 frame が止まることを確認し、共有の .defaultMessage にした（D3 の推奨は実機で誤りだった）。性能は未実測 | `perf(transport): NWConnectionTransport を segment のまま送り …` ほか 2 本 |
| 21 | 対応済み。connect が使う NWParameters に noDelay = true。実効値の読み戻しは API に無いので、渡した parameters を検査する | `perf(transport): NWConnectionTransport を segment のまま送り …` |

敵対レビューで採らなかった指摘（記録）:
- #18 R2: requestTimeout が nil の session で CLOSE の応答が来ないと FileId と transport が残る（既存）。069 M2 で cleanup の drain を TreeId と共通化するときに、requestTimeout と独立した有限の grace を入れる
- #18 R7: 旧シグネチャを function value として参照するとコンパイルできなくなる。docs/api-stability.md が保証しないと明記済み
- #17: setup の期限切れで共有 transport を閉じると進行中の他の操作も巻き込む。親の close が始まった後に限られ、close は既存操作の完了を保証しない契約なので不具合としない
- RTT 計測の P2-5（測定中に外部プロセスが tc を変えて戻す）: 脅威モデルの外として script のヘッダと docs に記録

## 進捗チェックポイント — #14 #15 #16 READ / WRITE の pipelining（2026-10-07 着手、codex-drive）

before の実測は `docs/performance-resource-baseline.md` の「2026-10-02: 追加 RTT ごとの Samba 転送 baseline（パイプライン化前）」
（RTT 20 ms の 64 MiB read 45.0 MiB/s = 1 MiB / 1 往復の上限）。

承認済みの設計（2026-10-07、ユーザー承認。D1 の独立 4 案 → D1.5 のクロス批評 → D2 の詳細設計 → D3 の発見型 + 敵対レビューを統合）:
- 転送ごとに最大 4 request を同時に outstanding にする（1 request は既存の上限 1 MiB 以下なので合計 4 MiB 以下）。session 合計の上限は置かない
  （`onChunk` / supplier が同じ session の別操作を待つと循環待ちになるため）。上限は内部定数で、公開 API は変えない。
- 状態は `SMBSession` actor 上の同期の状態機械（window）に置き、ループ（driver）は呼び出し側の Task で回す。`onChunk` / `onProgress` / supplier は actor の外で呼ぶ
  （actor の中でユーザーの callback を待つと reader・timer・close が止まる）。新しい actor・request ごとの Task は作らず、既存の sendTask と需要駆動の reader を使う。
- 失敗・cancel・期限切れの後は新しい request を commit（MID の採番と pending の登録）しない。commit 済みの request は送って final まで drain する
  （SMB CANCEL や tombstone を増やさない。commit 済み・未送信の request を捨てる経路は issue 106 の退役 primitive で、保留中なので使わない）。
- drain の期限は min(stop 時刻 + cleanupTimeout, 各 request の期限, operation の絶対期限)。回収できなければ既存の closeTransportAndWait。drain と close は呼び出し側が行い、reader に join させない。
- credit: 自分の committed slot があるときは待たない予約を試し、取れなければ自分の slot の完了を待つ。credit を待機するのは自分の slot が 0 件のときだけ。credit の FIFO の規則は変えない。
- WRITE は supplier を呼んでから credit を予約する（逆順は supplier が同じ session を使うと deadlock）。
- 返すエラー: caller の cancel・operation の期限 > session を落とす失敗 > offset が最小の失敗（直列版なら最初に出したはずのエラー）。short READ は手前まで配送し、送信済みを drain してから続きの offset で再開する。
- 失敗時は、失敗した offset より後ろも書かれていることがある。進捗は READ は配送済み、`upload(data:)` は成功応答の連続 prefix、supplier は供給済み。`docs/api-stability.md` に書く。
- #16: `receiveBlocking` は受信した分だけ初期化する（全域のゼロ埋めと prefix のコピーを除く）。
- 採らなかったもの: session 合計の上限 / 汎用の送信 permit / credit の availability receipt / admission handle / ack debt / byte 枠の独立管理（D3 で過剰と判断）。

マイルストーン:

| M | 内容 | 状態 |
|---|---|---|
| M1 | 共通の下地（window の状態機械、pending の completion の宛先、待たない予約、operation の絶対期限）。転送はまだ直列 | **完了**（2026-10-07、commit `feat(session): issue 102 #14 #15 の pipelining M1 — …`。未 push。レビュー: 発見型 12 件・敵対の反例 2 件を対応） |
| M2 | READ の pipelining | **完了**（2026-10-08、commit `feat(read): issue 102 #14 の pipelining M2 — …`。下の M2 の節） |
| M3 | WRITE の pipelining | 未着手 |
| M4 | POSIX の受信バッファ（#16）と総合検証（CI の性能 gate・RTT study の after） | 未着手 |

未確認のリスク: CI の Linux x86 の synthetic benchmark（`initialCredits=1` で実質 1 flight）での user CPU。手元の macOS / arm64 container で master と交互に測ってから push し、
gate が落ちたら上書きせず相談する。

再開するとき: 設計の正本は `tmp/cdpipe/d2-design.md` と `tmp/codex-drive-design.pipelining.md`（一時領域。消えていたら上の要点から再構成する）。

### M2（READ の pipelining）の記録（2026-10-08）

- 性能（macOS release の synthetic READ、initialCredits=1 で 1 本ずつ、M1 と AB/BA 6 組の中央値）: 最初の実装は throughput −28.7% / user CPU +40.2%。
  - `sample` の profile と codex の分析で、actor の出入りの回数は M1 と同じで、増えた thread の起床は XCTWaiter の待ちだと分かった（hop の数が原因という最初の仮説は外れ）。
  - slot の状態の分割・時刻の取得の削減・payload の decode を credit grant の後へ移す、で −8.7% / +11.2% まで縮めた（credit 待ちと retirement 待ちの分離は悪化したので戻した）。
  - 目標の ±5% には届いていない。残りは slot の管理の費用と見ている（内訳は数値で分けられていない）。CI の Linux x86 の gate は push で確かめる。
- レビュー: 発見型 3 観点で 12 件、敵対 2 周で 4 件。再現テストを先に red にしてから直した。
- 未確認のリスク（直していない、または実行で再現できていないもの）:
  - 送信失敗の後、refund された credit で新しい READ が commit される（敵対の反例 #2）: 実行では再現しなかった。設計の契約（送信失敗の後は session を terminal に・到達しうる request の credit を live な session に返さない）に合わせ、close を refund の前に移した。close と refund の順序を独立に観測する gate は無い。
  - refund の前の時刻で drain を記録する（敵対の反例 #4）: 状態機械のテストで固定して直した。session の refund の再入まで含めた統合の再現は、refund の await を止める gate が無いので書いていない。
  - final 時の軽い parser（`SMB2Read.responsePayloadLength`）と `decodeResponse` の食い違い: packet 長・data offset・data 長の組み合わせを網羅して食い違いは無かった。食い違ったときに retirement の失敗として配送しないことはテストで固定した。

