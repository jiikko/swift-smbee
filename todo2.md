# todo2: Linux/macOS smbclient coverage backlog

この文書は、SMBee を **Linux / macOS で使う smbclient 相当の SMB2/3 クライアント**として育てるための未実装・未検証 backlog である。

`todo.md` は実装進捗の時系列ログになっているため、本書では「Linux/macOS smbclient として何をカバーすべきか」「いま本当に未実装なのか」「完了条件は何か」に絞る。

## 監査時点

- 監査日: 2026-07-02
- 監査対象 branch: `master`
- 正本仕様:
  - MS-SMB2: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962>
  - MS-FSCC: FileInformation / FileSystemInformation / FSCTL / reparse point / security descriptor 周辺
  - MS-NLMP: NTLM / NTLMv2
  - MS-SPNG: SPNEGO
  - MS-DFSC: DFS referral
  - MS-SRVS / MS-RPCE / MS-DTYP / MS-ERREF: share enum、DCE/RPC、SID/FILETIME、NTSTATUS
- 実装確認に使った主なファイル:
  - `README.md`
  - `docs/smb-protocol.md`
  - `docs/testing.md`
  - `todo.md`
  - `Sources/SMBee/SMBee.swift`
  - `Sources/SMBee/SMBClient.swift`
  - `Sources/SMBee/SMBNegotiate.swift`
  - `Sources/SMBee/SMB2Header.swift`
  - `Sources/SMBee/SMB2ReadCodecs.swift`
  - `Sources/SMBee/SMB2DfsReferral.swift`
  - `Sources/SMBee/NTLM.swift`
  - `Sources/smbcli/SMBCLI.swift`
  - `Tests/SMBeeTests/SMBeeE2ETests.swift`
  - `.github/workflows/test.yml`
  - `.github/workflows/e2e.yml`
  - `.github/workflows/samba-compat.yml`
  - `issues/005-auth-macos-finder-equivalent-smb-auth.md`
  - `issues/008-acl-followups-sid-name-resolution-set-security.md`
  - `issues/009-dfs-referral-real-server-e2e.md`

## 状態ラベル

- `implemented`: 実装があり、unit または E2E の証拠がある。
- `implemented-but-underverified`: 実装はあるが、実サーバ・CI・互換 matrix の裏取りが足りない。
- `partial`: 一部 API / codec はあるが、smbclient として期待される挙動には足りない。
- `missing`: 実装が見つからない。コード検索でも対応する codec / public API / CLI が確認できない。
- `explicitly-out-of-scope`: 現時点ではやらない。README/docs にも明示する。

## 既にカバーしている範囲

ここは再実装しない。追加作業がある場合も「互換確認」「API安定化」「CI昇格」として扱う。

| 領域 | 状態 | 実装根拠 |
|---|---|---|
| direct TCP 445 transport | implemented | `docs/smb-protocol.md` は direct TCP 445 + 4 byte length framing を MVP として定義。`SMBClient` は default factory で `POSIXSocketTransport` を使う。 |
| SMB 3.0 / 3.0.2 / 3.1.1 authenticated dialect | implemented | `SMBNegotiateCodec.authenticatedDialects = [0x0300, 0x0302, 0x0311]`。 |
| SMB 2.0.2 / 2.1 probe | implemented | `SMBNegotiateCodec.probeDialects` には 0x0202 / 0x0210 も含まれる。authenticated path は SMB 3.x only とし、2.1 以下は診断付き `protocolError`。 |
| NTLMv2 password auth | implemented | `NTLM.makeType1` / `NTLM.makeType3`。MIC、KEY_EXCH、NT hash 派生あり。 |
| NT hash credential | implemented | `SMBCredential(username:ntHash:domain:)`、CLI `--nt-hash` / `SMB_NT_HASH`。 |
| anonymous / guest auth | implemented | `SMBCredential.anonymous`、CLI `--anonymous` / `--guest`。Samba guest E2E 記録あり。 |
| SPNEGO NTLM wrapping | implemented | NTLM OID 前提。Kerberos mech は未実装。 |
| SMB 3.0.2 signing/encryption | implemented | AES-CMAC / AES-128-CCM。Samba encrypted-required E2E + macOS SMBX smoke 記録あり。 |
| SMB 3.1.1 signing/encryption | implemented-but-underverified | AES-GMAC / AES-128-GCM 実装あり。`samba-compat.yml` では 3.1.1 signing/encrypted profile を full E2E、PR/push の `e2e.yml` では 3.1.1 signing-only / encrypted の authenticated fast smoke を回す。Windows/NAS 実サーバ smoke は未実施。 |
| NEGOTIATE / SESSION_SETUP / TREE_CONNECT / CREATE / CLOSE / FLUSH / READ / WRITE / QUERY_DIRECTORY / QUERY_INFO / SET_INFO / IOCTL / CHANGE_NOTIFY / TREE_DISCONNECT / LOGOFF | implemented | `SMB2Commands` と codec / session / facade に実装あり。 |
| ls / stat / cat / range read / streaming read | implemented | `SMBee.list` / `stat` / `read` / `withReadStream`、`smbcli ls/stat/cat`。 |
| put / get / mkdir / mv / rm / cp | implemented | `SMBee.upload` / `download` / `makeDirectory` / `rename` / `delete` / `copy`、CLI サブコマンド。 |
| recursive get / put / cp / rm | implemented | `downloadDirectory` / `uploadDirectory` / `copyDirectory` / recursive delete。`continueOnError` / `skipExisting` / `dryRun` / size-based resume あり。 |
| share discovery | implemented | `IPC$` + SRVSVC `NetrShareEnum`。`SMBee.listShares` / `smbcli shares`。 |
| volume / filesystem info | implemented | `SMBee.volumeInfo` / `smbcli df`。FileFsFullSizeInformation / FileFsAttributeInformation / FileFsVolumeInformation。 |
| metadata read/write | implemented | file attributes、creation/access/modified/change time、`SMBFileMetadataUpdate`、`updateMetadata`。 |
| security descriptor read / DACL write | partial | `securityInfo` / `setSecurityInfo` / `smbcli acl` / `smbcli setacl`。DACL は read-modify-write あり。ただし owner/group/SACL 書き換えと SID 名解決は未実装。 |
| change notification | implemented-but-underverified | `withChangeNotifications` / `smbcli watch`。Samba E2E はある。再接続時の再購読と JSON 出力は未実装。 |
| DFS referral metadata | implemented-but-underverified | `SMBee.dfsReferral` / `smbcli dfs`。unit fixture + 仕様精読あり。実 msdfs サーバ E2E は未実施。 |
| reparse tag metadata | partial | `SMBFileStat.reparseTag` / `reparseKind`。target 解決は未実装。 |

## P0: Linux/macOS smbclient と名乗る前の release blocker

### P0-1. 互換 matrix を実サーバで埋める

状態: `partial` / `implemented-but-underverified`

現状:

- Samba は CI / compat workflow でかなり確認済み。
- macOS SMBX は 3.0.2 の基本 smoke 記録あり。
- Windows SMB Server / Windows Pro / NAS は未実測。
- `docs/testing.md` でも「Samba green は macOS SMBX / Windows SMB Server の保証ではない」として Tier 3 smoke を要求している。
- 2026-07-02: `docs/compatibility-matrix.md` と `bin/e2e/smoke-real-server.sh` を追加。実サーバ smoke の記録先と共通手順はできた。残は Windows / NAS / macOS SMBX の再実行結果を埋めること。

やること:

- `docs/compatibility-matrix.md` を作る。
- `bin/e2e/smoke-real-server.sh` を作る。最低限のコマンドを同じ順番で実行できるようにする。
- 対象を分ける:
  - Linux client -> Samba
  - Linux client -> Windows SMB Server
  - Linux client -> Synology/QNAP/古いSamba系NAS
  - macOS client -> macOS SMBX
  - macOS client -> Samba
  - macOS client -> Windows SMB Server
- 各対象で次を記録する:
  - OS / Samba / Windows / NAS firmware version
  - negotiated dialect
  - signing required / signing algorithm
  - encryption required / cipher
  - auth method: password / NT hash / anonymous / Kerberos if implemented
  - path encoding / Unicode normalization behavior
  - file / directory / ACL / metadata / recursive transfer / share discovery の可否

完了条件:

- `smbcli probe/shares/ls/stat/cat/get/put/mkdir/mv/cp/rm/df/acl/watch` の representative smoke が、少なくとも Samba / macOS SMBX / Windows SMB Server で通る。
- Windows / NAS で失敗する項目は `known-issues` として matrix に残す。

### P0-2. SMB 3.1.1 authenticated full E2E を PR/push gate に昇格する

状態: `implemented`

現状:

- `todo.md` 上は SMB 3.1.1 GMAC signing-only / GCM encrypted session が実 Samba E2E green と記録されている。
- `.github/workflows/samba-compat.yml` は `smb311-signing-required` と `smb311-encrypted-required` を full `SMBeeE2ETests` で回す。
- 2026-07-02: `.github/workflows/e2e.yml` の PR/push matrix に `smb311-signing-required` / `smb311-encrypted-required` の authenticated fast smoke (`SMBeeE2ETests.testAuthenticatedFastSmoke`) を追加。push run `28559961166` で E2E success。

やること:

- PR/push の fast E2E に、3.1.1 signing-only と encrypted の authenticated smoke を足す。
- すべての full E2E が重い場合は、3.1.1 fast subset を作る:
  - connect
  - tree connect
  - list
  - read known file
  - write small file
  - delete
- コメントを最新状態に同期する。

完了条件:

- PR/push で 3.0.2 encrypted-required と 3.1.1 signing/encrypted authenticated path が最低1本ずつ通る。
- `e2e.yml` に古い「3.1.1 full は未完」コメントが残らない。

### P0-3. coverage matrix を仕様ID単位で固定する

状態: `implemented`

現状:

- `docs/smb-protocol.md` は仕様の地図。
- `todo.md` は時系列の進捗台帳。
- ただし、MS-SMB2 / MS-FSCC / MS-NLMP のどの節をどこまで実装したかを一覧できる doc がない。
- 2026-07-02: `docs/coverage.md` を追加し、README からリンク。feature / spec / implementation / unit / Samba E2E / macOS smoke / Windows-NAS / status / limitation を一覧化。

やること:

- `docs/coverage.md` を作る。
- 行単位で管理する:
  - feature
  - spec ID
  - spec section
  - implementation file/function
  - unit test
  - Samba E2E
  - macOS smoke
  - Windows smoke
  - status
  - known limitations

完了条件:

- 「SMBee は SMB 全体対応ではなく、どこまで対応か」を README から辿れる。
- 未実装の仕様が `todo.md` の時系列ログに埋もれない。

## P1: smbclient として実装すべき中核未実装

### P1-1. Kerberos / GSS / SPNEGO(Kerberos mech)

状態: `missing`

実装確認:

- `NTLM.swift` は password / NT hash / anonymous の NTLM path を持つ。
- `issues/005-auth-macos-finder-equivalent-smb-auth.md` に、SPNEGO は NTLM OID だけを広告し、Kerberos mech は未実装と記録されている。
- `SMBAuthenticator` のような抽象化も未実装。

Linux/macOS smbclient として必要な理由:

- Active Directory / enterprise NAS / macOS Finder 相当認証では Kerberos / GSS が必要になる場面がある。
- Linux の `smbclient` 相当を名乗るなら、少なくとも Kerberos 非対応を明示する必要がある。

やること:

- `SMBAuthenticator` protocol を設計する。
- NTLM backend を既存実装から切り出す。
- GSS backend を別実装にする:
  - macOS: GSS.framework / Security.framework
  - Linux: GSSAPI / krb5。SwiftPM optional feature または別 target にする。
- SPNEGO mech list を NTLM only から NTLM / Kerberos 切替へ拡張する。
- GSS token exchange 後に SMB signing/encryption 用 session key material を得られるか検証する。
- AD / Samba AD / macOS SMBX で実測する。

完了条件:

- `smbcli --kerberos` または同等の auth mode で `SESSION_SETUP` が通る。
- Kerberos session でも signing/encryption が動く。
- 失敗時は NTLM fallback するか、明示エラーにするかを documented policy にする。

### P1-2. SMB 2.1 authenticated fallback の方針決定

状態: `implemented` policy / `implemented` diagnostic / `implemented` for probe only

実装確認:

- `SMBNegotiateCodec.probeDialects` は 0x0202 / 0x0210 / 0x0300 / 0x0302 / 0x0311。
- `SMBNegotiateCodec.authenticatedDialects` は 0x0300 / 0x0302 / 0x0311 のみ。
- `docs/smb-protocol.md` の MVP は SMB 3.x サーバ。
- 2026-07-02: 方針確定。SMBee authenticated operations は SMB 3.x only を維持する。SMB 2.0.2 / 2.1 は probe-only。authenticated NEGOTIATE response が 2.1 以下なら `SMBError.protocolError(SMBNegotiateCodec.authenticatedUnsupportedMessage)` で SESSION_SETUP 前に停止する unit を追加。

Linux/macOS smbclient として必要な理由:

- 古いNASや古いWindows/Sambaでは SMB 2.1 までの構成が残る。
- ただし SMB 2.1 は encryption がなく、security policy を下げることになる。

やったこと:

- README / `docs/smb-protocol.md` / `docs/coverage.md` に SMB 3.x only と SMB 2.1 probe-only を明記。
- `SMBNegotiateCodec.supportsAuthenticatedConnection(dialect:)` と診断文字列を追加。
- SMB 2.1 response で SESSION_SETUP に進まない unit を追加。

完了条件:

- [x] README / coverage matrix に「SMB 2.1 は非対応」または「opt-in 対応」と明記される。
- [x] 非対応なら、2.1 only server へ接続した時に診断しやすい error を返す。

### P1-3. SMB2 credit accounting / multi-credit IO

状態: `partial`

実装確認:

- `SMB2Header` は `creditCharge` / `credits` field を持つが、default は `creditCharge = 0`, `credits = 1`。
- `todo.md` にも CreditCharge / CreditRequest / CreditResponse を管理していないと記録されている。
- read/write は negotiated MaxRead/MaxWriteSize と transform overhead で chunk を抑えているが、credit window を allocator として扱っていない。
- 2026-07-02: 最小 credit accounting を追加。READ/WRITE request は payload length から `CreditCharge` を計算し、`CreditRequest` も同値に設定する。`SMBSession` は送信時に charge を消費し、response header の `credits` grant を balance に加算して debug trace できる。
- 2026-07-02: read/write chunk planner を current credit balance で cap する helper を追加。直列 I/O の範囲では credit window を超える chunk を選ばない。
- credit-window blocking / multi-flight allocator は未実装。

Linux/macOS smbclient として必要な理由:

- 大きな read/write、暗号化 session、WAN / NAS / Windows Server でのスループットと互換性に影響する。
- multi-credit server では CreditCharge が不正だと server が拒否する可能性がある。

やること:

- credit-window が足りない時に待つ allocator を実装する。
- multi-flight 化する場合は messageId/async response demux と合わせて設計する。
- copychunk と encryption overhead を含む chunk planner の E2E 検証を広げる。
- unit: allocator。
- E2E: large file read/write を 1MiB 超、4GiB 境界、encrypted session で実行。

完了条件:

- large transfer で credit不足・不正CreditChargeが出ない。
- throughput regression test が command count / byte count / chunk count で監視される。

### P1-4. durable handle / persistent handle / reconnect policy

状態: `missing`

実装確認:

- `CREATE` request は create contexts を送っていない。
- `durable` / `persistent` / `lease` / `oplock` の実装ファイル・public API は確認できない。
- 現在の自動再接続は one-shot idempotent operation の再試行に限定される。

Linux/macOS smbclient として必要な理由:

- 大ファイル転送中の一時切断、Wi-Fi sleep/resume、NAS再起動、VPN切断で差が出る。
- durable handle がないと、途中再開はアプリ側でやり直すしかない。

やること:

- SMB2 CREATE durable handle request / reconnect context を調査・実装する。
- durable v1/v2 / persistent handle のうち、Linux/macOS clientとして必要な最小範囲を決める。
- reconnect 時に session/tree/file handle をどう復元するかを `SMBClientSession` より下の層で設計する。
- 現時点では「durable handle unsupported」と明示し、該当 recoverability を過大に宣伝しない。

完了条件:

- durable handle 非対応のままなら、docs/coverage.md と README の limitations に載る。
- 対応するなら、transfer中の接続断 simulation で再開できる。

### P1-5. lease / oplock break handling

状態: `missing`

実装確認:

- `CREATE` request に oplock level / lease create context がない。
- oplock break / lease break notification decoder がない。

Linux/macOS smbclient として必要な理由:

- 複数クライアントが同じファイルを扱う環境では、cache coherence と server通知を無視できない。
- ファイルブラウザ用途では aggressive caching しなければ回避できるが、明示的に「lease/oplock未対応」とする必要がある。

やること:

- まず方針を決める:
  - cacheしないので lease/oplock を要求しない。
  - それでも server から break が来る可能性を扱う。
- 対応する場合:
  - oplock break / lease break async response を受ける。
  - callback API か内部 ack を実装する。

完了条件:

- 未対応方針なら、CREATE で lease/oplock を要求しないことを coverage に記録。
- 対応方針なら、break notification の fixture と Samba/Windows smoke を持つ。

### P1-6. SMB2 LOCK / byte-range locking

状態: `missing`

実装確認:

- `SMB2Commands` に `lock` command 定数がない。
- `SMB2Lock` codec / public API / CLI は確認できない。

Linux/macOS smbclient として必要な理由:

- アプリケーションが同一ファイルを協調更新する場合に必要。
- 汎用 smbclient のファイル操作互換性として、最低限 explicit lock/unlock または unsupported policy が必要。

やること:

- SMB2 LOCK request/response codec を実装する。
- API: `lock(path:range:shared/exclusive:)` / `unlock(...)` を検討。
- CLI に入れるかは後回し。ライブラリ API 先行でよい。

完了条件:

- LOCK / UNLOCK の unit fixture。
- Samba + Windows で conflict / unlock / close-on-disconnect の挙動を確認。

### P1-7. multi-share / multi-tree session reuse

状態: `missing`

実装確認:

- `SMBClientSession` は 1 `treeId` を保持する 1 share 前提。
- `listShares` / `dfsReferral` は `IPC$` に別途 one-shot 接続する。
- `todo.md` にも multi-share / multi-tree session reuse が未実装として残っている。

Linux/macOS smbclient として必要な理由:

- `IPC$` で share discovery / DFS / LSA をしつつ、同じ authenticated session で通常 share も扱いたい。
- DFS auto-follow や SID lookup をやるなら必要になる。

やること:

- `SMBServerSession` と `SMBTreeSession` に分ける。
- 1 authenticated session から複数 TREE_CONNECT できる API にする。
- graceful teardown を tree単位 / session単位に分ける。

完了条件:

- 同じ session 上で `IPC$` + `public` + 別 share を同時に扱える。
- session close 時に全 tree を best-effort disconnect する。

### P1-8. DFS referral の実サーバE2Eと auto-follow

状態: `partial`

実装確認:

- `SMBee.dfsReferral` / `smbcli dfs` はある。
- `issues/009-dfs-referral-real-server-e2e.md` に、実 msdfs サーバ未検証と記録されている。
- 現在の API は referral metadata を返すだけで、target へ reconnect して path を辿る処理は呼び出し側責務。

Linux/macOS smbclient として必要な理由:

- 企業ファイルサーバでは DFS namespace が普通に使われる。
- smbclient として `smb://domain/root/link/path` を開いた時に referral を辿れないと、実用上「アクセス不可」に見える。

やること:

- Samba msdfs profile を作る。
- `SMBeeE2ETests` に DFS referral E2E を足す。
- auto-follow policy を設計する:
  - opt-in / default on
  - credential reuse
  - loop detection
  - referral TTL cache
  - target selection
- `SMBClient` に `resolveAndConnect` か path open 時の transparent referral を追加するか決める。

完了条件:

- msdfs Samba / Windows DFS で referral metadata が実 wire で decode できる。
- auto-follow を入れる場合、DFS link 配下の `ls/stat/read` が通る。

### P1-9. reparse point target resolution / symlink policy

状態: `partial`

実装確認:

- `SMBFileStat.reparseTag` と `SMBReparseKind` はある。
- `todo.md` に symlink target 解決 `FSCTL_GET_REPARSE_POINT` は未実装と記録されている。
- recursive copy/delete/download は reparse point を directory として辿らない安全側 policy になっている。

Linux/macOS smbclient として必要な理由:

- symlink / junction / mount point / DFS link はファイルブラウザで必ず問題になる。
- targetを表示できないと、UI/CLIで「何があるか」は分かっても「どこへ向いているか」が分からない。

やること:

- `FSCTL_GET_REPARSE_POINT` を実装する。
- symlink / mount point / DFS reparse data の decoder を分ける。
- CLI: `smbcli readlink` または `stat --json` に target を出す。
- recursive operation の policy を明示する:
  - followしない
  - same-shareだけfollow
  - explicit `--follow-reparse` のみ

完了条件:

- Samba / Windows / macOS SMBX で reparse target または unsupported を正しく返す。
- recursive operation で cycle しない。

### P1-10. byte-level resume / transfer verification / sparse file

状態: `partial`

実装確認:

- `downloadDirectory` / `uploadDirectory` の `resume` は size一致なら skip するだけ。
- 単一 file の byte-level resume はない。
- checksum verification はない。
- sparse file / zero range は未実装。

Linux/macOS smbclient として必要な理由:

- 大ファイル転送、動画、VM image、バックアップ用途では中断再開が必要。
- size一致だけでは corruption を検出できない。
- sparse file を通常転送すると通信量・ディスク使用量が膨らむ。

やること:

- 単一 file download/upload に `resume` を追加する。
- local partial file の扱いを決める:
  - `.part` staging
  - size確認後 range read/write
  - mtime/size/optional hash check
- `--verify size|hash|none` を検討する。
- sparse file 対応を調査する:
  - allocation size の取得
  - zero range / hole preservation の可能性
  - ローカルFS側の sparse write

完了条件:

- 意図的に中断した download/upload を再実行して途中から再開できる。
- `--verify` で転送後の破損を検出できる。

### P1-11. macOS metadata / resource fork / alternate data stream policy

状態: `missing`

実装確認:

- named stream / alternate data stream / resource fork を扱う public API は確認できない。
- `QUERY_DIRECTORY` / `QUERY_INFO` は通常ファイル metadata 中心。

Linux/macOS smbclient として必要な理由:

- macOS の Finder 相当コピーでは、拡張属性・resource fork・Finder info が問題になる。
- Linux/macOS の CLI copy として「データ fork だけコピー」なのか「macOS metadata も保つ」のかを明示しないと事故る。

やること:

- まず policy を決める:
  - SMBee core は data fork のみ。
  - macOS metadata は consumer 側。
  - あるいは named stream API を実装する。
- 実装する場合:
  - named stream enumeration / read / write を調査する。
  - macOS resource fork / AFP_AfpInfo 相当の互換性を実測する。

完了条件:

- README limitations に data fork only か metadata preservation 対応かを明記する。
- 対応するなら macOS SMBX と Samba fruit module で smoke を通す。

## P2: 実用性・管理系 smbclient として欲しい未実装

### P2-1. SID -> account name resolution

状態: `missing`

実装確認:

- `securityInfo` は SID 文字列を返す。
- `issues/008-acl-followups-sid-name-resolution-set-security.md` に MS-LSAT `LsarLookupSids` が未実装と記録されている。
- `setSecurityInfo` は後から実装済みになったため、issue 008 の B は stale。A の SID 名解決はまだ未実装。

やること:

- 軽量版: well-known SID table を持つ。
- 完全版: `\lsarpc` named pipe + MS-LSAT `LsarLookupSids` を実装する。
- `smbcli acl` に `--resolve-sids` を追加する。

完了条件:

- `S-1-1-0` などの well-known SID が human-readable に表示される。
- AD / Samba AD で domain user SID を解決できる。

### P2-2. owner / group / SACL write

状態: `missing`

実装確認:

- `setSecurityInfo` は DACL write のみ。
- `todo.md` に SACL は特権要求のため対象外、owner/group 書き換えも対象外と記録されている。

やること:

- owner/group write を実装するか決める。
- SACL は監査権限が必要なため、原則 out-of-scope でもよい。
- 実装する場合は `AdditionalInformation` の OWNER / GROUP / SACL bit と権限エラーを丁寧に扱う。

完了条件:

- 非対応なら docs に明記。
- 対応するなら専用 test share で rollback 可能な E2E を作る。

### P2-3. CHANGE_NOTIFY の reconnect / JSON / full-rescan helper

状態: `partial`

実装確認:

- `withChangeNotifications` はある。
- `todo.md` に `smbcli watch --json` 未実装、再接続時の再購読未配線と記録されている。

やること:

- `smbcli watch --json`。
- reconnect時の resubscribe。
- overflow時に full rescan を呼び出し側へ促すだけでなく、helper API を用意するか決める。

完了条件:

- watch中に接続断 -> reconnect -> 再購読できる。
- overflowを machine-readable に扱える。

### P2-4. CLI batch / wildcard の拡張

状態: `partial`

実装確認:

- `mget` / `mput` はある。
- `todo.md` に recursive `mget/mput -r`、`--create-dirs`、個別 progress、確認 prompt は defer と記録されている。

やること:

- `mget -r` / `mput -r`。
- `--include` / `--exclude` を recursive directory transfer にも統一する。
- `--create-dirs`。
- `--progress` を複数ファイル・recursive transfer に対応する。

完了条件:

- shell glob と SMB path validation の責務が崩れない。
- dry-run 出力で転送計画が確認できる。

### P2-5. CLI JSON parity / stable machine-readable output

状態: `partial`

実装確認:

- `probe` / `ls` / `stat` / `shares` / `df` / `acl` / `dfs` は JSON 出力がある。
- `watch` は JSON なし。
- `get/put/cp/mv/rm/mkdir/setacl` は成功時の structured output がない。

やること:

- すべての CLI に `--json` を付けるか、成功時出力不要のコマンドは docs に明記する。
- error JSON は別 flag にするか検討する。

完了条件:

- 自動化スクリプトが stdout/stderr を安定して parse できる。

### P2-6. operation-level deadline

状態: `missing`

実装確認:

- `timeout` は socket-level timeout として配線済み。
- `todo.md` に全操作 deadline は未対応と記録されている。

やること:

- `operationTimeout` / `deadline` を API に追加する。
- socket timeout と全体 timeout を分ける。
- recursive transfer では per-file timeout と全体 timeout を分ける。

完了条件:

- hanging server / stalled transfer を bounded に中断できる。

### P2-7. SMB ECHO / keepalive

状態: `partial`

実装確認:

- 2026-07-02: `SMB2Commands.echo` / `SMB2Echo` codec を追加。
- 2026-07-02: `SMBClientSession.echo()` / `SMBee.echo(...)` / `smbcli ping` を追加。
- 2026-07-02: codec shape、facade teardown、CLI parse の unit coverage を追加。
- persistent session の automatic / periodic keepalive は未実装。

Linux/macOS smbclient として必要な理由:

- 長時間 watch / large transfer / idle persistent session で server / NAT / VPN の idle timeout を検出したい。

やること:

- persistent session に optional keepalive を追加。
- keepalive 間隔、失敗時の session state、API surface を決める。

完了条件:

- authenticated ECHO を明示的に送れる。
- idle session で periodic ECHO を送れる。
- server切断を bounded に検出できる。

### P2-8. SMB CANCEL command

状態: `missing` as protocol command

実装確認:

- `SMB2Commands.cancel` constant はある。
- `SMB2Cancel` encoder / explicit CANCEL send path は確認できない。
- 現在の cancellation は close-on-cancel / transport shutdown を中心にしている。

Linux/macOS smbclient として必要な理由:

- `CHANGE_NOTIFY` や長い IOCTL/READ を protocol 的にキャンセルしたい場面がある。
- transport close は強い手段であり、session再利用と相性が悪い。

やること:

- SMB2 CANCEL request を実装。
- outstanding request tracking と結びつける。
- cancel後の response / STATUS_CANCELLED の扱いを決める。

完了条件:

- watch / long read を TCP close なしで cancel できる。

## P3: optional / advanced / 明示的に後回し

### P3-1. SMB compression

状態: `missing`

SMB 3.1.1 の compression は未実装。WAN越しや大ファイル転送では有効な場合があるが、ローカルNAS/obaket MVPでは後回しでよい。

完了条件:

- NEGOTIATE compression capabilities を実装するか、unsupported と明記する。

### P3-2. SMB multichannel

状態: `missing`

複数NIC / Wi-Fi+Ethernet / 高速NASで効くが、実装規模が大きい。Linux/macOS userspace client としては optional。

完了条件:

- unsupported と明記する。
- 対応する場合は channel binding / session binding / credit handling を再設計する。

### P3-3. SMB over QUIC

状態: `missing`

Windows系の新しい構成向け。Linux/macOS の汎用 smbclient MVPでは scope 外。

完了条件:

- 明示的に unsupported。

### P3-4. SMB Direct / RDMA

状態: `explicitly-out-of-scope`

userspace Swift SMB client の範囲外。

### P3-5. printer / print share support

状態: `explicitly-out-of-scope`

MS-SMB2 は file / print resource sharing を含むが、SMBee の用途は file browser / object storage backend。printer share は scope 外。

### P3-6. SMB1 / NetBIOS session service / port 139

状態: `explicitly-out-of-scope`

`docs/smb-protocol.md` でも SMB1 / CIFS は scope 外、transport は direct TCP 445 としている。

### P3-7. POSIX / UNIX extensions

状態: `missing`

Linux client としては mode/uid/gid/symlink/xattr の期待が出るが、SMB2/3標準互換との境界が難しい。まず metadata/resource fork/ADS policy を決めた後に扱う。

### P3-8. quotas / named streams / extended attributes

状態: `missing`

File browser / backup / macOS metadata preservation を本格的にやるなら必要。MVPでは data fork only として明示する方が安全。

## Stale / 注意が必要な既存 issue

### `issues/008-acl-followups-sid-name-resolution-set-security.md`

- B: SET_SECURITY は既に実装済み。`todo.md` と `SMBClient.swift` / `SMB2ReadCodecs.swift` / `SMBeeE2ETests.swift` でも確認できる。
- A: SID 名前解決は未実装のまま。
- C: SID 6-byte authority は現状維持でよい記録項目。

対応:

- issue 008 を更新し、SET_SECURITY 部分を done にする。
- SID lookup だけを新 issue に分離する。

## README に書くべき limitations

`smbclient` として過大に見せないため、README には次を明記する。

- SMB 3.x only。SMB 2.1 authenticated fallback は非対応 (probe-only、authenticated connect は診断付き `protocolError`)。
- Kerberos / GSS は未対応。現状は NTLMv2 / NT hash / anonymous。
- Windows SMB Server / NAS は smoke 未完了。
- durable handle / lease / oplock / byte-range lock は未対応。
- DFS referral は metadata 取得のみ。auto-follow と実 msdfs E2E は未完了。
- symlink / reparse point は tag 取得のみ。target 解決は未対応。
- byte-level resume / checksum verify / sparse file preservation は未対応。
- macOS resource fork / xattr / named stream preservation は未対応または方針未決。
- SMB1 / NetBIOS / port 139 / printer / RDMA / QUIC / multichannel / compression は未対応。

## 推奨実装順

1. P0-1 compatibility matrix の実サーバ結果埋め (Windows / NAS / macOS SMBX re-run)
2. P1-3 credit accounting / multi-credit
3. P1-7 multi-tree session model
4. P1-8 DFS real E2E + optional auto-follow
5. P1-9 reparse target resolution
6. P1-10 byte-level resume / verification
7. P1-1 Kerberos/GSS only if real user/server requirements demand it

## 完了の定義

SMBee を Linux/macOS smbclient として `0.1.0` にする最低条件:

- Samba / macOS SMBX / Windows SMB Server の smoke matrix がある。
- README に unsupported features が明記されている。
- 3.0.2 encrypted と 3.1.1 signing/encrypted の authenticated path が CI または scheduled compat で継続検証される。
- `docs/coverage.md` で spec feature と実装・テスト・未実装を辿れる。
- 未対応項目は runtime error / CLI error / README limitation のどれかで明示され、暗黙に失敗しない。

SMBee を `1.0.0` に近づける条件:

- Windows / NAS の互換 matrix が埋まる。
- credit accounting と large IO が安定する。
- DFS / reparse / lock / durable handle / Kerberos について、対応または非対応の判断が固まる。
- public API / error taxonomy / cancellation / timeout semantics が凍結される。
