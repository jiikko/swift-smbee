# todo2: current Linux/macOS smbclient backlog

この文書は、SMBee を **Linux / macOS で使う smbclient 相当の SMB2/3 クライアント**として育てるための、現在の未解決 backlog である。

`todo.md` は実装進捗の時系列ログではなく、現在の状態が分かる要約に整理する。詳細な調査ログや履歴は issue / commit / docs に寄せる。

## 監査時点

- 最終更新: 2026-07-19
- 対象 branch: `master`
- 正本仕様:
  - MS-SMB2: SMB2/3 command、dialect、signing/encryption、credit、durable handle、CHANGE_NOTIFY
  - MS-FSCC: file info / filesystem info / FSCTL / reparse point / security descriptor
  - MS-NLMP: NTLM / NTLMv2
  - MS-SPNG: SPNEGO
  - MS-DFSC: DFS referral
  - MS-SRVS / MS-RPCE / MS-DTYP / MS-ERREF: share enum、DCE/RPC、SID/FILETIME、NTSTATUS

## 状態ラベル

- `implemented`: 実装済み。unit または E2E の証拠がある。
- `implemented-but-underverified`: 実装済みだが、実サーバ・CI・互換 matrix の裏取りが足りない。
- `partial`: 一部実装済み。smbclient として期待される挙動にはまだ足りない。
- `missing`: 実装がない、または public API / CLI として露出していない。
- `explicitly-unsupported`: 現時点では対応しない。README / docs に制限として明記する。

## 既にカバーしている範囲

ここは再実装しない。追加作業がある場合も「互換確認」「API安定化」「CI昇格」として扱う。

| 領域 | 状態 | メモ |
|---|---|---|
| direct TCP 445 transport | implemented | direct TCP 445 + 4 byte length framing。SMB1 / NetBIOS は出さない。 |
| SMB 3.0 / 3.0.2 / 3.1.1 authenticated dialect | implemented | authenticated path は SMB 3.x only。SMB 2.0.2 / 2.1 は probe-only。 |
| NTLMv2 password auth | implemented | MIC、KEY_EXCH、NT hash 派生あり。 |
| NT hash credential | implemented | `SMBCredential(username:ntHash:domain:)`、CLI `--nt-hash` / `SMB_NT_HASH`。 |
| anonymous / guest auth | implemented | `SMBCredential.anonymous`、CLI `--anonymous` / `--guest`。 |
| SPNEGO NTLM wrapping | implemented | NTLM OID 前提。Kerberos mech は未実装。 |
| SMB 3.0.2 signing/encryption | implemented | AES-CMAC / AES-128-CCM。Samba encrypted-required E2E + macOS SMBX smoke 記録あり。 |
| SMB 3.1.1 signing/encryption | implemented-but-underverified | AES-GMAC / AES-128-GCM。Samba 3.1.1 signing/encrypted profile は green。Windows/NAS 実サーバ smoke は未実施。 |
| 基本 SMB operations | implemented | NEGOTIATE / SESSION_SETUP / TREE_CONNECT / CREATE / CLOSE / FLUSH / READ / WRITE / QUERY_DIRECTORY / QUERY_INFO / SET_INFO / IOCTL / CHANGE_NOTIFY / TREE_DISCONNECT / LOGOFF。 |
| ls / stat / cat / range read / streaming read | implemented | `SMBee.list` / `stat` / `read` / `withReadStream`、`smbcli ls/stat/cat`。 |
| put / get / mkdir / mv / rm / cp | implemented | `SMBee.upload` / `download` / `makeDirectory` / `rename` / `delete` / `copy`、CLI サブコマンド。 |
| recursive get / put / cp / rm | implemented | `continueOnError` / `skipExisting` / `dryRun` / resume / verify / include-exclude / per-file-timeout あり。 |
| share discovery | implemented-but-underverified | IPC$ + SRVSVC `NetrShareEnum`。Samba では実測済み。macOS SMBX / Windows / NAS smoke が残る。 |
| volume / filesystem info | implemented-but-underverified | `SMBee.volumeInfo` / `smbcli df`。Samba E2E 済み。macOS SMBX / Windows / NAS smoke が残る。 |
| path validation | implemented-but-underverified | `SMBPath` / `SMBShareName` で validation 済み。Samba の decomposed Unicode path E2E 済み。macOS SMBX / Windows / NAS の実測が残る。 |
| metadata read/write | implemented | file attributes、creation/access/modified/change time、`SMBFileMetadataUpdate`、`updateMetadata`。 |
| security descriptor read / DACL / owner / group write | implemented-but-underverified | `securityInfo` / `setSecurityInfo` / `smbcli acl` / `smbcli setacl`。SACL は scope 外。AD / Samba AD 実測が残る。 |
| SID name resolution | implemented-but-underverified | well-known SID table + LSARPC `LsarLookupSids`。AD / Samba AD 実測と issue 整理が残る。 |
| change notification | implemented-but-underverified | `withChangeNotifications(autoReconnect:)` / `smbcli watch --json --reconnect`。Samba E2E + reconnect unit あり。Windows/NAS 実測が残る。 |
| DFS referral metadata | implemented-but-underverified | `SMBee.dfsReferral` / `smbcli dfs`、multi-hop `resolveDFS` / `connectFollowingDFS` / `listFollowingDFS` / `readFollowingDFS`。loop detection、credential-scoped / bounded TTL cache、suffix rewrite は unit + Samba msdfs E2E 済み。Windows DFS 実測が残る。 |
| reparse target resolution | implemented-but-underverified | `readlink` で symlink / mount point / LX symlink target decode。DFS/NFS reparse data は opaque。実サーバ smoke が残る。 |
| byte-level resume / transfer verification | implemented | single-file get/put resume、recursive verify size/hash、SHA-256 read-back 実装済み。 |
| sparse file operations | partial | FSCTL_SET_SPARSE / SET_ZERO_DATA / QUERY_ALLOCATED_RANGES と `smbcli sparse`、allocation size stat 表示、Samba FSCTL E2E は実装済み。通常 transfer の hole preservation policy が残る。 |
| ECHO / keepalive | implemented | `echo` / `smbcli ping` / opt-in keepalive 実装済み。reconnect policy との統合は未決。 |
| SMB CANCEL / shared-session READ cancellation | implemented-but-underverified | watch / READ / IOCTL 等の通常 transaction cancellation で SMB2 CANCEL を送る。送信中 task を cancel せず response を drain する修正は blocking-send unit、Samba E2E、実 NAS の cancel-storm で確認済み。Windows / 他 NAS matrix は残る。 |
| byte-range lock | implemented-but-underverified | library API `SMBClientSession.withFileLock` と `smbcli lock`。Windows 実測は matrix 側。 |

## P0: 0.1.0 前の release blocker

### P0-1. 互換 matrix を実サーバで埋める

状態: `partial` / `implemented-but-underverified`

Windows SMB Server 対応: **pending**（実サーバ smoke 環境待ち）。現時点では Windows クライアント対応を意味せず、Linux/macOS client からの server interoperability を確認する作業を指す。

現状:

- Samba は CI / compat workflow でかなり確認済み。
- macOS SMBX は 3.0.2 の基本 smoke 記録あり。
- Windows SMB Server / Windows Pro / Synology / QNAP / 古い Samba 系 NAS は未実測。
- `docs/compatibility-matrix.md` と `bin/e2e/smoke-real-server.sh` は追加済み。
- SMBee を `smbclient` 相当と名乗る前に、Samba green だけでは不足。

やること:

- `docs/compatibility-matrix.md` に次を埋める:
  - Linux client -> Samba
  - Linux client -> Windows SMB Server
  - Linux client -> Synology/QNAP/古い Samba 系 NAS
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
  - file / directory / ACL / metadata / recursive transfer / share discovery / watch / sparse / lock の可否

完了条件:

- `smbcli probe/shares/ls/stat/cat/get/put/mkdir/mv/cp/rm/df/acl/watch` の representative smoke が、少なくとも Samba / macOS SMBX / Windows SMB Server で通る。
- Windows / NAS で失敗する項目は `known-issues` として matrix に残す。

### P0-2. API stability / packaging

状態: `implemented-but-underverified`

現状:

- SwiftPM library と CLI は動く。
- SemVer、public API の source compatibility、deprecated credential surface、DocC/API examples、binary/release artifact の方針は未整理。
- consumer が依存し始める前に public 型の命名、Sendable、error taxonomy、cancellation / timeout semantics を凍結する必要がある。

やること:

- `SMBCredential.password` 露出の deprecation plan を決める。
- public 型と error taxonomy をレビューする。
- `Sendable` / actor isolation / cancellation semantics を doc に固定する。
- DocC/API examples を追加する。
- release artifact 方針を決める。

完了条件:

- `0.1.0` 用の public API freeze note が README / docs にある。
- breaking change 予定が issue 化されている。
- consumer が依存しても migration path を説明できる。

## P1: smbclient として実装すべき中核残件

### P1-1. SMB2 credit accounting / multi-credit large IO E2E

状態: `implemented-but-underverified`

更新: SMB 3.1.1 encrypted の 2MiB+ READ/WRITE と multi-credit WRITE は push CI E2E で検証済み。残りは copychunk 実測と性能回帰監視。

現状:

- READ/WRITE の CreditCharge / CreditRequest、response grant tracking、credit-aware chunk planner は実装済み。
- `SMB2CreditWindow` actor と messageId keyed demux は実装済み。
- multi-credit READ/WRITE で messageId が CreditCharge 分進まないバグは修正済み。
- local read/write chunk cap は 1 MiB へ引き上げ済み。
- PR/push には 4GiB 境界 range-read E2E があり、週次 `Large-file E2E` workflow は sparse 4GiB+ fixture で read-stream と EOF を検証する。
   - SMB 3.1.1 encrypted session の 2MiB+ READ/WRITE は push CI E2E で検証済み（1MiB 境界超過の multi-credit WRITE を含む）。
   - 残件は offload-capable server の copychunk 実測と性能回帰監視。

やること:

- copychunk と encryption overhead を含む chunk planner の E2E 検証を広げる。
- SMB 3.1.1 encrypted session で 1 MiB chunk の large file read/write を実行する。
- multi-credit WRITE と offload-capable server の copychunk を実測する。
- throughput regression を command count / byte count / chunk count で監視する。

完了条件:

- large transfer で credit 不足・不正 CreditCharge が出ない。
- SMB 3.1.1 encrypted session の large READ/WRITE が安定する。

### P1-2. multi-share / multi-tree session model

状態: `implemented-but-underverified`（scoped tree API で実装済み）

更新: `SMBClientSession.listShares()` と `SMBClientTreeSession.listShares()` を追加し、IPC$ share discovery を同一認証 session の scoped tree として実行できるようにした。`withTree(share:)` で public / 別 share も同一 session 上で扱え、child tree tracking と session close 時の全 tree 切断にも対応した。DFS referral は scoped DFS-root tree 上で実行する。

現状:

- `SMBClientSession.withTree(share:)` と `SMBClientTreeSession` は実装済み。
- 同じ authenticated session 上で追加 TREE_CONNECT し、closure 終了時に tree 単位で disconnect できる。
- share discovery は scoped IPC$ tree、DFS referral は scoped DFS-root tree を使用する。
- full `SMBServerSession` / `SMBTreeSession` 型分離は未実装（現 API の scoped tree で要件を満たす）。

やること:

- `SMBServerSession` と `SMBTreeSession` に分けるか、既存 API のまま scoped tree を強化するか決める。
- IPC$ / data share / DFS / LSA helper を `withTree` ベースで統合する。
- graceful teardown を tree 単位 / session 単位に分ける。

完了条件:

- 同じ session 上で `IPC$` + `public` + 別 share を扱える。
- session close 時に全 tree を best-effort disconnect する。

### P1-3. DFS referral の実サーバ E2E と auto-follow

状態: `partial`

現状:

- `SMBee.dfsReferral` / `smbcli dfs` はある。
- Samba msdfs link の実 wire E2E を push CI と Apple Container ローカル E2E で確認した。
- `resolveDFS` / `connectFollowingDFS` / `listFollowingDFS` / `readFollowingDFS` は target 再接続、multi-hop、loop detection、credential-scoped / bounded TTL cache、path suffix rewrite を行う。`connectFollowingDFS` は session と最終 relative path を `SMBDfsConnection` で返す。Samba chain link の list/read E2E 済み。

完了条件:

- Samba msdfs で referral metadata と chain link の read が実 wire で通る。
- Windows DFS は compatibility matrix の pending として実測する。

### P1-4. Kerberos / GSS / SPNEGO(Kerberos mech)

状態: `partial`

現状:

- 現在は NTLMv2 / NT hash / anonymous が中心。
- SPNEGO は NTLM OID 前提。
- `SMBAuthenticator` のような auth backend 抽象化は未実装。

Linux/macOS smbclient として必要な理由:

- Active Directory / enterprise NAS / macOS Finder 相当認証では Kerberos / GSS が必要になる場面がある。
- Kerberos 非対応のままでもよいが、その場合は README limitations と runtime error を明確にする。

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

### P1-5. durable handle / persistent handle / reconnect policy

状態: `explicitly-unsupported`

判断:

- durable / persistent handle は、接続断をまたいで file handle を復元する状態機械であり、実サーバでの切断シミュレーション E2E なしには検証しきれない大タスク。
- 現時点では **明示的に unsupported** とする。
- CREATE は durable / lease / oplock context を送らない。
- README / docs/coverage.md の limitations に載せる。

完了条件:

- 非対応のままなら、README / docs/coverage.md / runtime limitation に載る。
- 対応するなら、transfer 中の接続断 simulation で再開できる。

### P1-6. macOS metadata / resource fork / alternate data stream policy

状態: `missing`

現状:

- named stream / alternate data stream / resource fork を扱う public API はない。
- 通常の data fork と基本 metadata が中心。

Linux/macOS smbclient として必要な理由:

- macOS の Finder 相当コピーでは、拡張属性・resource fork・Finder info が問題になる。
- CLI copy として「data fork だけコピー」なのか「macOS metadata も保つ」のかを明示しないと事故る。

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

## P2: 実用性・管理系 smbclient として欲しい残件

### P2-1. path handling / Unicode normalization smoke

状態: `implemented-but-underverified`

現状:

- CLI URL parser と public API の validation は `SMBPath` / `SMBShareName` に寄せた。
- `.` / `..` / decoded separator / 空 share などは拒否する。

残:

- macOS Finder / Samba / Windows / NAS で Unicode normalization 差を実測する。
- matrix に path encoding / normalization の観測結果を残す。

### P2-2. share discovery / volume / metadata / ACL の実サーバ smoke

状態: `implemented-but-underverified`

残:

- SRVSVC share discovery の macOS SMBX / Windows / NAS smoke。
- volume info の macOS SMBX / Windows / NAS smoke。
- ACL / owner / group / SID lookup の AD / Samba AD 実測。
- Samba POSIX backend の正規化差分を docs に残す。

### P2-3. reparse / readlink 実サーバ smoke

状態: `implemented-but-underverified`

残:

- Samba / Windows / macOS SMBX で `smbcli readlink` smoke を取る。
- recursive operation の policy を docs に明記する:
  - follow しない
  - same-share だけ follow
  - explicit `--follow-reparse` のみ

### P2-4. sparse file preservation / allocation size

状態: `partial`（allocation size の stat/JSON 表示は実装済み）

現状:

- `FSCTL_SET_SPARSE` / `FSCTL_SET_ZERO_DATA` / `FSCTL_QUERY_ALLOCATED_RANGES` は実装済み。
- `smbcli sparse` はある。

残:

- `SMBFileStat.allocationSize` と `stat --json` の `allocationSize` は実装済み。実サーバごとの差異確認は残る。
- copy/get/put で sparse hole を保存する policy を決める。
- ローカル FS 側の sparse write と SMB 側 allocated ranges の対応を検証する。

### P2-5. operation-level deadline の public API 方針

状態: `partial`

現状:

- socket-level `timeout` は配線済み。
- CLI は `--operation-timeout` と recursive transfer の `--per-file-timeout` を持つ。

残:

- `SMBee.read(..., operationTimeout:)` を追加済み。write/recursive API への展開は、ブロック中の transport receive を deadline cancellation で確実に中断できるようにしてから行う。
- timeout error taxonomy を固定する。

### P2-6. keepalive と reconnect policy の統合

状態: `partial`

現状:

- `SMBClientSession.echo()` / `SMBee.echo(...)` / `smbcli ping` はある。
- `SMBClientSession.startKeepAlive(interval:)` / `stopKeepAlive()` はある。

残:

- keepalive 失敗時に reconnect まで行うか、session invalidation のみにするか決める。
- watch reconnect との責務分離を docs に書く。

### P2-7. CLI surface follow-up

状態: `partial`（byte-range lock surface は実装済み）

残:

- byte-range lock CLI (`smbcli lock`) は実装済み。実サーバ matrix での CLI smoke は残る。
- mget/mput の確認 prompt を実装するか、`--dry-run` で代替すると明記する。
- JSON schema が増えたら `docs/smbcli-json.md` を更新する。

## P3: optional / advanced / 明示的に後回し

### P3-1. SMB compression

状態: `missing`

SMB 3.1.1 compression は未実装。WAN 越しや大ファイル転送では有効な場合があるが、ローカル NAS / obaket MVP では後回し。

完了条件:

- NEGOTIATE compression capabilities を実装するか、unsupported と明記する。

### P3-2. SMB multichannel

状態: `missing`

複数 NIC / Wi-Fi + Ethernet / 高速 NAS で効くが、実装規模が大きい。Linux/macOS userspace client としては optional。

完了条件:

- unsupported と明記する。
- 対応する場合は channel binding / session binding / credit handling を再設計する。

### P3-3. SMB over QUIC

状態: `missing`

Windows 系の新しい構成向け。Linux/macOS の汎用 smbclient MVP では scope 外。

完了条件:

- unsupported と明記する。

### P3-4. SMB Direct / RDMA

状態: `explicitly-unsupported`

userspace Swift SMB client の範囲外。

### P3-5. printer / print share support

状態: `explicitly-unsupported`

MS-SMB2 は file / print resource sharing を含むが、SMBee の用途は file browser / object storage backend。printer share は scope 外。

### P3-6. SMB1 / NetBIOS session service / port 139

状態: `explicitly-unsupported`

SMB1 / CIFS は scope 外。transport は direct TCP 445 のみ。

### P3-7. POSIX / UNIX extensions

状態: `missing`

Linux client としては mode/uid/gid/symlink/xattr の期待が出るが、SMB2/3 標準互換との境界が難しい。まず metadata/resource fork/ADS policy を決めた後に扱う。

### P3-8. quotas / named streams / extended attributes

状態: `missing`

file browser / backup / macOS metadata preservation を本格的にやるなら必要。MVP では data fork only として明示する方が安全。

## stale note cleanup

下記は古い未実装記述が残りやすいので、現在の扱いを固定する。

- SMB 3.1.1 GMAC/GCM: 実装済み。Samba E2E green。残件は Windows/NAS smoke。
- CHANGE_NOTIFY reconnect: 実装済み。残件は実サーバ互換 matrix。
- SID lookup: LSARPC lookup 実装済み。残件は AD / Samba AD 実測と issue 更新。
- owner/group write: 実装済み。SACL は scope 外。
- byte-level resume / verify: 実装済み。残件は sparse preservation / allocation size。
- operation timeout: CLI と `SMBee.read(..., operationTimeout:)` に実装済み。残件は write/recursive API への展開判断。
- durable handle: 現時点では unsupported として明記する。
- shared-session READ cancel: 送信中 task を cancel せず response を drain する修正済み。blocking-send unit / Samba E2E / 実 NAS 確認あり。Windows / 他 NAS の互換確認は残る。

## README に書くべき limitations

`smbclient` として過大に見せないため、README には次を明記する。

- SMB 3.x only。SMB 2.1 authenticated fallback は非対応。SMB 2.1 は probe-only。
- Kerberos / GSS は未対応。現状は NTLMv2 / NT hash / anonymous。
- Windows SMB Server / NAS は smoke 未完了。
- durable / persistent handle は未対応。lease / oplock は要求しない。byte-range lock は library API 先行。
- DFS referral は multi-hop auto-follow、loop detection、TTL cache、path suffix rewrite と Samba msdfs E2E まで実装済み。Windows DFS は matrix pending。
- symlink / mount point / LX symlink は `readlink` で target 解決可。DFS/NFS reparse data は opaque。
- byte-level resume と `--verify size|hash` は対応済み。
- sparse FSCTL は対応済みだが、転送時の sparse preservation と allocation size 表示は未整理。
- macOS resource fork / xattr / named stream preservation は未対応または方針未決。
- SMB1 / NetBIOS / port 139 / printer / RDMA / QUIC / multichannel / compression は未対応。

## 推奨実装順

1. P0-1 compatibility matrix の実サーバ結果埋め。Windows / NAS / macOS SMBX re-run。
2. P1-1 multi-credit WRITE / SMB 3.1.1 encrypted large IO E2E。
3. P1-2 multi-tree session model。
4. P1-3 DFS real E2E + optional auto-follow。
5. P0-2 API stability / packaging。
6. P1-6 macOS metadata / named stream policy。
7. P1-4 Kerberos / GSS。実ユーザーや実サーバ要件が出たら着手。

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
