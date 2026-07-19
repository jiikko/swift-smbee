# SMBee implementation TODO

この文書は、SMBee の現在の実装状態と残タスクを短く確認するための入口である。

詳細な smbclient backlog は [`todo2.md`](todo2.md) を正本とする。実装方針は [`docs/architecture.md`](docs/architecture.md) / [`docs/smb-protocol.md`](docs/smb-protocol.md) / [`docs/testing.md`](docs/testing.md) を正本とする。

## 現在の到達点

SMBee は、Linux / macOS で動く Swift 製 SMB2/3 client library + `smbcli` として、MVP の read/write path は実装済み。

主な実装済み範囲:

- direct TCP 445 transport
- SMB 3.0 / 3.0.2 / 3.1.1 authenticated dialect
- SMB 2.0.2 / 2.1 probe-only policy
- NTLMv2 password auth
- NT hash credential
- anonymous / guest auth
- SPNEGO NTLM wrapping
- SMB 3.0.2 AES-CMAC signing / AES-128-CCM encryption
- SMB 3.1.1 AES-GMAC signing / AES-128-GCM encryption
- NEGOTIATE / SESSION_SETUP / TREE_CONNECT / CREATE / CLOSE / FLUSH
- READ / WRITE / QUERY_DIRECTORY / QUERY_INFO / SET_INFO / IOCTL
- CHANGE_NOTIFY / TREE_DISCONNECT / LOGOFF / ECHO / CANCEL / LOCK
- `probe` / `ls` / `stat` / `cat`
- `get` / `put` / `mkdir` / `mv` / `rm` / `cp`
- recursive `get` / `put` / `cp` / `rm`
- streaming read / streaming write
- share discovery via IPC$ + SRVSVC
- filesystem / volume info
- metadata read/write
- security descriptor read / DACL / owner / group write
- SID name resolution via well-known table + LSARPC lookup
- reparse tag / `readlink`
- DFS referral metadata API
- byte-level resume for single-file get/put
- transfer verification `--verify size|hash`
- sparse FSCTL operations
- persistent session API
- scoped multi-tree API `withTree(share:)`
- graceful TREE_DISCONNECT / LOGOFF
- `smbcli lock`（byte-range lock の acquire/release surface）
- `SMBFileStat.allocationSize` / `stat --json` allocation size
- `SMBee.read(..., operationTimeout:)` の単一 read deadline
- 1 MiB local read/write chunk、credit-aware multi-flight I/O、週次 4GiB+ read-stream E2E
- shared session 上の in-flight READ cancel 後の response drain（実 NAS で再利用確認済み）
- socket timeout / operation timeout / per-file timeout
- progress callback / CLI progress
- JSON output / structured error output
- debug redaction / explicit wire trace gate

## 実装済みだが検証が薄いもの

| 領域 | 状態 | 残り |
|---|---|---|
| SMB 3.1.1 GMAC/GCM | implemented-but-underverified | Samba では green。Windows / NAS smoke が残る。 |
| share discovery | implemented-but-underverified | Samba 実測済み。macOS SMBX / Windows / NAS smoke が残る。 |
| volume info | implemented-but-underverified | Samba E2E 済み。macOS SMBX / Windows / NAS smoke が残る。 |
| path handling | implemented-but-underverified | validation は実装済み。Unicode normalization の実測が残る。 |
| ACL / owner / group / SID lookup | implemented-but-underverified | Samba では実測済み。AD / Samba AD / Windows での実測が残る。 |
| CHANGE_NOTIFY reconnect | implemented-but-underverified | unit + Samba E2E あり。Windows / NAS での挙動確認が残る。 |
| shared-session READ cancellation | implemented-but-underverified | blocking-send unit、Samba E2E、実 NAS の cancel-storm 確認あり。Windows / 他 NAS での matrix は残る。 |
| reparse / readlink | implemented-but-underverified | unit coverage あり。Samba / Windows / macOS SMBX smoke が残る。 |
| byte-range lock | implemented-but-underverified | library API あり。CLI surface と Windows 挙動確認が残る。 |

## 現在の未解決タスク

### P0: release blocker

1. **compatibility matrix を実サーバで埋める**
   - Windows SMB Server 対応は **pending**（実サーバ smoke 環境待ち）。実装可否の判断は matrix 結果に基づく。
   - Samba は CI / compat workflow で確認済み。
   - macOS SMBX は基本 smoke 記録あり。
   - Windows SMB Server / Windows Pro / Synology / QNAP / 古い Samba 系 NAS が未実測。
   - `docs/compatibility-matrix.md` と `bin/e2e/smoke-real-server.sh` を使って、代表コマンドの smoke を埋める。

2. **API stability / packaging**
   - SemVer 方針。
   - public API source compatibility。
   - `SMBCredential.password` 露出の deprecation plan。
   - DocC / examples。
   - binary / release artifact 方針。
   - Sendable / error taxonomy / cancellation / timeout semantics の凍結。

### P1: smbclient 中核残件

1. **SMB2 credit / multi-credit large IO E2E**
   - 状態: `implemented-but-underverified`（暗号化 large READ/WRITE は CI E2E 済み）
   - credit accounting / `SMB2CreditWindow` / messageId demux と 1 MiB local chunk は実装済み。
   - 4GiB+ read-stream E2E は weekly workflow で実行する。PR/push には 4GiB 境界 range-read E2E がある。
   - SMB 3.1.1 encrypted session の 2MiB+ READ/WRITE は push CI E2E で検証済み（1MiB 境界超過の multi-credit WRITE を含む）。
   - 残りは offload-capable server の copychunk 実測と throughput regression の継続監視。

2. **multi-share / multi-tree session model**
   - `SMBClientSession.listShares()` が同一認証セッション上で IPC$ を一時接続し、既存 tree を維持する。
   - `withTree(share:)` で public / 別 share を同じ session から扱え、child tree を tracking して session close 時に全 tree を切断する。
   - DFS referral も同一 session の scoped DFS-root tree 経由に統合済み。
   - `withTree(share:)` は実装済み。
   - 残りは full server/tree session split、IPC$ helper 統合、複数 tree tracking。

3. **DFS referral real E2E + optional auto-follow**
   - `SMBee.dfsReferral` / `smbcli dfs` は実装済み。
   - Samba msdfs link の実 wire referral decode は push CI E2E で検証する。
   - auto-follow policy は未実装。

4. **Kerberos / GSS / SPNEGO(Kerberos mech)**
   - 現状は NTLMv2 / NT hash / anonymous。
   - Kerberos / GSS backend と auth abstraction は未実装。

5. **durable / persistent handle**
   - 現時点では explicitly unsupported。
   - 対応するなら切断シミュレーション E2E と file handle reconnect state machine が必要。

6. **macOS metadata / resource fork / named stream policy**
   - data fork only にするか、named stream API を実装するか未決。
   - Finder 相当コピーを名乗るなら必須。

### P2: 実用性・管理系 follow-up

- path Unicode normalization smoke
- share discovery / volume / ACL / SID lookup の実サーバ smoke
- reparse / readlink の実サーバ smoke
- sparse file preservation / allocation size 表示
- operation-level deadline の public API 化判断
- keepalive と reconnect policy の統合
- byte-range lock CLI surface
- JSON schema 更新運用

### P3: optional / advanced / 後回し

- SMB compression
- SMB multichannel
- SMB over QUIC
- POSIX / UNIX extensions
- quotas / named streams / extended attributes

### explicitly unsupported

- SMB Direct / RDMA
- printer / print share support
- SMB1 / CIFS
- NetBIOS session service / port 139

## stale note cleanup

以下の古い未実装メモは現在の状態に更新済み。

- SMB 3.1.1 crypto framing は実装済み。残りは Windows / NAS smoke。
- CHANGE_NOTIFY reconnect は実装済み。残りは互換 matrix。
- SID lookup は LSARPC lookup 実装済み。残りは AD / Samba AD 実測。
- owner/group write は実装済み。SACL は scope 外。
- byte-level resume / `--verify size|hash` は実装済み。
- sparse FSCTL と allocation size 表示は実装済み。残りは転送時の hole preservation。
- operation timeout は CLI 実装済み。残りは public API 化判断。
- `SMBee.read(..., operationTimeout:)` は実装済み。残りは write/recursive API への展開判断。
- shared session の READ cancel は、送信中 task を cancel せず response を drain するよう修正済み。残りは Windows / 他 NAS の互換確認。
- durable handle は未実装ではなく、現時点では unsupported として扱う。

## 0.1.0 の完了条件

- Samba / macOS SMBX / Windows SMB Server の smoke matrix がある。
- README に unsupported features が明記されている。
- 3.0.2 encrypted と 3.1.1 signing/encrypted の authenticated path が CI または scheduled compat で継続検証される。
- `docs/coverage.md` で spec feature と実装・テスト・未実装を辿れる。
- 未対応項目は runtime error / CLI error / README limitation のどれかで明示され、暗黙に失敗しない。

## 推奨順

1. compatibility matrix の実サーバ結果埋め。
2. multi-credit WRITE / SMB 3.1.1 encrypted large IO E2E。
3. multi-tree session model 整理。
4. DFS real E2E + optional auto-follow。
5. API stability / packaging。
6. macOS metadata / named stream policy。
7. Kerberos / GSS。実要件が出たら着手。
