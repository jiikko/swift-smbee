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
- sparse FSCTL operations（通常 transfer は logical-content policy。hole topology の保存は未対応）
- persistent session API
- scoped multi-tree API `withTree(share:)`
- graceful TREE_DISCONNECT / LOGOFF
- `smbcli lock`（byte-range lock の acquire/release surface）
- `SMBFileStat.allocationSize` / `stat --json` allocation size
- `mget` / `mput` の `--dry-run` による非対話確認と `--json` NDJSON action / summary
- `SMBee.read(...)` / upload / recursive download・upload・copy・delete の operation deadline
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
| path handling | implemented-but-underverified | validation と Samba の decomposed Unicode path E2E は実装済み。macOS SMBX / Windows / NAS の normalization 実測が残る。 |
| ACL / owner / group / SID lookup | implemented-but-underverified | Samba では実測済み。AD / Samba AD / Windows での実測が残る。 |
| CHANGE_NOTIFY reconnect | implemented-but-underverified | unit + Samba E2E あり。Windows / NAS での挙動確認が残る。 |
| shared-session READ cancellation | implemented-but-underverified | blocking-send unit、PR/push必須のSamba cancel-storm E2E、実 NAS 確認あり。Windows / 他 NAS での matrix は残る。 |
| reparse / readlink | implemented-but-underverified | unit coverage あり。Samba / Windows / macOS SMBX smoke が残る。 |
| byte-range lock | implemented-but-underverified | library API と `smbcli lock` の Samba CLI smoke は実装済み。Windows / NAS の挙動確認が残る。 |

## 現在の未解決タスク

### P0: release blocker

1. **compatibility matrix を実サーバで埋める**
   - Windows SMB Server 対応は **pending**（実サーバ smoke 環境待ち）。実装可否の判断は matrix 結果に基づく。
   - Samba は CI / compat workflow で確認済み。
   - macOS SMBX は基本 smoke 記録あり。
   - Windows SMB Server / Windows Pro / Synology / QNAP / 古い Samba 系 NAS が未実測。
   - `docs/compatibility-matrix.md` と `bin/e2e/smoke-real-server.sh` を使って、代表コマンドの smoke を埋める。

2. **API stability / packaging**
   - 0.1 public API freeze、source compatibility、Sendable / actor isolation、error / cancellation / timeout contractは`docs/api-stability.md`に固定済み。
   - `SMBCodecError` / `SMBTransportError`はpublic `Sendable`としてcompile regressionで固定済み。
   - `SMBCredential.password`の段階的deprecation planはissue 063、DocC / compile-tested examplesは追加済み。
   - pre-1.0 / 1.0 の source・binary artifact 配布方針は本 backlog の対象外とし、残タスクには数えない。

### P1: smbclient 中核の状態

1. **SMB2 credit / multi-credit large IO**
   - 状態: `implemented`（暗号化 large READ/WRITE は CI E2E 済み）
   - credit accounting / `SMB2CreditWindow` / messageId demux と 1 MiB local chunk は実装済み。
   - 4GiB+ read-stream E2E は weekly workflow で実行する。PR/push には 4GiB 境界 range-read E2E がある。
   - SMB 3.1.1 encrypted session の 2MiB+ READ/WRITE は push CI E2E で検証済み（1MiB 境界超過の multi-credit WRITE を含む）。
   - offload-capable server の copychunk 実測は compatibility matrix、throughput regression は継続的な CI 運用として扱う。

2. **multi-share / multi-tree session model** — `implemented`
   - `SMBClientSession.listShares()` が同一認証セッション上で IPC$ を一時接続し、既存 tree を維持する。
   - `withTree(share:)` で public / 別 share を同じ session から扱え、child tree を tracking して session close 時に全 tree を切断する。
   - DFS referral も同一 session の scoped DFS-root tree 経由に統合済み。
   - `withTree(share:)` は実装済み。
   - scoped tree API で必要な multi-share 利用・helper 統合・child tree tracking は完了。full server/tree 型分離は任意の API 整理として扱う。

3. **DFS referral real E2E + auto-follow** — `implemented-but-underverified`
   - `SMBee.dfsReferral` / `smbcli dfs` は実装済み。
   - Samba msdfs link の実 wire referral decode は push CI E2E で検証済み。
   - `SMBee.resolveDFS` / `connectFollowingDFS` / `listFollowingDFS` / `readFollowingDFS` は multi-hop、loop detection、credential-scoped / bounded TTL cache、path suffix rewrite を実装済み。
   - `connectFollowingDFS` は `SMBDfsConnection` として session・最終 relative path・hop 数を返す。
   - Samba E2E で chain link の list/read、suffix rewrite、loop rejection を検証済み。custom target selection は `SMBDfsReferralResult.targets` で可能。

4. **Kerberos / GSS / SPNEGO(Kerberos mech)**
   - 状態: 0.1では`explicitly-unsupported`。現状はNTLMv2 / NT hash / anonymous。
   - CLIにKerberos modeはなく、README limitationを正本とする。将来実装はAD/GSS検証環境が揃ってから扱う。

5. **durable / persistent handle**
   - 現時点では explicitly unsupported。
   - 対応するなら切断シミュレーション E2E と file handle reconnect state machine が必要。

6. **macOS metadata / resource fork / named stream policy**
   - 状態: `implemented`（data fork only policy）。
   - resource fork / xattr / ADSは保存・列挙せず、Finder相当コピーを保証しない。

### P2: 実用性・管理系 follow-up

- path Unicode normalization smoke（Samba は実施済み。macOS SMBX / Windows / NAS が残る）
- share discovery / volume / ACL / SID lookup の実サーバ smoke
- reparse / readlink の実サーバ smoke
- sparse file preservation（通常 get/put/copy は logical-content policy。allocation size 表示と Samba sparse FSCTL E2E は実装済み。hole topology の保存は明示的に未対応）
- operation-level deadline の Windows / NAS 実測
- keepalive invalidation / watch reconnect policy の実サーバ smoke
- byte-range lock CLI の実サーバ smoke
- JSON schema更新運用は`docs/smbcli-json.md`の互換ルールとunit/E2E更新checklistに固定済み

### P3: optional roadmap（0.1では明示的unsupported）

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
- sparse FSCTL と allocation size 表示は実装済み。通常 transfer は logical-content policy とし、hole topology preservation は未対応として明示する。
- operation timeout は CLI と、`SMBee.read(...)`、upload、recursive download/upload/copy/delete の public API に実装済み。provider の旧非escaping overloadも維持済み。残りは Windows / NAS の cancellation 実測。
- shared session の READ cancel は、送信中 task を cancel せず response を drain するよう修正済み。残りは Windows / 他 NAS の互換確認。
- durable handle は未実装ではなく、現時点では unsupported として扱う。

## 0.1.0 の完了条件

- Samba / macOS SMBX / Windows SMB Server の smoke matrix がある。
- README に unsupported features が明記されている。
- 3.0.2 encrypted と 3.1.1 signing/encrypted の authenticated path が CI または scheduled compat で継続検証される。
- `docs/coverage.md` で spec feature と実装・テスト・未実装を辿れる。
- 未対応項目は runtime error / CLI error / README limitation のどれかで明示され、暗黙に失敗しない。

## 推奨順

1. compatibility matrix の実サーバ結果埋め（Windows は pending）。
2. offload-capable server の copychunk と各実サーバ固有機能の smoke。
3. 0.1でunsupportedとしたKerberos / GSSやP3機能は、実要件と検証環境が揃った段階でroadmapから着手。
