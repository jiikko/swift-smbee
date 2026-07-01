# SMBee 実装 TODO 🐝

設計は [docs/architecture.md](docs/architecture.md) / [docs/smb-protocol.md](docs/smb-protocol.md) /
[docs/testing.md](docs/testing.md) を正本とする。各タスクは **その doc を読んでから**着手。
`ⓥ` = 実装中に spec / 実測で確認する判断点。

## 実装状況 (2026-06-29 時点)

**SMB 3.0.2 経路は実 Samba E2E で全 green（署名 CMAC + 暗号 CCM 必須下）**:

- ✅ probe (NEGOTIATE, multi-dialect) / NTLMv2 認証 / SESSION_SETUP / TREE_CONNECT
- ✅ 署名 = AES-128-CMAC (RFC4493 vector) / 暗号 = AES-128-CCM + TRANSFORM_HEADER (RFC3610 vector)
- ✅ ls (QUERY_DIRECTORY) / stat (QUERY_INFO) / cat (READ)
- ✅ mkdir / put(streaming) / mv (SET_INFO rename) / rm / 非空 dir 再帰削除
- ✅ MaxRead/WriteSize 尊重 / FLUSH / async STATUS_PENDING interim 応答処理
- ✅ smbcli probe/ls/stat/cat/mkdir/put/mv/rm(-r) / unit 51 + E2E 3 green / CI(macos-26 unit + ubuntu e2e)

- ✅ C: NTLMv2 **MIC + NTLMSSP_NEGOTIATE_KEY_EXCH** (RC4) + 公式 MS-NLMP §4.2.4 vector。署名/暗号鍵を
  ExportedSessionKey 由来に。実 macOS が MIC を要求しても通る
- ✅ D: **SMBError** 型付きエラー (NTSTATUS→case) + SMBErrorMapper を全 operation に適用 / READ・WRITE・
  再帰削除・paging・PENDING・transport の各ループに **cancellation** (Task.checkCancellation)

**残**:

- ✅ #3: 実 macOS (3.0.2) フル smoke 完了 (2026-06-30)。probe/ls/stat/cat(content round-trip)/
  mkdir/put/mv/rm(--directory) すべて成功 = 署名 CMAC + 暗号 CCM が実 macOS セッション上で正しい。
  通過のため NTLMv2 の 3 バグを修正 (blob header byte order / trailing Z(4) / SPNEGO mechListMIC の
  KEY_EXCH RC4 sealing)。詳細は `issues/001-bug-macos-ntlm-logon-failure.md`。
  注: macOS は `rm` でディレクトリを消すとき NON_DIRECTORY_FILE open を拒否する (Samba は許容) ため
  `smbcli rm --directory` が必要。将来 stat で自動判別する UX 改善余地あり (ぼやき)。
  再発防止メモ: E2E が Samba のみだと「Samba 通過/macOS 拒否」型バグを取りこぼす。NT ハッシュ有効化済み
  macOS アカウントへの手動 smoke を維持すること。
- ✅ rm のディレクトリ自動判定 (2026-06-30): 非 recursive delete で STATUS_FILE_IS_A_DIRECTORY を
  捕まえ directory:true で 1 回自動リトライ。`rm <dir>` が --directory 無しでも macOS で通る。
- ✅ D 残: **切断検出→自動再接続** 完了 (2026-06-30)。transport を factory 化し、接続喪失
  (SMBTransportError.connectionClosed/.socketFailure) 時に idempotent 操作 (probe/ls/stat/cat) のみ
  新 transport で最大 1 回再接続+やり直し。mutation は再試行せず SMBError.connectionLost。
  非接続喪失エラー・CancellationError は即 rethrow。
- ✅ E (2026-07-01 更新): 3.1.1 経路。**GMAC signing-only / GCM encrypted session とも実 Samba E2E green**
  (smb311-signing-required。KDF label null + preauth transcript の 2 バグを修正。commit e3468c9)。
  GCM encrypted session は TRANSFORM_HEADER Flags に cipher id (GCM=0x0002) を入れていたのが原因。
  Flags は `SMB2_TRANSFORM_FLAG_ENCRYPTED = 0x0001` 固定で、cipher は negotiate 済み session state から
  選ぶよう修正。Apple container + `smb311-encrypted-required` profile で API E2E / smbcli smoke green。
- ✅ 公開 read streaming API (2026-06-30): `SMBee.withReadStream(... onChunk:)` (scoped callback)。
  SMBSession.readChunks primitive に集約し既存 `[UInt8]` 一括 read は互換維持。chunk yield 後は透過 retry
  せず connectionLost に昇格。`smbcli cat` も streaming 化 (大ファイルを全量 lift しない)。実機 macOS で
  400KB multi-chunk の round-trip 一致を確認。
- ✅ SMBSession actor 化 (2026-06-30): `final class` → `actor`。wire orchestration state を isolate
  (messageId/transformNonce/keys)。codec/crypto は stateless のまま。
- ✅ ローカル Samba 手動起動スクリプト (2026-06-30): `test/e2e/start-local-samba.sh` (Docker 前提、手動専用)。
- 🧊 obaket 組み込み (SMBClient ラッパーで ObjectStorageProtocol 化) は obaket 側 issue 356/359

---

MVP scope: **SMB 3.0.2 + 3.1.1 / NTLMv2 / negotiated dialect 依存の署名・暗号 /
対象=macOS SMBX(実上限 3.0.2) + Windows SMB Server + Samba**。
3.1.1 は AES-128-GMAC 署名 + AES-128-GCM 暗号（swift-crypto）。3.0.2 は
AES-CMAC 署名 + AES-128-CCM 暗号（in-repo pure-Swift 実装、Linux ビルド維持）。
read 先行 → write。**read 成功を理由に write へ自動 GO しない**（各 Phase 末でレビュー）。

---

## Phase 0 — 足場（transport / codec / crypto feasibility）

- [x] `SMBTransport` protocol を定義（connect / send / receive / close。SMB 概念を持たない）
- [x] `POSIXSocketTransport`（または `NIOTransport`）実装 — Linux+macOS 両対応 ⓥ(POSIX 直書き or SwiftNIO)
- [x] `NWConnectionTransport` 実装 — `#if canImport(Network)` で隔離（macOS 本番）
- [x] in-memory / loopback fake transport（unit test 用）
- [x] direct-TCP framing（4 byte big-endian length, 最上位 byte 0）を SMB 層に実装 ⓥ(transport 内/外)
- [x] SMB2 packet header (64B) encode/decode + round-trip unit test
- [x] crypto feasibility spike（unit）:
  - [x] MD4 を pure Swift 実装 + RFC1320 / MS-NLMP vector
  - [x] HMAC-MD5 / HMAC-SHA256 / SHA-512（swift-crypto）vector
  - [x] AES-128-GCM 暗号化 + **AES-128-GMAC を「平文0 / AAD=msg」の MAC として使えるか**検証（NIST vector）ⓥ
- [x] `swift build` / `swift test` が **Linux でも green**（Network.framework 非依存を確認）
  - 2026-06-29: macOS で `swift build` / `swift test` green。`Network.framework` は
    `NWConnectionTransport` の `#if canImport(Network)` 内に隔離。Linux 実機/CI での実行確認は未実施。
- 撤退判断: 上記 crypto/vector が揃わない / Linux build 不可 → 方針再考

## Phase 1 — probe（NEGOTIATE）

- [x] NEGOTIATE request（dialect 0x0302 / 0x0311 + 3.1.1 用 negotiate contexts: preauth=SHA-512 /
      encryption=AES-128-GCM(+256) / signing=AES-GMAC）encode
- [x] NEGOTIATE response parse（選択 dialect / security mode(signing required) /
      negotiate contexts の選択結果）
- [x] `probe(host:port:)` API → `{dialect, signingRequired, signingAlgo, cipher, preauthHashAlgo, serverGuid}`
- [x] `smbcli probe smb://host[:445]` で表示
- [x] **実測**: macOS SMBX は macOS 26.5.1 でも **3.0.2 上限**。3.1.1 は喋らない。
  - probe(NEGOTIATE) は 3.0.2 macOS に対して成功済み。
- [x] **実測**: Samba が **3.1.1 + GMAC + GCM** を交渉するか ⓥ
  - 2026-06-30 実装レビュー追記: 現状の `SMBNegotiateCodec.encodeEncryptionData()` は
    AES-128-CCM だけを提示している一方、3.1.1 authenticated path は AES-128-GCM を必須として
    guard している。3.1.1 実測前に request context を設計どおり AES-128-GCM 優先
    (+必要なら AES-256-GCM / AES-128-CCM fallback) へ修正し、unit fixture を追加する。
  - 2026-06-30: NEGOTIATE encryption context を AES-128-GCM 優先 + AES-128-CCM fallback
    に修正し、request fixture で context payload を検証。残: 実 Samba 3.1.1 での交渉確認。
  - 2026-06-30: `.github/workflows/samba-compat.yml` と `test/e2e/smb/smb311-*.conf` を追加。
    `smb311-encrypted-required` で 3.1.1 + GMAC + GCM の probe / authenticated E2E を
    workflow_dispatch / schedule で確認できる状態にした。残: GitHub Actions 上の初回実行結果を記録する。
  - 2026-07-01: Apple container + Ubuntu 24.04 Samba + `smb311-encrypted-required` で
    `dialect: 0x0311`, `signing: 0x0002`, `cipher: 0x0002`, `preauthHash: 0x0001` を実測。
    `.github/workflows/e2e.yml` の API E2E matrix に PR / push で走る negotiate-scope lane を追加。
- [x] 既知課題: Samba 3.1.1 response の parser が `truncated` になるバグを調査
  - 2026-06-30: NEGOTIATE context parser が「最後の context も 8-byte padding あり」と仮定していた
    ため、最後の context が unpadded の response で `truncated` になり得た。最終 context は padding
    なしでも受けるよう修正し、unit fixture 追加済み。実 Samba packet での再確認は上の実測タスクに含める。
- 撤退判断: Samba が GMAC/GCM を交渉しない & 設定で出せない → 3.1.1 側 scope 見直し

## Phase 2 — 認証（NTLMv2 / SPNEGO）+ TREE_CONNECT

- [x] SPNEGO 最小ラップ（MS-SPNG / RFC4178）
- [x] NTLMv2: NEGOTIATE(type1) → CHALLENGE(type2) parse → AUTHENTICATE(type3)
  - [x] NTOWFv2 / NTProofStr / AV pair(target info) / timestamp / clientChallenge / MIC（UTF-16LE）
  - [x] vector test（MS-NLMP / RFC）
- [x] SESSION_SETUP の複数往復（STATUS_MORE_PROCESSING_REQUIRED）
- [ ] **SMB 3.1.1 crypto framing**:
  - [x] preauth integrity: NEGOTIATE+SESSION_SETUP の SHA-512 running transcript
  - [x] SP800-108 counter KDF（HMAC-SHA256）で signing/encryption/application key 導出（label/context ⓥ）
  - [x] signing = AES-GMAC を packet に適用 / 検証
    - 2026-06-30: primitive と KDF は実装済み。GMAC 署名 packet の nonce/signature field レイアウトは
      実 packet fixture か 3.1.1 サーバで確認してから配線する。
    - 2026-06-30 実装レビュー追記: `sendSigned` は GMAC signing 単体を未配線、`verifySigned` は
      CMAC 固定。暗号化済み transform response は検証できるが、3.1.1 signing-only session や
      unencrypted response verification は未対応。GMAC nonce source / header signature field /
      response verify を packet fixture で固める。
    - 2026-06-30: MS-SMB2 v20260413 PDF を `docs/references/ms-smb2.pdf` に保存し、
      §3.1.4.1 / §3.1.5.1 の nonce 仕様 (MessageId + sender/CANCEL flags) に従って
      AES-GMAC signing-only を配線。unit で nonce / signature / session read path を検証。
      `smb311-signing-required` profile も authenticated API E2E 対象に変更。残: 実 Samba 3.1.1
      workflow_dispatch 初回実行結果を記録する。
    - 2026-07-01 **実測 (Apple container + Samba `smb311-signing-required`)**: probe は成功
      (dialect 0x0311 / signing 0x0002 GMAC 交渉 OK) だが、**authenticated 全 op が
      `invalidValue("SMB signature verification failed")` で失敗** (TreeConnect+List /
      Write / ShareDiscovery の 3 test。`SMBClient.swift:436` / `:479` の verify 経路)。
      GMAC signing-only 経路は unit green だが実 Samba 3.1.1 では通らない = 循環テスト型の
      未検出バグ。真因候補: 3.1.1 signing key 導出 / GMAC nonce レイアウト / response の
      signature field zeroing / verify 側 AAD。**要デバッグ (未着手)**。
    - 2026-07-01 **解決**: wire trace で TREE_CONNECT response = STATUS_ACCESS_DENIED =
      サーバが署名を拒否 = signing key 誤りと特定。真因 2 点: (1) 3.1.1 KDF label
      (SMBSigningKey ほか 4 種) が終端 null を欠き 3.0.x と非対称に 1 null で導出していた
      (MS-SMB2 §3.1.4.2)。(2) preauth hash に最終 SESSION_SETUP success 応答まで畳み込んで
      いた (key 導出は最終 request まで; §3.2.5.3.1)。両修正で **smb311-signing-required
      E2E green** (実 Samba)。KDF unit vector を実サーバ検証済み正値へ更新。commit e3468c9。
  - [x] encryption = TRANSFORM_HEADER + AES-GCM（nonce/AAD/tag レイアウト ⓥ）
    - 2026-06-30: 12-byte nonce + 16-byte TRANSFORM_HEADER nonce field padding / AAD / tag fixture を追加し、
      session の 3.1.1 暗号化・復号分岐へ配線。
  - [x] preauth transcript / KDF / transform header の fixture test
- [x] **SMB 3.0.2 crypto framing**:
  - [x] signing = AES-CMAC（RFC4493）を pure-Swift 実装または pure-Swift cross-platform lib で対応
  - [x] encryption = AES-128-CCM（RFC3610 / NIST SP800-38C）を pure-Swift 実装または pure-Swift cross-platform lib で対応
  - [x] CommonCrypto は Linux 非対応なので使わない
- [x] TREE_CONNECT（`\\host\share`）
- 撤退判断: NTLMv2 SESSION_SETUP が 2〜3 日 opaque に失敗（packet capture でも追えない）→ 方針再考

## Phase 3 — read

- [x] CREATE（open。desired access / share access / disposition=OPEN）
- [x] QUERY_DIRECTORY（`FileIdBothDirectoryInformation`）反復 → STATUS_NO_MORE_FILES = `list`
- [x] QUERY_INFO（size/mtime/is-dir）= `stat`
- [x] READ（offset/length）反復 = `read`（full / range）
  - [x] download 完全性: 受信 byte 積算を `stat().size` と照合
- [x] CLOSE / handle 寿命管理
- [x] `smbcli ls / stat / cat [--range]`
- [x] 大 dir は全件メモリ集約（known limitation。pageToken 化は後回し）
- [x] large file read（>4 GiB）: 公開 streaming read API `SMBee.withReadStream` で全量 lift せず読める。
      gated E2E test (`SMBEE_E2E_LARGE=1`) 追加済。**実 >4GiB 転送の実行確認は要 4GiB サーバ (未実行)**
- 撤退判断: ls/stat/cat が macOS/Samba で安定しない → 方針再考

## Phase 4 — write

- [x] CREATE(disposition: overwrite=false→FILE_CREATE / true→FILE_OVERWRITE_IF ⓥ) + WRITE(offset) 反復
  - [x] file URL を memory に lift しない streaming write
- [x] mkdir（CREATE dir, FILE_CREATE）
- [x] rename / move（SET_INFO `FileRenameInformation`, ReplaceIfExists）— 同一 share / atomic 挙動 ⓥ
- [x] delete（SET_INFO `FileDispositionInformation`）/ 空 dir rmdir / 非空は per-file 再帰
- [x] `smbcli put / mkdir / mv / rm`

## Phase 5 — E2E（コンテナ Samba）

- [x] E2E test target（`SMBEE_E2E` env gate）— probe-only（NEGOTIATE: 3.0.2 / signing required /
      3.1.1 negotiate contexts なし）
- [x] Samba イメージ + smb.conf 確定（macOS SMBX ミラーとして SMB3_02 上限、signing required）
- [x] `.github/workflows/e2e.yml` の TODO を埋め、push トリガを有効化
- [x] ローカル Apple container 起動スクリプト（手動）

## smbclient としての追加 backlog（MVP 後）

実装済みの `probe/ls/stat/cat/mkdir/put/mv/rm` は最小 SMB client としては動くが、汎用 smbclient /
ファイルブラウザ基盤としては下記が未実装。obaket 連携や GUI consumer の要件が出た順に着手する。

- [x] share discovery: `TREE_CONNECT` 前にサーバ上の共有一覧を取る API / `smbcli shares`
  - 2026-06-30 調査: SMB2 単体の既存 command set では足りず、現実的には `IPC$` へ TREE_CONNECT →
    `srvsvc` named pipe CREATE → DCE/RPC bind → SRVSVC `NetrShareEnum` が必要。MS-RAP は古く、
    DFS referral は share enumeration そのものではないため、第一候補は SRVSVC over named pipe。
  - 着手前に必要: SMB2 IOCTL または named pipe READ/WRITE の fixture、DCE/RPC bind/request/response codec、
    `SHARE_INFO_1` 以上の NDR decode、macOS SMBX / Samba の実 packet capture。
  - 2026-06-30: 実装 scope を `issues/006-share-discovery-srvsvc.md` に分離。SRVSVC over IPC$ と
    fixture 要件を完了条件として明文化。
  - 2026-06-30: `SMBee.listShares` / `SMBClient.listShares` / `smbcli shares` の入口を追加。
    現時点では `SMBError.unsupported(operation: "SHARE_DISCOVERY_SRVsvc")` を返す。残:
    `issues/006-share-discovery-srvsvc.md` の DCE/RPC + SRVSVC 実装。
  - 2026-06-30: SRVSVC over IPC$ の最小実装を追加。`srvsvc` named pipe に DCE/RPC bind →
    `NetrShareEnum` Level 1 を送り、`SMBShareInfo(name/type/comment)` を decode。unit fixture と
    Samba E2E/CLI smoke を追加。残: macOS SMBX 手動 smoke、guest/anonymous 方針は認証 backend 拡張時に扱う。
  - 2026-07-01 堅牢化 (commit a155b7f): DCE/RPC 複数 fragment reassembly (PFC_LAST_FRAG) と
    FSCTL_PIPE_TRANSCEIVE の STATUS_BUFFER_OVERFLOW → pipe 継続 read を実装。従来は先頭 fragment のみ
    decode し share 数が多いと黙って切り捨てていた。150 share の Samba で全列挙を実測 (wire trace で
    部分応答 + 継続 READ + reassembly 確認)。unit fixture 追加。**API 本体は完了**。残は macOS SMBX 手動
    smoke (Tier 3 / user-gated) と guest/anonymous policy (認証 backend 拡張時)。
- [x] download API / `smbcli get`: remote file を local file へ streaming 保存
  - 2026-06-30: `SMBee.download` / `SMBClient.download` / `smbcli get` を追加。既存 `withReadStream` を使い、
    local temp file へ streaming 書き込み後に move/replace。`--no-overwrite` 対応。Samba E2E に round-trip
    assertion 追加。
- [x] copy primitive: remote→remote copy / local→remote directory upload / remote→local directory download
  - 2026-07-02 実装確認: 下記 2026-06-30〜07-01 の記録どおり `SMBee.copy` / `copyDirectory` /
    `uploadDirectory` / `downloadDirectory` (server-side copychunk fallback 込み) + `smbcli cp/put/get (-r)`
    が実装済み。recursive safety (自己再帰防止 + max depth) も 2026-07-01 (issue 236 partial) で追加済み。
    checkbox のみ未チェックだったため [x] 化。残の streaming traversal / atomicity は 236 の defer 側。
  - 2026-06-30: 同一 share 内 remote file → remote file の client-side copy API / `smbcli cp` を追加。
    既存 READ/WRITE で streaming copy し、Samba E2E に round-trip assertion 追加。
  - 2026-06-30: recursive local directory upload (`SMBee.uploadDirectory`, `smbcli put -r`) と
    remote directory download (`SMBee.downloadDirectory`, `smbcli get -r`) を追加。既存 operation の組み合わせで
    実装し、Samba E2E に directory round-trip assertion 追加。
  - 2026-06-30: remote directory → remote directory copy (`SMBee.copyDirectory`, `SMBClientSession.copyDirectory`,
    `smbcli cp -r`) を追加。既存 READ/WRITE + QUERY_DIRECTORY の client-side recursive copy で実装し、
    unit と Samba E2E smoke に assertion 追加。
  - 2026-07-01 (commit f502d96): server-side copy (`FSCTL_SRV_COPYCHUNK`) 実装 + 対応可否実測。
    `copyFile` が resume key → copychunk_write (chunk limit 交渉付き) を先に試し、非対応時は
    client-side READ/WRITE に透過フォールバック。**実測**: 当 Samba container の FS は copychunk
    offload 非対応で `STATUS_INVALID_DEVICE_REQUEST` (StructureSize=9 error response) を返すため
    fallback で動作 (300KB cp round-trip 一致)。offload 対応サーバでは server-side path を使う。
    デバッグで 3 バグ修正 (resume key buffer size / IOCTL error-format 許容 / fallback 配線)。
    error-format fallback の unit regression test 追加。
  - 2026-06-30 実装レビュー追記: recursive copy/delete/download は directory page を配列集約してから
    再帰している箇所がある。大規模 tree 向けに streaming traversal 化し、source が destination
    配下にある場合の自己再帰防止、最大 depth、同名衝突時の partial rollback 方針を決める。
  - 2026-06-30: `SMBSession.copyDirectory` / `deleteRecursively` は `queryDirectory(... onEntry:)`
    の callback traversal に変更し、directory entry 配列集約を避けるよう修正。残:
    one-shot `downloadDirectory` の session 境界を含む streaming traversal 化と安全策。
- [ ] recursive operation safety / transfer atomicity
  - copy/delete/download/upload の recursive 系は実装済みだが、汎用 smbclient としては failure 中断時の
    partial tree の扱い、同名衝突時の rollback/skip/overwrite policy、最大 depth、source が destination
    配下にある場合の自己再帰防止を API/CLI option として明示する。
  - local download は temp file → move/replace で単一 file の atomicity を確保済み。directory download /
    upload / remote copy は directory 単位の atomicity は無いので、resume / verify / cleanup policy を
    別タスクとして設計する。
  - 2026-07-01 (codex-drive): **自己再帰防止 + 最大 depth cap を実装**。
    `SMBError.invalidRecursion(String)` を追加。`SMBPath.validateDirectoryCopyTarget`
    (toPath が fromPath と同一/子孫なら reject、case-insensitive、`source\` 境界で /a vs /ab 誤検出なし) を
    copyDirectory 入口で、`validateRecursionDepth`(`maxRecursionDepth=64`)を
    copyDirectory/deleteRecursively/downloadDirectory/uploadDirectory の再帰に配線。exit code は 1 に分類。
    Linux 138 / macOS 141 unit green。
    **残 (設計判断ゆえ本タスクでは未着手)**: failure 中断時の partial tree の rollback/skip policy、
    同名衝突の overwrite policy の option 化、directory 単位 atomicity、resume/verify/cleanup。
- [x] directory pagination: `list` の全件メモリ集約を避ける streaming / pageToken API
  - 2026-06-30: `SMBee.withDirectoryStream` / `SMBClient.withDirectoryStream` を追加。`SMBSession`
    は同一 directory handle へ `QUERY_DIRECTORY` を初回 restart scan、以後 continuation で
    `STATUS_NO_MORE_FILES` まで反復する。既存 `list` は互換維持のため collector で配列集約。
    `smbcli ls` は streaming 表示に変更。unit で continuation flag と multi-page stream を検証。
- [x] persistent session API: 複数 operation で TCP/session/tree を再利用する公開 handle
  - 2026-06-30: `SMBee.connect` / `SMBClient.connect` / `SMBClientSession` を追加。同一 tree 上で
    `list` / directory stream / `stat` / `read` / read stream / `mkdir` / `upload(data)` / `copy` /
    `rename` / `delete` を再利用できる。`SMBSession` の wire serializer 前提で安全側に逐次化。
    自動再接続は従来の static one-shot API 側に限定。
  - 2026-06-30 手動 smoke: `swift run smbcli ls smb://koji@127.0.0.1/koji` と、実 SMB サーバ上の
    一時 directory で `mkdir` / `put` / `cat` / `get` / `cp` / `put -r` / `get -r` / `rm -r` を確認。
    同等の command smoke を `.github/workflows/e2e.yml` に追加。
- [x] authentication options: NT hash 入力 / password provider callback / keychain 連携 / guest or anonymous の扱い
  - secret を log に出さない方針は維持。CLI は `SMB_PASSWORD` 以外の安全な入力方法を追加する。
  - 2026-06-30: CLI に `--password-stdin` を追加。URL 埋め込み password → stdin → `SMB_PASSWORD` の
    優先順位で `ls/stat/cat/get/mkdir/put/mv/cp/rm` が共通利用する。
  - 2026-06-30: NT hash credential を追加。`SMBCredential(username:ntHash:domain:)` と CLI `--nt-hash` /
    `SMB_NT_HASH` に対応し、平文 password 入力なしで NTOWFv2 を導出できる。残: provider callback /
    keychain / guest or anonymous。
  - 2026-06-30 実装レビュー追記: `SMBCredential` は source compatibility のため `password: String`
    を保持しており、NT hash credential では空文字を入れている。将来は `password` 露出を避ける
    credential enum / provider callback へ移行し、deprecation plan を用意する。
  - 2026-07-01 (commit c8172c3): **password provider callback** と **guest/anonymous** を実装。
    `SMBCredentialProvider` (lazy closure) を persistent `connect` に、`SMBCredential.anonymous` /
    CLI `--anonymous`/`--guest` を追加。NTLM anonymous Type3 + signing 不可時の unsigned フォールバック。
    実 Samba guest E2E で anonymous ls/cat/stat 成功 (test/e2e/smb/guest.conf)。
    **残 (本ライブラリ core 対象外): keychain 連携 = macOS Security.framework 依存で consumer 側
    (obaket/smbcli) の関心。Kerberos/GSS = MVP scope 外 ([`issues/005`](issues/005-auth-macos-finder-equivalent-smb-auth.md))。**
    ライブラリは credential-agnostic (password/ntHash/provider/anonymous) を維持する方針。
  - 2026-07-01: `SMBCredentialProvider` を one-shot API 全体 (`listShares` / `list` / `stat` / `read` /
    stream / download / upload / copy / metadata / rename / delete) に拡張。Keychain 等の consumer 依存
    credential source は provider に閉じ込められるため、core の authentication options は完了扱い。
- [ ] path handling: SMB パス正規化・`.`/`..`・区切り文字・URL percent decoding/encoding の仕様化
  - 2026-06-30: CLI URL parser で share/path component と userinfo の percent decode を実装。
    path component の `.` / `..` と decoded separator (`/` / `\`) は拒否し、URL `/` のみを
    SMB path separator `\` へ変換する方針を `docs/smb-protocol.md` に明記。unit 追加済み。
  - 2026-06-30 実装レビュー追記: 公開 API (`SMBee.* path:` / `SMBClientSession.* path:`) は
    URL parser を経由しないため、`.` / `..` / separator / 空 share などの検証が統一されていない。
    `SMBPath` / `SMBShareName` 型または共通 normalizer を導入し、CLI と API の挙動を揃える。
  - 2026-06-30: `SMBPath` / `SMBShareName` を追加し、URL parser と CREATE / SET_INFO rename /
    TREE_CONNECT codec の入口で共通 validation を通すようにした。公開 API の String surface は維持。
    unit で `.` / `..` / 空 component / share separator を検証。
  - macOS Finder/Samba での Unicode normalization 差も実測する。
- [x] metadata operations: chmod 相当ではなく SMB/NTFS 属性として readonly/hidden/system/archive、
      create/access/modify/change time の read/write
  - `QUERY_INFO` / `SET_INFO` の information class を拡張。
  - 2026-06-30: `SMBDirectoryEntry` / `SMBFileStat` に raw SMB file attributes (`UInt32`) を追加し、
    `QUERY_DIRECTORY` / `QUERY_INFO(FileNetworkOpenInformation)` decode 結果として返すようにした。
    残: create/access/change time と `SET_INFO` による属性・時刻更新。
  - 2026-06-30: `SMBFileStat` に creation/access/change time を追加し、
    `SMBFileMetadataUpdate` + `SMBee.updateMetadata` / `SMBClient.updateMetadata` /
    `SMBClientSession.updateMetadata` で FileBasicInformation SET_INFO を送れるようにした。
    unit で FileNetworkOpenInformation decode と FileBasicInformation encode を検証。
- [x] symlink / reparse point / DFS referral の扱い
  - follow するか entry metadata として返すか、recursive delete/copy の安全策を先に決める。
  - 2026-06-30 実装レビュー追記: 現状の directory entry は `isDirectory` しか返さず、reparse point /
    symlink / DFS referral を判別できない。recursive delete/copy/download は cycle 検出なしで
    directory 扱いする可能性があるため、FileAttributes / FileId / reparse tag を metadata として
    返す設計を先に入れる。
  - 2026-06-30: FileAttributes は `SMBDirectoryEntry.attributes` で返せるようになった。残:
    FileId / reparse tag の取得と recursive operation での traversal policy。
  - 2026-06-30: `FileIdBothDirectoryInformation` の FileId を `SMBDirectoryEntry.fileId` として返し、
    `isReparsePoint` helper を追加。recursive copy/delete/download は reparse point を directory として
    辿らない安全側 policy にした。残: reparse tag 本体の取得 (`FileAttributeTagInformation` など) と
    DFS referral の扱い。
  - 2026-07-01 (codex-drive): **reparse tag 取得を実装**。QUERY_INFO FileAttributeTagInformation
    (FILE class 35) の decoder を追加し、stat が **reparse bit のある時だけ**追加 query して
    `SMBFileStat.reparseTag: UInt32?` を埋める (通常ファイルは追加往復なし)。`SMBReparseKind`
    (symlink 0xA000000C / mountPoint 0xA0000003 / dfs 0x8000000A / nfs / other) + `reparseKind`
    computed。`smbcli stat` に reparseTag/reparseKind (human + --json)。fixture unit で decode/kind
    マッピングを検証。Linux 149 / macOS 152 unit green。
    残: **DFS referral の扱い** (FSCTL_DFS_GET_REFERRALS。別 protocol・大タスク)。symlink target 解決
    (FSCTL_GET_REPARSE_POINT) も未実装。
  - 2026-07-01 (codex-drive): **DFS referral 取得を実装**。IOCTL FSCTL_DFS_GET_REFERRALS
    (0x00060194) を IPC$ tree + no-file FileId(0xFF×16) で送出。REQ_GET_DFS_REFERRAL encode +
    RESP_GET_DFS_REFERRAL decode (V3/V4 = entry 先頭相対 offset で DFSPath/AlternatePath/
    NetworkAddress を全 offset/len 検証付き parse、V1/V2/未知は Size でスキップ、NameListReferral は
    best-effort)。`SMBDfsReferralResult`/`SMBDfsReferral` 公開型 + `SMBee.dfsReferral` +
    `smbcli dfs` (--json)。MS-DFSC 準拠の fixture unit で検証。Linux 153 / macOS 156 unit green。
    **注**: 実 msdfs サーバが手元に無いため **unit fixture + 仕様精読が検証の主体** (実 DFS E2E は未実施)。
    symlink target 解決 (FSCTL_GET_REPARSE_POINT) と DFS を辿った先の path 再解決は defer (この項目としては
    reparse tag + referral 取得で [x])。
- [x] filesystem / volume information
  - `smbcli df` / API として share の total/free/available capacity、filesystem name、volume label、
    filesystem attributes / max component length を取得する。`QUERY_INFO(FileFsSizeInformation /
    FileFsAttributeInformation / FileFsVolumeInformation)` 相当。
  - upload / copy 前の空き容量チェックや GUI の容量表示で必要。server 実装差が出やすいため Samba /
    macOS SMBX / Windows で fixture または smoke を取る。
  - 2026-07-01 (commit 4c420a0, codex-drive): QUERY_INFO を InfoType=0x02 (FILESYSTEM) で送れるよう
    parametrize (既存 stat wire 不変)。decoder = FileFsFullSizeInformation(7) / FileFsAttributeInformation(5)
    / FileFsVolumeInformation(1)。`SMBVolumeInfo` + `SMBee.volumeInfo` / `SMBClientSession.volumeInfo` +
    `smbcli df` (--json)。fixture unit + 実 Samba E2E (df assertion) green。
    残: macOS SMBX / Windows / NAS の smoke (実機必要)。
- [x] change notification / directory watch
  - ファイルブラウザ基盤として、ディレクトリ変更検知 (`CHANGE_NOTIFY`) の API を検討する。
    long-poll/async response、cancellation、再接続時の再購読、overflow 時の full rescan 方針が必要。
  - CLI では `smbcli watch smb://...` 相当。MVP の copy/read/write には不要なので後回し。
  - 2026-07-02 (codex-drive): **SMB2 CHANGE_NOTIFY (command 15) を実装**。専用 long-poll 受信
    (`signedLongPollWireTransaction`/`receiveLongPoll`) で STATUS_PENDING を打ち切らず実 notification まで
    待機、cancel は M2 の transport close-on-cancel で解除、resubscribe ループ。overflow
    (STATUS_NOTIFY_ENUM_DIR) は `.overflow` として callback へ (full-rescan は呼び出し側)。公開型
    `SMBFileChange`/`SMBFileChangeAction`/`SMBChangeNotifyFilter`(OptionSet)/`SMBChangeNotifyEvent`。
    `SMBClientSession.withChangeNotifications` / `SMBee.withChangeNotifications` (callback) + `smbcli watch`
    (`-r` で watch-tree)。fixture unit + **実 Samba E2E** (dir watch → file 作成 → ADDED 通知を bounded 受信) green。
    残: `smbcli watch` の `--json` は未実装 (human のみ)。再接続時の再購読は同一 session 前提 (自動再接続は未配線)。
- [x] ACL / owner / SID metadata
  - `QUERY_SECURITY` / `SET_SECURITY`。MVP では扱わないが、管理系 smbclient としては必要。
  - 2026-07-01 (codex-drive): **READ (QUERY_SECURITY) を実装**。QUERY_INFO に
    `additionalInformation: UInt32` を追加 (既存 stat/df wire は default 0 不変)。InfoType=0x03 で
    AdditionalInformation=OWNER|GROUP|DACL(0x1|0x2|0x4) を送り、self-relative SECURITY_DESCRIPTOR /
    SID (6-byte BE authority → "S-1-..") / ACL / ACE を境界検証付きで parse。公開型
    `SMBSecurityInfo` (ownerSID?/groupSID?/dacl?/controlFlags) + `SMBAccessControlEntry`
    (type/flags/accessMask/trusteeSID?)。READ_CONTROL 付き `.querySecurity(path:)` open。
    `SMBClientSession.securityInfo` / `SMBee.securityInfo` + `smbcli acl` (--json)。未知/OBJECT ACE は
    mask だけ保持し AceSize でスキップ。fixture unit + 実 Samba E2E (ownerSID != nil / DACL ACE>=1) green。
  - 2026-07-02 (codex-drive): **SET_SECURITY (DACL write) を実装**。SET_INFO を InfoType/
    AdditionalInformation 指定可に parametrize。self-relative SECURITY_DESCRIPTOR/SID/ACL/ACE encoder
    (decode と round-trip)。WRITE_DAC 付き `.setSecurity(path:)` open。read-modify-write (owner/group 保持)。
    **自ロックアウト防止 guard** (`validateWritableDACL`: 空 DACL / ACCESS_ALLOWED 皆無を reject、`force` で解除、
    trusteeSID nil の ACE は書き戻せず reject)。`SMBClientSession.setSecurityInfo(path:dacl:force:)` /
    `SMBee.setSecurityInfo` + `smbcli setacl`。fixture unit + **実 Samba round-trip E2E** green。
    観測: **Samba は POSIX-ACL backing のため access mask を正規化** (要求 0x00020000 → read-back 0x00120089)。
    write 自体は成功 (追加 SID の ACE が反映) を実測確認、round-trip は mask-exact ではない旨を doc に明記。
  - **残 (defer)**: SACL は特権要求のため対象外 (AdditionalInformation に SACL bit を立てていない)。
    owner/group の書き換えも今回対象外 (DACL のみ)。
- [ ] locking / durable handle / lease / oplock の扱い
  - concurrent clients や大ファイル操作の堅牢性向け。最初は明示的に unsupported としてエラーを設計する。
- [ ] multi-share / multi-tree session reuse
  - 現在の persistent `SMBClientSession` は 1 share = 1 TREE_CONNECT 前提。汎用 smbclient では同一
    authenticated session 上で複数 share / IPC$ / DFS target を扱いたい場面がある。
  - API は `SMBServerSession` (session-level) と `SMBTreeSession` (tree-level) に分けるか、
    既存 `SMBClientSession` を維持して one-shot API だけで複数 share を扱うかを設計する。
- [x] dialect / encryption policy の整理
  - 2026-06-30 実装レビュー追加: NEGOTIATE は 2.0.2 / 2.1 も提示するが authenticated path は
    3.0+ だけを受ける。probe 専用 dialect と authenticated dialect policy を分けるか、
    authenticated connect では 3.x のみ提示する。
  - 2026-06-30: NEGOTIATE codec に dialect list を渡せるようにし、probe は従来通り
    2.0.2/2.1/3.x、authenticated connect は 3.0/3.0.2/3.1.1 のみ提示するよう分離。
  - 2026-06-30 実装レビュー追加: SESSION_SETUP 後は encryption key があれば常に transform 送信する。
    server global capabilities / tree share flags / encryption required を見ていないため、暗号非対応 share や
    signing-only 運用との互換性が不明。TREE_CONNECT response の share capabilities / flags を parse し、
    暗号必須・暗号可能・署名のみの policy を明示する。
  - 2026-06-30: TREE_CONNECT response の share type / flags / capabilities / maximal access を parse。
    share flags/capabilities が encryption required を示すのに encryption key が無い場合は protocolError。
    3.1.1 signing-only は cipher nil のまま signed packet で運用し、encrypted profile は従来どおり transform。
- [ ] SMB2 credit / chunk sizing / multi-credit
  - 2026-06-30 実装レビュー追加: read/write chunk size は negotiated MaxRead/WriteSize と transform overhead
    で抑えているが、CreditCharge / CreditRequest / CreditResponse を管理していない。大きな IO や
    multi-credit server での挙動を MS-SMB2 と実 packet で確認し、必要なら messageId/credit allocator を
    `SMBWireTransactionGate` の後継として設計する。
- [ ] resume / sparse file / integrity verification
  - `get` / `put` / `cp` は streaming だが中断後 resume は未実装。remote/local size と mtime/hash
    照合、range read/write による resume、既存 partial file の扱いを設計する。
  - sparse file / allocation size / zero range の扱いも未実装。巨大 VM image や backup 用途では
    通信量と local disk 使用量に影響するため、`FSCTL_SET_ZERO_DATA` 等を調査する。
  - 暗号化 transport の integrity とは別に、consumer visible な transfer verification (size / optional hash)
    を API/CLI option として検討する。
- [x] session lifecycle: TREE_DISCONNECT / LOGOFF
  - 2026-06-30 実装レビュー追加: close は TCP close のみで、TREE_DISCONNECT / LOGOFF を送らない。
    persistent session API の `close()` で graceful teardown するか、best-effort に留めるかを決める。
  - 2026-06-30: `SMBClientSession.close()` は best-effort で TREE_DISCONNECT → LOGOFF を送ってから
    transport close するよう修正し、二重 close で再送しない unit test を追加。
  - 2026-07-01 (commit eec6b34): ワンショット静的 API (`withSession` 成功経路) も bare closeTransport
    から best-effort disconnect (TREE_DISCONNECT → LOGOFF → close) に統一。error 経路は session が
    suspect なので bare close 維持。実 Samba で one-shot ls の teardown 送出を確認。
- [x] timeout / progress / cancellation API の整備
  - read/write loop は cancellation 済み。公開 API と CLI に progress callback / transfer rate / timeout を足す。
  - 2026-06-30 実装レビュー追記: POSIX transport は blocking `connect` / `recv` / `send` を
    `Task.detached` で包むため、Task cancellation だけでは OS blocking call を即中断できない。
    socket timeout / nonblocking IO / close-on-cancel の設計が必要。NWConnection も continuation 多重 resume
    防止を含めた cancellation test を追加する。
  - 2026-07-01 実装 (M1-M5, codex-drive + Linux/macOS 両検証):
    - M1: NWConnectionTransport の continuation 二重 resume を NWContinuationResumer で修正
      (.ready 後の .cancelled/.failed で crash していた)。loopback NWListener で cancellation test。
    - M2: POSIXSocketTransport に socket timeout (nonblocking connect+poll / SO_RCVTIMEO/SO_SNDTIMEO) と
      close-on-cancel を実装。**Linux は blocking recv 中の fd を close() しても起きない**ため
      cancel 経路で shutdown(SHUT_RDWR) して起こす。fd を NSLock 保護。
    - M3: 公開 API (facade 19 func + SMBClient) に timeout: Duration? を配線 (socket-level, operation
      deadline ではない)。
    - M4: SMBTransferProgress (bytesTransferred/totalBytes?/bytesPerSecond) + onProgress を read/upload/
      download に追加。ContinuousClock でレート算出。
    - M5: smbcli に --timeout (TransportOptions) と get/put の --progress (stderr, \r live 更新) を配線。
    - 残: 全操作 deadline (per-operation withTimeout ラップ) は未対応 (今回は socket-level のみ)。
      put --progress はファイルを Data に読み込む経路 (streaming ではない) = 大ファイルでメモリ増。
- [x] CLI UX: `--password-stdin` / interactive password prompt / `--json` / exit code 表 / `--debug` redaction policy
  - 自動化用途と人間操作の両方を想定。
  - 2026-07-01: interactive password prompt を実装。`readPassword` の最終フォールバックとして
    URL/`--password-stdin`/`SMB_PASSWORD` が全て無く **stdin が TTY (`isatty(STDIN_FILENO)`)** の場合のみ
    `getpass` で echo 無効入力を促す。非TTY (パイプ/CI) では発火せず既存の ValidationError 経路を維持。
    Linux の `stdin` グローバル concurrency 非安全を避け `STDIN_FILENO` 定数を使用。Linux/macOS build+unit green。
  - 2026-06-30 実装レビュー追記: `SMBEE_DEBUG=1` は raw SMB packet を出す。SESSION_SETUP 以降は
    security blob / encrypted payload / signing material に近い情報を含み得るため、command type ごとの
    redaction policy と `--debug` / `--trace-wire` の分離を決める。
  - 2026-06-30: `SMBEE_DEBUG=1` は packet label と byte count のみに redaction し、raw hex は
    `SMBEE_TRACE_WIRE=1` 併用時だけ出すよう分離。残: CLI flag としての `--debug` / `--trace-wire`。
  - 2026-06-30: `smbcli probe/ls/stat/cat/get/mkdir/put/mv/cp/rm` に `--debug` と
    `--trace-wire` を追加。`--trace-wire` は `--debug` を暗黙に有効化し、既存の env gate
    (`SMBEE_DEBUG` / `SMBEE_TRACE_WIRE`) に接続する。
  - 2026-07-01 (commit 62e0e48): `--json` (probe/ls/stat/shares) と exit code 表を実装。
    JSON は sortedKeys / hex 文字列 / ISO8601、human 出力は不変。SMBError → distinct exit code
    (0/1/2/3/4/5) を exhaustive switch でマッピングし docs/smbcli-exit-codes.md に記載。unit +
    実 Samba live check 済み。**残: interactive password prompt (TTY 依存) のみ**。
- [x] CLI batch / wildcard ergonomics
  - `smbclient` 互換の対話 shell までは MVP 外だが、運用用途では wildcard (`*.log`) / glob、
    `mget`/`mput` 的な複数 path、`--include`/`--exclude`、dry-run、確認 prompt が欲しくなる。
  - shell 側 glob と SMB 側 pattern matching の責務を分け、URL percent decode / path validation と
    矛盾しない CLI surface を設計する。
  - 2026-07-01 (codex-drive): **`smbcli mget` / `mput` を実装**。設計 = **glob は client-side**
    (SMB path に wildcard を埋めず、remote/local dir を列挙 → `fnmatch(3)` で filter → 各ファイル転送。
    既存の URL/path validation が wildcard を拒否する方針と矛盾させない)。単一 dir 直下の非ディレクトリのみ、
    `--exclude` (repeatable) / `--dry-run` / `--no-overwrite`。0 match は exit 0 + stderr 警告。
    glob helper (`globMatches`/`batchGlobEntries`) を切り出して unit test。転送は既に E2E 実証済みの
    list/download/upload を合成。Linux 160 / macOS 163 unit green (test target が smbcli を import)。
    残 (defer): recursive (`-r`)、`--create-dirs`、個別ファイル progress、対話 shell、確認 prompt
    (mget/mput は非破壊なので --dry-run で代替)。
- [ ] compatibility matrix: macOS SMBX / Samba / Windows Server / NAS (Synology/QNAP 等)
  - dialect/signing/encryption/quirk を記録し、手動 smoke 手順を docs 化する。
  - 2026-07-01 現状: Samba は 3.0.2 encrypted-required / 3.1.1 signing-required /
    3.1.1 encrypted-required / guest profile を自動・ローカル E2E で確認済み。macOS SMBX は 3.0.2 smoke
    済み。**Windows Server / NAS は未実測**なので、smbclient として名乗る前に read/write/share discovery/
    metadata/copy fallback の Tier 3 smoke を追加する。
- [ ] packaging / API stability
  - SwiftPM library と CLI は動くが、SemVer、public API の source compatibility、deprecated credential
    surface (`SMBCredential.password` 露出)、DocC/API examples、binary/release artifact の方針は未整理。
  - consumer (obaket / GUI) が依存し始める前に public 型の命名、Sendable、error taxonomy、cancellation
    semantics を凍結する。
- [ ] NetBIOS name / port 139 / hostname discovery は原則 scope 外だが、必要になったら separate transport として検討
  - 現状は direct TCP 445 のみ。

## 横断（全 Phase 共通）

- [x] `SMBErrorMapper`: NTSTATUS → エラー型（[docs/smb-protocol.md] の表、値は MS-ERREF 確認）
- [x] `SMBSession`（actor）化 / 切断検出→再接続 / cancellation（Task.checkCancellation を READ/WRITE ループに）
  - 2026-06-30: `SMBWireTransactionGate` で request/response pair を FIFO 直列化。actor reentrancy があっても
    同一 session 上の並行 wire 操作で応答取り違えが起きないことを unit test 済み。
    真の messageId/credit multi-flight demux は未実装（必要になったら別 issue）。
- [x] retry 粒度: stat=透過 / list=全体再実行 / read=stream 未 yield なら先頭再試行 / write・delete・rename=原則 retry しない
- [x] secret（password / NT hash / session key / signing key）を log に出さない
- [x] SMB1 を一切提示しない
- [x] 3.0.2 用 CMAC(RFC4493) / CCM(RFC3610 / SP800-38C) を Phase 2 で pure-Swift 実装または
      pure-Swift cross-platform lib を踏襲（Linux ビルド維持）
- [x] 公開 API は async + cancellation + streaming（read/write）= consumer がそのまま被せられる形
- [x] SwiftLint plugin green を維持（CI=macos-26）

## 完了の目安（MVP）

- [x] Phase 0–3（read）+ Phase 5 の read E2E が green
- [x] probe が macOS SMBX で 3.0.2 + signing required、Samba で 3.1.1+GMAC+GCM または
      3.0.2 mirror E2E green を確認
  - 2026-06-30: macOS SMBX 3.0.2 smoke 済み、Samba は 3.0.2 mirror E2E green。Samba 3.1.1+
    GMAC+GCM の実測は Phase 1 の独立タスクとして残す。
- [x] write（Phase 4）は read 安定後に着手判断
