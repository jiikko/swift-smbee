# SMBee 実装 TODO 🐝

設計は [docs/architecture.md](docs/architecture.md) / [docs/smb-protocol.md](docs/smb-protocol.md) /
[docs/testing.md](docs/testing.md) を正本とする。各タスクは **その doc を読んでから**着手。
`ⓥ` = 実装中に spec / 実測で確認する判断点。

MVP scope: **SMB 3.0.2 + 3.1.1 / NTLMv2 / negotiated dialect 依存の署名・暗号 /
対象=macOS SMBX(実上限 3.0.2) + Samba(3.1.1 想定)**。
3.1.1 は AES-128-GMAC 署名 + AES-128-GCM 暗号（swift-crypto）。3.0.2 は
AES-CMAC 署名 + AES-128-CCM 暗号（swift-crypto に無いため Phase 2 で pure-Swift 実装または
pure-Swift cross-platform lib を踏襲、Linux ビルド維持）。
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
- [ ] **実測**: Samba が **3.1.1 + GMAC + GCM** を交渉するか ⓥ
- [ ] 既知課題: Samba 3.1.1 response の parser が `truncated` になるバグを調査（macOS 実上限が
      3.0.2 のため優先度低）
- 撤退判断: Samba が GMAC/GCM を交渉しない & 設定で出せない → 3.1.1 側 scope 見直し

## Phase 2 — 認証（NTLMv2 / SPNEGO）+ TREE_CONNECT

- [ ] SPNEGO 最小ラップ（MS-SPNG / RFC4178）
- [ ] NTLMv2: NEGOTIATE(type1) → CHALLENGE(type2) parse → AUTHENTICATE(type3)
  - [ ] NTOWFv2 / NTProofStr / AV pair(target info) / timestamp / clientChallenge / MIC（UTF-16LE）
  - [ ] vector test（MS-NLMP / RFC）
- [ ] SESSION_SETUP の複数往復（STATUS_MORE_PROCESSING_REQUIRED）
- [ ] **SMB 3.1.1 crypto framing**:
  - [ ] preauth integrity: NEGOTIATE+SESSION_SETUP の SHA-512 running transcript
  - [ ] SP800-108 counter KDF（HMAC-SHA256）で signing/encryption/application key 導出（label/context ⓥ）
  - [ ] signing = AES-GMAC を packet に適用 / 検証
  - [ ] encryption = TRANSFORM_HEADER + AES-GCM（nonce/AAD/tag レイアウト ⓥ）
  - [ ] preauth transcript / KDF / transform header の fixture test
- [ ] **SMB 3.0.2 crypto framing**:
  - [ ] signing = AES-CMAC（RFC4493）を pure-Swift 実装または pure-Swift cross-platform lib で対応
  - [ ] encryption = AES-128-CCM（RFC3610 / NIST SP800-38C）を pure-Swift 実装または pure-Swift cross-platform lib で対応
  - [ ] CommonCrypto は Linux 非対応なので使わない
- [ ] TREE_CONNECT（`\\host\share`）
- 撤退判断: NTLMv2 SESSION_SETUP が 2〜3 日 opaque に失敗（packet capture でも追えない）→ 方針再考

## Phase 3 — read

- [ ] CREATE（open。desired access / share access / disposition=OPEN）
- [ ] QUERY_DIRECTORY（`FileIdBothDirectoryInformation`）反復 → STATUS_NO_MORE_FILES = `list`
- [ ] QUERY_INFO（size/mtime/is-dir）= `stat`
- [ ] READ（offset/length）反復 = `read`（full / range）
  - [ ] download 完全性: 受信 byte 積算を `stat().size` と照合
- [ ] CLOSE / handle 寿命管理
- [ ] `smbcli ls / stat / cat [--range]`
- [ ] 大 dir は全件メモリ集約（known limitation。pageToken 化は後回し）
- [ ] large file read（>4 GiB）でメモリ/速度/cancellation を確認 ⓥ
- 撤退判断: ls/stat/cat が macOS/Samba で安定しない → 方針再考

## Phase 4 — write

- [ ] CREATE(disposition: overwrite=false→FILE_CREATE / true→FILE_OVERWRITE_IF ⓥ) + WRITE(offset) 反復
  - [ ] file URL を memory に lift しない streaming write
- [ ] mkdir（CREATE dir, FILE_CREATE）
- [ ] rename / move（SET_INFO `FileRenameInformation`, ReplaceIfExists）— 同一 share / atomic 挙動 ⓥ
- [ ] delete（SET_INFO `FileDispositionInformation`）/ 空 dir rmdir / 非空は per-file 再帰
- [ ] `smbcli put / mkdir / mv / rm`

## Phase 5 — E2E（コンテナ Samba）

- [x] E2E test target（`SMBEE_E2E` env gate）— probe-only（NEGOTIATE: 3.0.2 / signing required /
      3.1.1 negotiate contexts なし）
- [x] Samba イメージ + smb.conf 確定（macOS SMBX ミラーとして SMB3_02 上限、signing required）
- [x] `.github/workflows/e2e.yml` の TODO を埋め、push トリガを有効化
- [ ] ローカル Apple container 起動スクリプト（手動）

## 横断（全 Phase 共通）

- [ ] `SMBErrorMapper`: NTSTATUS → エラー型（[docs/smb-protocol.md] の表、値は MS-ERREF 確認）
- [ ] `SMBSession`（actor）で全 wire を直列化 / 切断検出→再接続 / cancellation（Task.checkCancellation を READ/WRITE ループに）
- [ ] retry 粒度: stat=透過 / list=全体再実行 / read=stream 未 yield なら先頭再試行 / write・delete・rename=原則 retry しない
- [ ] secret（password / NT hash / session key / signing key）を log に出さない
- [ ] SMB1 を一切提示しない
- [ ] 3.0.2 用 CMAC(RFC4493) / CCM(RFC3610 / SP800-38C) を Phase 2 で pure-Swift 実装または
      pure-Swift cross-platform lib を踏襲（Linux ビルド維持）
- [ ] 公開 API は async + cancellation + streaming（read/write）= consumer がそのまま被せられる形
- [ ] SwiftLint plugin green を維持（CI=macos-26）

## 完了の目安（MVP）

- [ ] Phase 0–3（read）+ Phase 5 の read E2E が green
- [ ] probe が macOS SMBX で 3.0.2 + signing required、Samba で 3.1.1+GMAC+GCM または
      3.0.2 mirror E2E green を確認
- [ ] write（Phase 4）は read 安定後に着手判断
