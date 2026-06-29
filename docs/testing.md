# SMBee — テスト戦略

SMBee のテストは 3 tier。**ⓥ = 実装/運用前に要確認**。

## Tier 1: unit（primitive / framing vector）— CI 必須・サーバ不要

純粋ロジックを既知ベクタで固める。実 SMB サーバに依存しない。

- **crypto primitive**: MD4（RFC1320）/ HMAC-MD5・HMAC-SHA256（RFC2104）/ NIST GCM・GMAC / SHA-512
- **NTLMv2**: MS-NLMP / RFC の既知ベクタ（NTOWFv2 / NTProofStr / MIC）
- **SMB framing**: SMB2 packet header・各 command 構造の encode/decode round-trip /
  3.1.1 preauth integrity transcript fixture / SP800-108 KDF vector /
  TRANSFORM_HEADER round-trip / signed packet 検証 /
  **packet-level fixture**（pcap or 既存実装由来。primitive が通っても framing が正しいとは限らない）

## Tier 2: E2E（Apple container 上の SMB サーバ）— 本 repo のテスト範囲の主役

**Apple container（macOS 26 の `container` CLI / Containerization framework, Apple silicon）で
SMB サーバ（Samba）を起動し、SMBee/`smbcli` でゴールデンパスを通す。**「手動で macOS ファイル
共有を立てる」依存を排し、E2E を再現可能にする。

ゴールデンパス（probe → 認証 → 操作）:

```
probe   : NEGOTIATE 結果 (dialect/signing/cipher) が想定 (3.1.1 / GMAC / GCM) か
ls      : QUERY_DIRECTORY
stat    : QUERY_INFO
cat     : READ（full / range）。download sha256 を期待値と照合
put     : WRITE（streaming、large file >4GiB 含む）
mkdir / rename / rm : SET_INFO / CREATE / disposition
```

E2E ハーネスの流れ（XCTest から driver 経由 ⓥ）:

1. `container run` で Samba イメージを起動（445 を expose、share + ユーザを用意）
2. 445 が listen するまで wait（probe で疎通確認）
3. ゴールデンパスを実行して assert
4. `container stop` / `rm` で確実に後始末（テスト失敗時も）

### ⚠️ Samba と macOS SMBX の差（重要・要確認 ⓥ）

- MVP の**対象サーバは macOS SMBX**だが、E2E は **Samba（Linux）**。両者は別実装。
- **signing/cipher の交渉差**: SMBee MVP は **GMAC+GCM のみ**に pin している。**Samba が
  既定で AES-CMAC 署名に倒れると、GMAC-only の SMBee は接続できない**。E2E では Samba を
  **SMB 3.1.1 + AES-128-GMAC + AES-128-GCM を出す設定**にする（`smb.conf` で
  `server signing` / `smb encrypt` / 対応 Samba バージョン ⓥ）。
- これが満たせない場合の判断: (a) Samba 設定で GMAC を出させる / (b) SMBee の signing 許容を
  CMAC まで広げる（= MVP scope 拡張）/ (c) E2E は CMAC でやり macOS SMBX 向けに GMAC を別途
  確認。**どれを採るかは probe の実測（Samba と macOS 双方）後に決める**。
- したがって E2E（Samba）green ≠ macOS SMBX 動作保証。**macOS SMBX への手動 smoke（Tier 3）を併用**する。

### CI 実行可否 ⓥ

- Apple container は **macOS 26 + Apple silicon + virtualization** が前提。GitHub hosted の
  `macos-26` runner で `container`（ネスト仮想化）が動くかは**要検証**。動かなければ E2E は
  **self-hosted runner / ローカル限定**とし、CI（hosted）は Tier 1 のみ必須にする。
- E2E テストは env gate（例: `SMBEE_E2E=1` かつ `container` 利用可能時のみ）。未満足なら skip。

## Tier 3: 手動 smoke（実 macOS SMBX）— リリース前

MVP の真の対象である **macOS のファイル共有（SMBX）**に対し `smbcli probe` + ゴールデンパスを
手動で 1 周。Tier 2 の Samba では拾えない macOS SMBX 固有挙動（交渉値・quirk）を確認する。
「自発実行はビルドまで、実行はユーザー」運用に乗せる。

## まとめ

| Tier | 対象 | CI | 役割 |
|------|------|----|----|
| 1 unit | なし（vector/fixture） | ✅ 必須 | ロジック・framing の正しさ |
| 2 E2E | Apple container 上の Samba | ⓥ（hosted で可なら必須、不可なら self-hosted/local） | 再現可能なゴールデンパス回帰 |
| 3 smoke | 実 macOS SMBX | 手動 | MVP 本番サーバの最終確認 |
