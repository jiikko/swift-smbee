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

## Tier 2: E2E（コンテナ上の SMB サーバ）— 本 repo のテスト範囲の主役

SMB サーバ（Samba）をコンテナで起動し、SMBee/`smbcli` でゴールデンパスを通す。
**「手動で macOS ファイル共有を立てる」依存を排し、E2E を再現可能にする。**

- **ローカル**: Apple container（macOS 26 の `container` CLI / Containerization framework, Apple silicon）
- **CI**: Docker（**Linux runner**。GHA: `.github/workflows/e2e.yml`、public repo で無料）

test code は共通（Samba を起動 → golden path）で、**起動手段だけ差し替える**。

> ⚠️ **CI(Docker/Linux) の前提**: Docker は Linux で動かす（macOS hosted runner では Docker 不可）。
> よって **SMBee が Linux でビルド/実行できる**必要がある。→ **決定: transport を抽象化**し
> macOS=NWConnection / Linux=POSIX|NIO を差し替える（[architecture.md](architecture.md)）。
> `Network.framework` 依存は `NWConnectionTransport` 内に `#if canImport(Network)` で閉じ込める。

ゴールデンパス（probe → 認証 → 操作）:

```
probe   : NEGOTIATE 結果 (dialect/signing/contexts) が想定 (macOS mirror: 3.0.2 / signing required / contexts なし) か
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
- **signing/cipher の交渉差**: macOS SMBX は macOS 26.5.1 でも negotiated dialect が
  **0x0302 (SMB 3.0.2)** で上限。SMB 3.0.2 は 3.1.1 negotiate contexts を返さず、
  signing/encryption は CMAC/CCM 系になる。
- 当面の E2E は Samba を **SMB3_02 上限 + signing required** に固定し、実 macOS の probe-only
  挙動をミラーする。3.0.2 用 AES-CMAC / AES-128-CCM は swift-crypto に無いため Phase 2 で
  pure-Swift 実装または pure-Swift cross-platform lib を検討する。
- Samba の **SMB 3.1.1 + AES-128-GMAC + AES-128-GCM** 交渉は別途 probe で確認する。Samba 3.1.1
  response parser が `truncated` になる既知課題があり、macOS 実上限が 3.0.2 のため優先度は低い。
- したがって E2E（Samba）green ≠ macOS SMBX 動作保証。**macOS SMBX への手動 smoke（Tier 3）を併用**する。

### CI 実行 — Docker / Linux runner

- CI は **`ubuntu-latest` + Docker で Samba を起動**して E2E（`.github/workflows/e2e.yml`）。
  ローカルは Apple container、CI は Docker、と起動手段を分ける。
- **前提（再掲）**: Linux で動かす以上、SMBee が Linux ビルド可能であること（上の transport 制約）。
- E2E テストは env gate（`SMBEE_E2E=1` + 接続情報 env）。未満足ならローカルの通常 `swift test` では skip。
- `.github/workflows/e2e.yml` は PR / push 用の代表 smoke。profile は
  `test/e2e/smb/smb302-encrypted-required.conf` を使い、macOS SMBX mirror として
  SMB 3.0.2 + signing mandatory + encryption required を維持する。
- `.github/workflows/samba-compat.yml` は重い互換性 matrix。`workflow_dispatch` と週次 schedule で、
  distro-provided Samba と `test/e2e/smb/*.conf` profile の代表組み合わせを回す。

Samba profile:

- `smb302-encrypted-required`: PR 必須代表。SMB 3.0.2 / signing mandatory / encryption required。
- `smb311-signing-required`: SMB 3.1.1 / signing mandatory / encryption off。GMAC signing-only 経路の検証用。
- `smb311-encrypted-required`: SMB 3.1.1 / signing mandatory / encryption required。GCM transform 経路の検証用。

## Tier 3: 手動 smoke（実 macOS SMBX）— リリース前

MVP の真の対象である **macOS のファイル共有（SMBX）**に対し `smbcli probe` + ゴールデンパスを
手動で 1 周。Tier 2 の Samba では拾えない macOS SMBX 固有挙動（交渉値・quirk）を確認する。
「自発実行はビルドまで、実行はユーザー」運用に乗せる。

## まとめ

| Tier | 対象 | CI | 役割 |
|------|------|----|----|
| 1 unit | なし（vector/fixture） | ✅ 必須 | ロジック・framing の正しさ |
| 2 E2E | Samba コンテナ（ローカル=Apple container / CI=Docker on Linux） | ✅（e2e.yml。足場は手動、整い次第 push/PR） | 再現可能なゴールデンパス回帰 |
| 3 smoke | 実 macOS SMBX | 手動 | MVP 本番サーバの最終確認 |
