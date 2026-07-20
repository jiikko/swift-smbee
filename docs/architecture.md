# SMBee — 内部アーキテクチャ

## transport 抽象（決定 2026-06-29）

SMB のプロトコル/framing/session コードは **transport に依存しない**。バイト列を運ぶ層を
**protocol で抽象化**し、プラットフォームで実装を差し替える。

```
SMBSession / NEGOTIATE / SESSION_SETUP / TREE_CONNECT / CREATE / READ / WRITE ...
        │  (依存するのは下の protocol だけ)
        ▼
protocol SMBTransport            // TCP 445 上の双方向バイトストリーム
  - connect(host:port:) async throws
  - send(_ bytes:) async throws
  - receive(maxLength:) async throws -> [UInt8]   // or AsyncStream
  - close()
        ▲                         ▲
        │                         │
 NWConnectionTransport      POSIXSocketTransport
 (macOS 本番)               (Linux CI / E2E / cross-platform)
```

### なぜ抽象化するか

- **本番 (macOS app)** は `Network.framework` の `NWConnection` を使いたい（省電力・接続管理・
  Apple 統合）。
- **CI の E2E** は **Linux runner + Docker の Samba** で回す（無料・再現可能）。Linux では
  `Network.framework` が無いため、実装済みの **POSIX socket transport** を使う。
- 両者を `SMBTransport` protocol の差し替えで吸収する＝ **best of both**。SMB の本体ロジックは
  一切プラットフォーム分岐を持たない。

### 実装方針

- `SMBTransport` は SMB に固有の概念を持たない（純粋に「接続して send/receive」だけ）。
  direct-TCP の **4 byte length framing** は `DirectTCPFraming` としてtransportの外側に実装済み。
- `NWConnectionTransport`: macOS。`#if canImport(Network)` でガード。
- `POSIXSocketTransport`: Linux + macOS 両対応（テスト・E2E・CI用）。SwiftNIO依存は採用していない。
- テスト（unit）は transport を **in-memory fake / loopback** に差し替えて framing を検証できる。

### プラットフォーム条件

- `SMBSession` / protocol / crypto / auth は **Linux でもビルド可能**に保つ（swift-crypto は
  Linux 対応）。`Network.framework` 依存は `NWConnectionTransport` の中だけに閉じ込め、
  `#if canImport(Network)` で囲う。これを破ると CI(Linux) の E2E が動かなくなる。

## レイヤリング（repo 内）

| 層 | 役割 |
|----|----|
| `SMBTransport`（protocol）+ 実装 | TCP バイトストリーム。platform 差はここだけ |
| `Protocol/` | SMB2 header / command codec / framing |
| `Auth/` | NTLMv2 / SPNEGO |
| `Crypto/` | preauth / KDF / signing / encryption。3.1.1 は GMAC/GCM をswift-cryptoで扱う。3.0.2 CMACはCommonCrypto（Apple）/ CryptoExtras（Linux）、CCMはCommonCrypto（Apple）/ pure Swift（Linux）で扱う |
| `Session/` | `SMBSession`（actor）: 接続シーケンス・直列化・再接続・cancellation |
| `API/` | 公開 API（list/stat/read/write/mkdir/rename/delete）。型は path/offset/length/attrs |
| `smbcli` | CLI（probe/ls/stat/cat/put/...） |

GUI / `ObjectStorageProtocol` 適合などの consumer 側は **本 repo に置かない**（consumer 側で
SMBee を薄くラップする）。

## dialect / crypto scope（実測 2026-06-29）

- macOS SMBX は macOS 26.5.1（最新）でも negotiated dialect が **0x0302 (SMB 3.0.2)** で上限。
  3.1.1 は喋らない。
- Samba 等の 3.1.1 対応サーバでは **0x0311 (SMB 3.1.1)** も対象。
- 3.1.1はAES-GMAC / AES-GCMをswift-cryptoで扱う。3.0.2のAES-CMACはCommonCrypto（Apple）と
  swift-crypto CryptoExtras（Linux）を使い、同一RFC 4493 vectorで結果を照合する。pure-Swift CMACは
  differential test用に残す。AES-128-CCMはCommonCrypto（Apple）/ in-repo pure Swift（Linux）で扱う。
