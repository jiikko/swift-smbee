# SMBee 🐝

A pure-Swift SMB2/3 client.

SMB のプロトコル / framing / NTLMv2 フロー / SMB3 の crypto framing は本ライブラリで
**自作**し、AES-GCM / HMAC / SHA などの暗号プリミティブの計算は
[swift-crypto](https://github.com/apple/swift-crypto) に委ねる
（`libsmb2` のような vendored C 依存は持たない）。

## スコープ (MVP)

- 対象サーバ: **macOS の SMB サーバ (SMBX / ファイル共有)**
- dialect: **SMB 3.1.1**（signing = AES-GMAC / encryption = AES-GCM が交渉できた場合）
- 認証: **NTLMv2**（Kerberos は対象外）
- まず CLI (`smbcli`) で動かし、後段で GUI から利用する

## 構成

- `SMBee` — ライブラリ本体
- `smbcli` — CLI（`smbcli probe smb://host` で交渉結果を表示、など）

## ドキュメント

- [docs/smb-protocol.md](docs/smb-protocol.md) — 実装する SMB wire 仕様と一次ソース（MS-SMB2 / MS-NLMP / NIST 等）
- [docs/testing.md](docs/testing.md) — テスト戦略（unit vector / Apple container 上の Samba で E2E / 実 macOS smoke）

## 開発状況

設計・実装の進行中。
