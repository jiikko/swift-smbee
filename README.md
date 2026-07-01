# SMBee 🐝

[![Test](https://github.com/jiikko/swift-smbee/actions/workflows/test.yml/badge.svg)](https://github.com/jiikko/swift-smbee/actions/workflows/test.yml)
[![E2E](https://github.com/jiikko/swift-smbee/actions/workflows/e2e.yml/badge.svg)](https://github.com/jiikko/swift-smbee/actions/workflows/e2e.yml)

A pure-Swift SMB2/3 client.

SMB のプロトコル / framing / NTLMv2 フロー / SMB3 の crypto framing は本ライブラリで
**自作**し、AES-GCM / HMAC / SHA などの暗号プリミティブの計算は
[swift-crypto](https://github.com/apple/swift-crypto) と in-repo pure-Swift 実装に委ねる
（`libsmb2` のような vendored C 依存は持たない）。

## スコープ (MVP)

- 対象サーバ: **SMB 3.x サーバ**（macOS SMBX / Windows SMB Server / Samba）。現時点の自動 E2E は Samba、Windows 実機 smoke は未追加。
- dialect: **SMB 3.0.2 / SMB 3.1.1**（サーバとの NEGOTIATE 結果に従う。macOS SMBX は現状 3.0.2 上限、Samba では 3.1.1 profile も検証。Windows SMB Server は実機 smoke 未追加）
- signing / encryption: negotiated dialect に応じて AES-CMAC / AES-CCM（3.0.x）または AES-GMAC / AES-GCM（3.1.1）
- 認証: **NTLMv2**（Kerberos は対象外）
- まず CLI (`smbcli`) で動かし、後段で GUI から利用する

## 構成

- `SMBee` — ライブラリ本体
- `smbcli` — CLI（`smbcli probe smb://host` で交渉結果を表示、など）

## ドキュメント

- [docs/smb-protocol.md](docs/smb-protocol.md) — 実装する SMB wire 仕様と一次ソース（MS-SMB2 / MS-NLMP / NIST 等）
- [docs/architecture.md](docs/architecture.md) — 内部構成と transport 抽象（macOS=NWConnection / Linux=POSIX|NIO）
- [docs/testing.md](docs/testing.md) — テスト戦略（unit vector / コンテナ Samba で E2E: ローカル=Apple container・CI=Docker / 実サーバ smoke）
- [todo.md](todo.md) — 実装 TODO（Phase 0〜5 のチェックリスト）

## 開発状況

設計・実装の進行中。
