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
- dialect: authenticated operations are **SMB 3.x only**: **SMB 3.0 / 3.0.2 / 3.1.1**
  （サーバとの NEGOTIATE 結果に従う。probe は SMB 2.0.2 / 2.1 も表示できるが、SMB 2.1 以下への
  authenticated fallback は非対応。macOS SMBX は現状 3.0.2 上限、Samba では 3.1.1 profile も検証。
  Windows SMB Server は実機 smoke 未追加）
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
- [docs/coverage.md](docs/coverage.md) — SMBee が実装済み・未検証・未対応の SMB surface とテスト状況
- [docs/compatibility-matrix.md](docs/compatibility-matrix.md) — Samba / macOS SMBX / Windows / NAS の実サーバ smoke 記録
- [todo.md](todo.md) — 実装 TODO（Phase 0〜5 のチェックリスト）

## 現時点の制限

- 認証済み操作は SMB 3.x only。SMB 2.0.2 / 2.1 は probe-only で、接続時は診断付きエラーにする。
- Kerberos / GSS は未対応。現状は NTLMv2 password / NT hash / anonymous を対象にする。
- Windows SMB Server / NAS の実サーバ smoke は未完了。Samba と一部 macOS SMBX の確認が中心。
- durable handle / lease / oplock は未対応。byte-range lock はライブラリ API (`SMBClientSession.withFileLock`) のみ (CLI 非対応)。
- CHANGE_NOTIFY は `--reconnect` で接続断時の再購読に対応 (取りこぼし分は overflow で通知)。
- DFS referral は metadata 取得のみ。target への auto-follow は未対応。
- reparse point / symlink / mount point / LX symlink の target は `readlink` API で扱える。DFS/NFS の reparse data は MS-FSCC 上 opaque (client 解釈対象外) で、DFS link の解決は `smbcli dfs` (FSCTL_DFS_GET_REFERRALS)。実サーバ readlink smoke は未完了。
- single-file download/upload の byte-level resume と `--verify size|hash` (SHA-256 read-back) は対応済み。sparse file は `smbcli sparse` (SET_SPARSE / hole punch / allocated-range query) に対応 (FS 依存)。転送時の hole preservation は未対応。
- macOS resource fork / xattr / named stream preservation は未対応。通常の data fork 転送を対象にする。
- SMB1 / NetBIOS port 139 / printer share / SMB Direct(RDMA) / SMB over QUIC / multichannel / compression は未対応。

## 開発状況

設計・実装の進行中。
