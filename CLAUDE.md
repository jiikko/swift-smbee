# SMBee — 開発の流れ

pure-Swift SMB2/3 client。プロトコル正本は [docs/smb-protocol.md](docs/smb-protocol.md) /
[docs/architecture.md](docs/architecture.md)、テスト戦略正本は [docs/testing.md](docs/testing.md)、
実装 TODO は [todo2.md](todo2.md)。ここには「触ったときに必ず踏む手順」だけを置く。

## push後のCI確認（Codex/Claude共通・必須）

pushしたら、完了報告前に必ず次を実行し、終了コード0を確認する。

```sh
bin/ci/verify-agent-push <full-commit-sha>
```

Test / E2E / Performanceを並行して待ち、失敗jobとlog要点を自動表示する。成功時は20ペア測定、
AB/BA順序、regression gate、raw artifact、統計再計算も検証する。どれかが失敗・skipした場合は
完了扱いにしない。Performanceだけを再検証する低レベルコマンドは
`bin/ci/verify-agent-performance`。canonical policyは
[docs/agent-performance-verification.md](docs/agent-performance-verification.md)。

## 実装を変更したら smoke E2E を回す（最重要）

**production の wire 挙動（`Sources/SMBee/` の codec / crypto / session / transport など）を変更したら、
unit だけで済ませず container Samba に対する E2E smoke を実行する。** unit は `InMemoryTransport` +
synthetic frame なので「自分のエンコードを自分でデコードして通る」型の退行を取りこぼす
（実サーバが `INVALID_PARAMETER` を返す類）。実サーバ照合は smoke でしか担保できない。

```sh
swift build && swift test          # 1. まず unit（サーバ不要・必須）
bin/e2e/container-samba.sh          # 2. production を触ったら container Samba E2E smoke
```

SMB 3.0.2 encrypted、SMB 3.1.1 signing、Samba 4.22 reparseの3プロファイルをまとめて検証し、
push 前ゲート用マーカーを作るには `bin/e2e/smoke-all`（または
`make smoke`）を実行する。初回だけ `make setup-hooks` でリポジトリ管理の pre-push フックを有効化する。
`make smoke`は進捗と結果だけを表示し、完全ログを`tmp/e2e-smoke-latest.log`へ保存する。
wire logを端末へ全量表示したい場合だけ`make smoke-verbose`を使う。
`SMBEE_SKIP_E2E_GATE=1 git push` は緊急時の明示的なスキップに使える。
マーカーは `Sources/SMBee` の subtree hash に紐づくため、docs / test だけの後続 commit では
無効化されない。ただし smoke は committed tree を証明するので **wire 変更は commit してから
smoke を回す**（`Sources/SMBee` が dirty だと smoke-all が拒否する）。

`bin/e2e/container-samba.sh` は container 起動 → `smbcli probe` → `swift test --filter SMBeeE2ETests`
→ `smbcli` smoke → 後始末までを 1 発で回す。主な env（既定は SMB 3.0.2 encrypted-required profile）:

```sh
SMBEE_E2E_PORT=1446 bin/e2e/container-samba.sh
SMBEE_E2E_KEEP_CONTAINER=1 bin/e2e/container-samba.sh                 # 失敗調査用に残す
SAMBA_CONFIG=test/e2e/smb/smb311-encrypted-required.conf bin/e2e/container-samba.sh
```

profile の使い分け・SMB 3.1.1 だけ確認する起動例・wire trace は [docs/testing.md](docs/testing.md)
「ローカル実行 — Apple container / macOS」が正本。

> ⚠️ **この Mac に Docker Desktop / colima / podman は無い。探さない・入れない。**
> コンテナは常に Apple の `container` CLI (`brew install container`)。`docker` コマンドが
> 見つからないのは正常であり、Docker をインストールする方向に進まないこと (2026-07-17 指摘)。

### 変更したら「その箇所をどうカバーするか」を必ず検討する

コードを変更したら、**変更した箇所の退行を捕まえるテストを追加できないか**を毎回検討する。
機能追加・バグ修正だけで終わらせず、次のどれでカバーするか（または「不要」の理由）を明示する:

- **unit / regression test**: 変更したロジック・codec・境界の退行を synthetic に固定する
  （例: perf 契約は `SMBeePerformanceRegressionTests`、wire は fixture）。
- **E2E test**: 実サーバでしか出ない挙動（negotiate 結果・署名/暗号・実 status）は
  `Tests/SMBeeTests/SMBeeE2ETests.swift` に足し、`bin/e2e/container-samba.sh` で回す。
- 該当 profile が無ければ `test/e2e/smb/*.conf` を足すことも検討する。

「テストで守れない変更」だと判断したら、その理由を PR / commit に一行残す。

### smoke が要る変更 / 要らない変更

- **要る**: CREATE/READ/WRITE/QUERY_*/SET_INFO 等の codec、署名（CMAC/GMAC）、暗号（CCM/GCM）、
  SESSION_SETUP / NTLM、transform header、negotiate、session/transport の挙動変更。
- **要らない（unit で十分）**: test 追加のみ、docs、CI yaml、CLI の文言、コメント。
  例: perf-regression test（issue 003）は production 非変更なので smoke 不要。

## container の初回セットアップ（1 回だけ・対話）

ローカルは Apple の `container` CLI（`brew install container`）を使う。**初回だけ
`container system start` が kernel download を対話で聞いてくる**。非対話（エージェント）では
完了できないので、未セットアップなら人間が一度だけ実行する:

```sh
container system start   # 推奨 kernel の install に y と答える（初回のみ）
```

これを終える前は `bin/e2e/container-samba.sh` が
`container system start failed. Complete container first-run setup, then retry.` で止まる。

## CI とローカルの分担

- **ローカル**: Apple `container`（macOS / Apple silicon）。CI と同じ distro Samba・同じ順序を再現する。
- **CI**: Docker + Linux runner（`.github/workflows/`）。macOS runner では Docker を使わない。
  → SMBee が **Linux でビルド/実行できる**こと（`Network.framework` は `NWConnectionTransport` の
  `#if canImport(Network)` に閉じ込める）を壊さない。
- 実サーバ（macOS SMBX / Windows）に対する手動 smoke はリリース前の Tier 3。自発実行はビルドまで、
  実行はユーザーに委ねる。

## commit 粒度

このリポジトリは submodule。commit したら親（my-products）参照 bump 前に **submodule リモートへ push**
する運用（親側 `.claude/rules/submodule-workflow.md`）。1 マイルストーン = 1 commit。
