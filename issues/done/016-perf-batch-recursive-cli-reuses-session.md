# 016 perf: batch/recursive CLI がファイルごとに SMB セッションを張り直す

- 種別: perf
- 起票: 2026-07-11
- 状態: open

## 症状 / リスク

`smbcli mget` / `mput` や recursive transfer は、対象ファイルごとに `SMBee.download(...)` / `SMBee.upload(...)` / `SMBee.stat(...)` / `SMBee.makeDirectory(...)` を呼ぶ経路が多い。これらの static API は基本的に `withSession` 経由で connect → session setup → tree connect → operation → disconnect を毎回行う。

ファイル数が多い workload では、実データ転送よりも認証・tree connect・close の往復が支配的になる。

## 根拠

該当箇所:

- `Sources/smbcli/BatchCommands.swift`: `MGet.download(files:)` が各ファイルで `SMBee.download(...)`
- `Sources/smbcli/BatchCommands.swift`: `MPut.upload(files:)` が各ファイルで `remotePathExists(...)`、`makeRemoteParentDirectories(...)`、`SMBee.upload(...)`
- `Sources/smbcli/BatchCommands.swift`: recursive remote glob はディレクトリごとに `remoteDirectoryEntries(...)` を呼び、static `SMBee.withDirectoryStream(...)` で接続を張る
- `Sources/SMBee/SMBClient.swift`: static API の多くが `withSession(...)` で 1 操作 1 セッション

一方で `SMBClient.connect(...)` は persistent `SMBClientSession` を返せるので、CLI 側で 1 コマンド 1 セッションに寄せる実装余地がある。

## 修正方針

1. `mget` / `mput` / recursive command のコマンド単位で `SMBClient.connect(...)` し、同じ `SMBClientSession` を使い回す。
2. `MGet` は remote recursive glob と download を同一 session 上で実行する。
3. `MPut` は remote existence check、parent mkdir、upload を同一 session 上で実行する。
4. recursive directory transfer API も可能なら内部で 1 session を使い回し、public static API は互換 wrapper とする。

## 注意点

- 非冪等操作中の connection loss は現状 static API の operation boundary と意味が変わる。retry は既存より広げず、まずは接続再利用だけに絞る。
- `withTree(...)` が必要な複数 share 操作とは分ける。batch command は同一 share 前提なので session reuse しやすい。
- `--continue-on-error` では、1 ファイル失敗後に session が壊れている場合の扱いを明確にする。必要なら reconnect して後続へ進む。

## 受け入れ条件

- [ ] `mget` / `mput` の複数ファイル転送で negotiate/session setup/tree connect がファイル数分発生しない
- [ ] 小ファイル 1000 個の upload/download で before/after の wall time を記録する
- [ ] recursive include/exclude/no-overwrite/dry-run の既存挙動が維持される
- [ ] connection loss 時のエラーが既存より曖昧にならない
