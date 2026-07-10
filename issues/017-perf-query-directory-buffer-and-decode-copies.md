# 017 perf: directory listing が 64KiB query と decode 時コピーに固定されている

- 種別: perf
- 起票: 2026-07-11
- 状態: open

## 症状 / リスク

`QUERY_DIRECTORY` の output buffer が 64KiB 固定で、巨大ディレクトリでは往復回数が増える。また decode 時に response slice を複数回 `Array(...)` 化しており、entry 数が多い listing / recursive glob で CPU とメモリコピーが増える。

## 根拠

該当箇所:

- `Sources/SMBee/SMB2ReadCodecs.swift`: `SMB2QueryDirectory.encodeRequest(...)` が `writer.writeUInt32LE(65_536)` 固定
- `Sources/SMBee/SMB2ReadCodecs.swift`: `decodeResponse(...)` が `Array(bytes.dropFirst(...))`、`Array(bytes[offset..<offset + length])`、名前 decode で `Array(data[nameOffset..<...])`
- `Sources/SMBee/SMBClient.swift`: `list(...)` は全 entry を collector に蓄積してから返す。stream API はあるが CLI JSON/list の一部は配列化する
- `Sources/smbcli/BatchCommands.swift`: remote recursive glob は各 directory の entries を配列化し、最後に sort する

## 修正方針

1. `QUERY_DIRECTORY` の output buffer size を negotiate/session の limits と credit に応じて増やせるようにする。まず 256KiB / 1MiB の実測比較を行う。
2. `SMB2QueryDirectory.decodeResponse` を `ArraySlice<UInt8>` / offset-based reader に寄せ、response 全体や entry payload のコピーを減らす。
3. UTF-16LE decode も `[UInt8]` 生成なしで `Collection` / buffer pointer から読める helper を追加する。
4. recursive glob は streaming 可能な箇所では全件配列化を避ける。ただし deterministic output が必要な command は sort のための蓄積を維持する。

## 注意点

- 大きすぎる query buffer は server compatibility に差が出る可能性がある。Samba / Windows / macOS SMB server で確認する。
- JSON list など順序がユーザーに見える command は、streaming 化で順序や出力タイミングが変わる。互換性を優先する。
- decode copy 削減は micro optimization になりやすい。まず大規模 directory listing の CPU profile と allocation profile を取る。

## 受け入れ条件

- [ ] 10k+ entries の directory listing で before/after の wall time、allocation、QUERY_DIRECTORY request count を記録する
- [ ] Samba / Windows 相当 / macOS SMB server の compatibility smoke が通る
- [ ] `withDirectoryStream` の逐次性が維持される
- [ ] CLI の通常出力・JSON 出力の順序が意図せず変わらない
