# 015 perf: upload/write が 64KiB 直列 write に固定されている

- 種別: perf
- 起票: 2026-07-11
- 状態: open
- 関連: `issues/014-perf-ccm-decrypt-and-read-throughput.md` の read 側 follow-up

## 症状 / リスク

download/read 側は `localReadChunkLimit = 1024 * 1024` まで引き上げ済みだが、upload/write 側はまだ 64KiB 固定のまま。

- `SMBClientSession.localWriteChunkLimit = 64 * 1024`
- `SMBSession.creditAwareWriteChunkSize()` の `localLimit: 64 * 1024`
- `SMBClientSession.upload(fileURL:)` は `min(maxLength, Self.localWriteChunkLimit)` でさらに 64KiB に clamp
- `SMBSession.write(...)` は 1 チャンク write → 応答待ち → 次チャンク、の直列ループ

RTT があるネットワークでは write throughput が `64KiB / RTT` に近い上限を受ける。例: RTT 5ms なら理論上限は約 13MB/s、RTT 20ms なら約 3.3MB/s。

## 根拠

該当箇所:

- `Sources/SMBee/SMBClient.swift`: `SMBClientSession.localWriteChunkLimit`
- `Sources/SMBee/SMBClient.swift`: `SMBClientSession.upload(path:fileURL:...)`
- `Sources/SMBee/SMBClient.swift`: `SMBSession.write(...)`
- `Sources/SMBee/SMBClient.swift`: `SMBSession.creditAwareWriteChunkSize()`

read 側は既に `maxReadSize` / credit を見て 1MiB まで使う設計に寄っている。write 側も `maxWriteSize` と credit charge に合わせた上限へ寄せられる余地がある。

## 修正方針

1. `SMBEE_PERF=1` に write chunk size / wire time / credit balance / negotiated `maxWriteSize` を出す。
2. container Samba と実 NAS で 64KiB 直列 upload の現状 throughput を測る。
3. `localWriteChunkLimit` を 1MiB 程度へ引き上げる。ただし `maxWriteSize`、transform overhead、credit balance で必ず clamp する。
4. 必要なら read と同様に credit request policy を見直し、write の multi-flight pipeline 化を検討する。

## 注意点

- write は非冪等なので、connection loss 時の再試行や pipeline 中の部分成功の扱いを read より慎重に設計する。
- `upload(fileURL:)` は `FileHandle.read(upToCount:)` の戻り値を `Array(data)` にコピーしている。チャンク拡大でコピー量も増えるため、先に throughput と CPU を計測する。
- 暗号化セッションでは transform overhead を `maxWriteSize` から差し引く現在の扱いが仕様上正しいか、read 側 follow-up と合わせて確認する。

## 受け入れ条件

- [ ] `SMBEE_PERF=1` で write の chunk size / wire time / credit balance が観測できる
- [ ] loopback encrypted/unencrypted upload の before/after throughput を記録する
- [ ] RTT を付けた環境、または実 NAS で 64KiB 直列より明確に改善する
- [ ] 既存 upload / resume / directory upload tests が green
