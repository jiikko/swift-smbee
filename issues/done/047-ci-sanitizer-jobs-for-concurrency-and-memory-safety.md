# 047 CI: concurrencyとmemory safetyを検証するsanitizer jobがない

- 種別: CI / dynamic analysis / regression prevention
- 重要度: medium-high
- 状態: open
- 関連: `.github/workflows/test.yml`, `@unchecked Sendable`, transport/crypto codec implementations

## 問題

通常のmacOS/Linux build、unit test、coverage jobはあるが、Thread SanitizerやAddress Sanitizerを使うjobがない。
コードには`@unchecked Sendable`、NSLock、checked continuation、actor外transport state、unsafe byte buffer、
platform C APIがあり、compile-time concurrency checkと通常testだけではdata raceやmemory errorを検出できない。

特にPOSIX transportのfd close/send/receive競合、progress/collectorのlock、continuation resume競合は
timing依存であり、line coverageが高くても安全性を保証しない。

## 影響

- data race、二重resume周辺の状態競合、unsafe buffer境界errorがreleaseまで見逃される。
- macOS/Linux固有のruntime差が通常jobでたまたま再現しない場合、CIがgreenになる。
- concurrency refactor時に`@unchecked Sendable`の前提崩れを検出する自動手段がない。

## 対応方針

1. macOSで`swift test --sanitize=thread --skip SMBeeE2ETests`を専用jobとして追加する。
2. Linuxで`swift test --sanitize=address --skip SMBeeE2ETests`を追加する。
3. PRではtransport/concurrency/codecの対象test filterに絞り、full sanitizer suiteはschedule実行にする。
4. sanitizer reportをartifact化し、既知toolchain false positiveはversion付きallowlistで管理する。
5. sanitizer job自体のhangにjob timeoutとstack dumpを付ける。

## リグレッションテスト / CI受け入れ条件

- 意図的なrace/heap overflow fixture branchで各sanitizer jobがfailすることを導入時に確認する。
- `SMB2CreditWindow`、demux cancellation、POSIX close/send/receive競合testをTSan対象に含める。
- codec malformed-input suiteとcrypto buffer処理をASan対象に含める。
- sanitizer非対応toolchainで黙ってskipせず、job summaryへ対応状況を出す。
