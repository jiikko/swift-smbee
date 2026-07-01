# 007 ci: Swift 6.0 Linux unit test が stuck する

状態: **open**
起票: 2026-07-01
関連: `.github/workflows/test.yml` / `Tests/SMBeeTests/SMBeeE2ETests.swift`
GitHub Actions: https://github.com/jiikko/swift-smbee/actions/runs/28486174498/job/84433018363

## 背景

GitHub Actions の `Test` workflow で、`linux-build-test / Swift 6.0` job が
`Unit tests on Linux` step に入ったまま長時間進まない事象を確認した。

同一 run 内の比較:

- `build-test` (macOS): success
- `linux-build-test / Swift 6.2`: success。`Unit tests on Linux` は約 14 秒で完了
- `linux-build-test / Swift 6.0`: `Unit tests on Linux` が `in_progress` のまま

`gh run view 28486174498 --job 84433018363 --log` は、job が in progress の間は
`logs will be available when it is complete` となり、途中ログは取得できなかった。

## 暫定判断

原因は、Swift 6.0 Linux の XCTest / SwiftPM test runner が、skip される async E2E XCTest を含む
test plan で停滞している可能性が高い。

根拠:

- macOS job は既に `swift test --skip SMBeeE2ETests` を使っており、同種の hang 回避コメントがある。
- Linux job だけが素の `swift test` を使っていた。
- Swift 6.2 Linux は同じ素の `swift test` でも完了した。
- `SMBeeE2ETests` は env gate (`SMBEE_E2E=1`) 未設定なら skip する async XCTest を含む。
- stuck した step は Samba container E2E ではなく、通常 unit job の `Unit tests on Linux`。

## container で再現するか

現時点では **Apple container の既存 smoke では再現条件を満たしていない**。

理由:

- `bin/e2e/container-samba.sh` は Samba server を起動し、`SMBEE_E2E=1` で
  `swift test --filter SMBeeE2ETests` を実行する E2E 用。
- 今回 stuck したのは Samba なしの Linux unit job で、`SMBEE_E2E` 未設定のまま素の
  `swift test` を実行する経路。
- 再現には、Samba ではなく **Swift 6.0 Linux toolchain の container** が必要。

したがって、既存の container smoke が green でも、この stuck 問題を否定できない。

## 暫定対応

`test.yml` の Linux unit job を macOS と同じ方針へ揃えた。

```yaml
- name: Unit tests on Linux
  timeout-minutes: 10
  run: swift test --skip SMBeeE2ETests
```

目的:

- unit/vector CI は deterministic な非 E2E coverage に限定する。
- Samba-backed E2E は `.github/workflows/e2e.yml` に集約する。
- Swift 6.0 Linux runner が stuck しても 10 分で失敗させる。

実施コミット:

- `52d5e36 Skip E2E tests in Linux unit CI`

## 次にやるなら

再現を詰めるなら、専用の Linux Swift 6.0 container 再現 script を追加する。

候補:

```sh
# 例: Swift 6.0 Linux toolchain container 内で実行
swift --version
swift test
swift test --skip SMBeeE2ETests
swift test --list-tests
```

確認したいこと:

- `swift test` だけが止まり、`swift test --skip SMBeeE2ETests` は通るか。
- `swift test --list-tests` で止まるなら discovery 側の問題。
- test 実行開始後に止まるなら skipped async XCTest の runner 側問題。
- Swift 6.0 のみで起き、Swift 6.2 では起きないか。

## 完了条件

- [x] CI の stuck を回避する暫定対応を入れる。
- [x] Linux unit job に timeout を入れる。
- [ ] Swift 6.0 Linux container で素の `swift test` stuck を再現または非再現確認する。
- [ ] 再現できる場合、最小再現条件を記録する。
- [ ] upstream/toolchain 問題か repo 側 test 構成問題かを切り分ける。
