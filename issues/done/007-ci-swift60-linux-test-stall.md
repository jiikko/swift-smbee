# 007 ci: Swift 6.0 Linux unit test が stuck する

状態: **done** (2026-07-01 恒久対処: Swift 6.0 を CI matrix から除外)
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

## 再現確認 (2026-07-01) — 暫定仮説は誤り、真因を特定

### 暫定対応後も stall した (skip では直らない)

`52d5e36` の `swift test --skip SMBeeE2ETests` を入れた後も、
run `28491898150` の `linux-build-test / Swift 6.0` は **skip 済みのまま 10 分 timeout**
した (build は成功、test 実行段階で停止)。同一 run で macOS / Swift 6.2 Linux は成功。
同一 SHA `ee6fb818` の別 run は成功しており **flaky**。

→ 上記「暫定判断」の **「skip される async E2E XCTest が test plan に残るのが原因」という
仮説は誤り**。E2E を skip しても停止する。

### 最小再現 (Apple container / Swift 6.0 Linux / CPU 制約下で高確率)

macOS ローカル (arm64) では **`--cpus` を制約すると再現する** (無制約だと出にくい)。
CI runner の低コア数が再現条件。`swift:6.0-noble` (Ubuntu 24.04 = CI の ubuntu-latest に glibc
一致。`6.0-jammy` は arm64 swiftlint plugin が GLIBC_2.38 不足で別エラーになるので使わない)。

```sh
# repo ルートで実行 (Apple container CLI, native arm64)
container run --rm --cpus 2 -v "$PWD:/work" -w /work swift:6.0-noble bash -c '
  swift build --build-tests --build-path /tmp/bt
  for i in $(seq 1 8); do
    timeout 90 swift test --skip SMBeeE2ETests --build-path /tmp/bt \
      2>&1 | grep -E "Executed [0-9]+ tests" | tail -1
    echo "run $i exit=${PIPESTATUS[0]} (124=stall)"
  done
'
```

実測: skip 版で 8 回中 3 回が exit 124 (stall)。完了時は `Executed 115 tests ... 0 failures`、
停止時は `Executed` 行が出ない = **discovery ではなく test 実行中に hang**。

### 真因テストの特定 (`--filter` 単独ループ, `--cpus 2`)

| test | 結果 |
|---|---|
| `testConcurrentReadChunksSerializeWireTransactions` | **stall 7/15 (≈47%)** ← 主犯 |
| `testTransportCancellationPropagatesCancellationError` | stall 1/15 (副次的) |

主犯は `SMBeeTests.testConcurrentReadChunksSerializeWireTransactions`
(`Tests/SMBeeTests/SMBeeTests.swift`)。2 つの子 `Task` が `session.readChunk` を並行発行し
`SMBWireTransactionGate` で直列化、その進行を `waitForOutboundFrameCount` が
`Task.sleep(10ms)` polling で待つ構造。**Swift 6.0 Linux の cooperative thread pool** が
低コア環境で continuation 配送 / task 進行を間欠的に取りこぼし deadlock する
(`ControlledReceiveTransport` の `NSLock` + `CheckedContinuation` resume race を突く形)。

### 切り分け結論: toolchain 側の flaky hang

- **Swift 6.2 Linux / macOS では決定的に green**。同一 repo コードで 6.0 Linux のみ間欠停止。
- repo のテストロジック自体は正しい (continuation の resume 経路は網羅されている) が、
  並行 + polling パターンが 6.0 Linux runtime のスケジューリング不具合を露出させる。
- = **upstream (Swift 6.0 Linux concurrency runtime) 問題**。repo 側は「6.0 でこの並行
  test を実行しない / 書き換えて runtime 依存を減らす」で回避する。

## 次にやるなら (対処案 — 未決定)

1. Linux matrix の Swift 6.0 は `swift build` のみ (6.0 ソース互換を担保)、`swift test` は 6.2 のみ。
   ※ `swift-tools-version: 6.0` なのでコンパイル互換は 6.0 で担保し続ける。
2. 主犯 test を 6.0 Linux で `throwsUnlessEnv` / `XCTSkip` gate、または polling を
   決定論的な continuation 同期に書き換えて runtime 依存を外す。
3. 6.0 test step を `continue-on-error: true` で non-blocking 化 (signal は残す)。

## 恒久対処 (2026-07-01 実施)

案 1 を採用。あわせて Swift バージョン整合も解消した (swift-asn1 downgrade 問題)。

- `Package.swift`: `swift-tools-version` を 6.0 → **6.2** に引き上げ。
  - 背景: `swift-crypto` の推移依存 `swift-asn1` は **1.7.0 以降が Swift 6.1+ を要求**
    (1.6.0 の tools-version は 6.0)。Swift 6.0 toolchain で resolve すると asn1 が
    1.6.0 へ **自動 downgrade** され、committed の `Package.resolved` (asn1 1.7.1 /
    crypto 3.15.1) と乖離・dirty 化していた。tools-version を 6.2 にすることで 6.0
    での resolve 経路自体を塞ぎ、単一 `Package.resolved` (asn1 1.7.1) で整合する。
  - `swift-smbee` を参照する consumer は my-products 内に現状ゼロ (影響なし)。
- `.github/workflows/test.yml`: Linux matrix を `["6.0", "6.2"]` → **`["6.2"]`**。
  6.0 Linux の flaky hash を CI から排除。
- `Package.resolved`: 変更なし (HEAD は元々 asn1 1.7.1 で正しかった。1.6.0 への
  downgrade は 6.0 での resolve 時にのみ作業ツリーで発生する transient な副作用)。

再現 script (下記) は Swift 6.0 toolchain 依存の記録として残すが、CI からは 6.0 が
消えたため本 stall は再発しない。

## 完了条件

- [x] CI の stuck を回避する暫定対応を入れる。
- [x] Linux unit job に timeout を入れる。
- [x] Swift 6.0 Linux container で `swift test --skip SMBeeE2ETests` stall を **再現**した。
- [x] 最小再現条件を記録する (`--cpus 2` + `swift:6.0-noble`, 上記)。
- [x] toolchain 問題か repo 側か切り分ける (**toolchain: 6.0 Linux concurrency runtime の flaky hang**。
      主犯 test = `testConcurrentReadChunksSerializeWireTransactions`)。
- [x] 恒久対処: 案 1 採用 (Swift 6.0 を CI から除外 + tools-version 6.2 化)。
