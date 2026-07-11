# 004 ci: throughput / CPU / memory の性能退行を補助指標として計測する

状態: **open**
起票: 2026-07-01
関連: `issues/003-ci-performance-regression-metrics.md` / `.github/workflows/test.yml` / `Tests/SMBeeTests/SMBeePerformanceRegressionTests.swift`

## 背景

`issues/003` と現行 `SMBeePerformanceRegressionTests` は、GitHub Actions の環境差で flake しにくいように、主に以下の deterministic proxy を固定している。

- SMB command count
- read/write chunk count
- read/write payload byte count
- persistent session reuse count

これは正しい。wall-clock time を pass/fail の主条件にすると、runner の混雑、CPU世代、仮想化、ファイルI/O、thermal throttling の影響を受けて不安定になる。

ただし、command count / chunk count が同じでも、以下の退行は入り得る。

- chunk ごとに余計な copy / allocation が増えて throughput が落ちる
- `Data` / `[UInt8]` の累積 append で CPU 使用量が増える
- streaming 経路のつもりが内部で full buffer を保持して max RSS が増える
- signing / transform / parser / path handling の変更で user CPU time が増える
- 実行時間はギリギリ許容だが、CPU効率やmemory footprintが悪化する

そのため、`003` の deterministic CI gate とは別に、**throughput / CPU / memory を補助指標としてログ化し、安定したものからゆるいguardrailに昇格する**。

## 目的

CIで以下を観測できるようにする。

- synthetic read / write stream の throughput
- synthetic workload の user CPU time / system CPU time
- synthetic workload の max RSS / heap growth proxy
- resource 指標の履歴比較に使える machine-readable log

初期段階では、これらを細かい pass/fail 条件にしない。まず計測値を蓄積し、環境差とばらつきを見たうえで、明らかな退行だけを落とす。

## 方針

### 原則

1. **既存 `performance-regression` job の deterministic contract を壊さない。**
   - command count / chunk count / byte count は引き続き `SMBeePerformanceRegressionTests` が見る。
   - throughput / CPU / memory は別 test class か別 job に分離する。

2. **Debug build ではなく Release build で測る。**
   - `swift test` のデフォルト Debug は最適化されておらず、throughput / CPU の指標として弱い。
   - CIでは `swift test -c release --filter SMBeeResourcePerformanceTests` を使う。

3. **実networkには依存しない。**
   - まず `PerformanceInMemoryTransport` 相当の synthetic transport を使う。
   - 実 Samba / macOS SMBX / NAS / Windows Server の実測は別系統の manual benchmark とする。

4. **最初は PERF_INFO としてログ化する。**
   - fail条件にするのは、明らかな異常だけ。
   - 例: max RSS が 512MB を超える、throughput が 5MiB/s 未満、のような catastrophic guardrail。
   - 厳密な基準は数回CIで観測してから決める。

## 実装アイディア

### 1. `SMBeeResourcePerformanceTests` を追加する

新規ファイル候補:

```text
Tests/SMBeeTests/SMBeeResourcePerformanceTests.swift
```

テスト対象は最初は2本でよい。

```swift
final class SMBeeResourcePerformanceTests: XCTestCase {
    func testSyntheticReadStreamResourceUsage() async throws
    func testSyntheticWriteStreamResourceUsage() async throws
}
```

各テストは以下を行う。

- 8MiB〜64MiB程度の synthetic payload を用意する
- warmup を1回走らせる
- measured run を3回程度走らせ、median を取る
- sink/source は payload を再集約せず、byte count だけを数える
- metric を `PERF_RESOURCE` 形式でprintする

ログ例:

```text
PERF_RESOURCE read_stream.throughput_mib_s value=820.4 size_mib=32 runs=3 config=release
PERF_RESOURCE read_stream.user_cpu_ms value=41.2 size_mib=32 runs=3 config=release
PERF_RESOURCE read_stream.system_cpu_ms value=8.5 size_mib=32 runs=3 config=release
PERF_RESOURCE read_stream.max_rss_kb value=74240 size_mib=32 runs=3 config=release
```

### 2. throughput 計測

計算式:

```text
throughput_mib_s = bytesProcessed / elapsedSeconds / 1024 / 1024
```

実装案:

```swift
let clock = ContinuousClock()
let start = clock.now
try await runSyntheticRead(size: size)
let elapsed = start.duration(to: clock.now)
let mibPerSecond = Double(size) / elapsed.seconds / 1024 / 1024
```

`Duration` から秒へ変換する helper をテスト側に置く。

```swift
extension Duration {
    var secondsAsDouble: Double {
        let components = self.components
        return Double(components.seconds) + Double(components.attoseconds) / 1_000_000_000_000_000_000
    }
}
```

注意:

- CI runner差が大きいので初期は `XCTAssertGreaterThan` を置かない。
- 置くとしても catastrophic threshold にする。
- `-c release` で実行しないと値がノイズになる。

### 3. CPU 使用量計測

Linux / macOS どちらでも使いやすい `getrusage(RUSAGE_SELF)` を使う。

計測対象:

- user CPU time
- system CPU time
- max RSS

実装イメージ:

```swift
import Glibc

struct ResourceSnapshot {
    var userMicros: Int64
    var systemMicros: Int64
    var maxRSSKilobytes: Int64
}

func resourceSnapshot() -> ResourceSnapshot {
    var usage = rusage()
    getrusage(RUSAGE_SELF, &usage)
    return ResourceSnapshot(
        userMicros: Int64(usage.ru_utime.tv_sec) * 1_000_000 + Int64(usage.ru_utime.tv_usec),
        systemMicros: Int64(usage.ru_stime.tv_sec) * 1_000_000 + Int64(usage.ru_stime.tv_usec),
        maxRSSKilobytes: Int64(usage.ru_maxrss)
    )
}
```

cross-platform化する場合:

```swift
#if os(Linux)
import Glibc
#else
import Darwin
#endif
```

注意:

- `ru_maxrss` の単位はLinuxではKB、Darwinではbyte扱いになることがあるため、platformごとに正規化する。
- `RUSAGE_SELF` はprocess全体なので、同じtest process内の前段テストの影響を受ける。
- max RSSは単調増加なので、testごとの差分より「job全体の上限 guardrail」として扱うほうが安定する。

### 4. memory 使用量の補助指標

`getrusage` の max RSS だけでは細かいallocation退行は見えない。初期は以下のproxyを併用する。

- sinkが保持するchunkを0にする
- callback countとbyte countだけ保持する
- synthetic payload sizeを2倍にしてもmax RSSが線形以上に増えないかを見る
- full buffer APIとstreaming APIの差を明示する

実装アイディア:

```swift
final class CountingDiscardingSink: @unchecked Sendable {
    private let lock = NSLock()
    private var chunks = 0
    private var bytes = 0

    func record(_ chunk: [UInt8]) {
        lock.withLock {
            chunks += 1
            bytes += chunk.count
        }
    }
}
```

禁止したい退行:

```swift
var all = Data()
for try await chunk in stream {
    all.append(contentsOf: chunk)
}
```

streaming performance test では、上記のような full aggregation を使わない。

### 5. `/usr/bin/time -v` でjob全体のRSSもログ化する

Swift test内の `getrusage` とは別に、CI job全体の resource usage もログに残す。

```yaml
resource-performance:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: swift-actions/setup-swift@v2
      with:
        swift-version: "6.2"
    - name: Resource performance tests
      timeout-minutes: 10
      run: |
        /usr/bin/time -v swift test -c release --filter SMBeeResourcePerformanceTests
```

`/usr/bin/time -v` で見られる代表値:

- User time
- System time
- Percent of CPU
- Elapsed wall clock time
- Maximum resident set size
- File system inputs/outputs

最初は raw log で十分。必要になったら parser script で `PERF_RESOURCE process.max_rss_kb ...` に整形する。

### 6. optional: dedicated benchmark executable

XCTestはpass/fail中心なので、将来的に計測が増えるなら executable target を切る。

候補:

```text
Benchmarks/SMBeeResourceBenchmarks
```

または SwiftPM executable target:

```text
Sources/SMBeeBenchmark/main.swift
```

CLI出力:

```text
PERF_RESOURCE read_stream.throughput_mib_s value=...
PERF_RESOURCE write_stream.throughput_mib_s value=...
PERF_RESOURCE process.max_rss_kb value=...
```

メリット:

- test runnerのoverheadを避けられる
- workloadを明示的に選べる
- `swift run -c release SMBeeBenchmark --json` のようにCI artifact化しやすい

デメリット:

- targetが増える
- benchmark維持コストが増える
- 初期段階ではXCTestで十分

## CI設計案

既存 job とは分ける。

```yaml
resource-performance:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Set up Swift
      uses: swift-actions/setup-swift@v2
      with:
        swift-version: "6.2"
    - name: Swift version
      run: swift --version
    - name: Resource performance tests
      timeout-minutes: 10
      run: |
        /usr/bin/time -v swift test -c release --filter SMBeeResourcePerformanceTests
```

初期運用:

- PR必須jobにする場合も、fail条件は catastrophic guardrail のみ
- thresholdは少なくとも数回CI実行してから決める
- `PERF_RESOURCE` logをPRコメント化するのは later

## 閾値案

初期は以下のように段階的にする。

### Phase 1: logging only

- throughput / CPU / RSS を `PERF_RESOURCE` として出す
- test failureにしない
- `/usr/bin/time -v` も raw log で残す

### Phase 2: catastrophic guardrail

例:

- 32MiB synthetic read/write が10分 timeoutしない
- process max RSS が512MiBを超えない
- throughput が極端に低くない
  - 例: `read_stream.throughput_mib_s > 20`
  - 例: `write_stream.throughput_mib_s > 20`

この値は仮。GitHub Actionsで複数回観測してから決める。

### Phase 3: baseline比較

baseline JSONをrepoに持つか、GitHub Actions artifactから比較する。

```json
{
  "read_stream.throughput_mib_s": { "median": 800, "allowed_drop_ratio": 0.5 },
  "write_stream.throughput_mib_s": { "median": 650, "allowed_drop_ratio": 0.5 },
  "process.max_rss_kb": { "max": 262144 }
}
```

ただし baseline 比較は flaky になりやすいので、PR必須gateではなく nightly / manual workflow のほうが安全。

## 実装手順

1. `SMBeeResourcePerformanceTests.swift` を追加する。
2. `ResourceSnapshot` helper を test-only で追加する。
3. `ContinuousClock` で wall elapsed を取り、throughputを計算する。
4. `getrusage` で user/system CPU time と max RSS を取る。
5. read/write synthetic workload を用意する。
6. `PERF_RESOURCE ...` 形式でログ出力する。
7. `.github/workflows/test.yml` に `resource-performance` job を追加する。
8. 最初は logging only で運用する。
9. CI数回分の値を見て catastrophic guardrail を決める。
10. 必要なら later で benchmark executable / JSON artifact / nightly workflow に分離する。

## 完了条件

- [ ] `SMBeeResourcePerformanceTests` を追加する。
- [ ] synthetic read stream の throughput / CPU / max RSS をログ出力する。
- [ ] synthetic write stream の throughput / CPU / max RSS をログ出力する。
- [ ] `PERF_RESOURCE` 形式のログを出す。
- [ ] CIに `resource-performance` job を追加する。
- [ ] `swift test -c release --filter SMBeeResourcePerformanceTests` で実行する。
- [ ] `/usr/bin/time -v` のraw logをCIに残す。
- [ ] 初期はlogging onlyまたはcatastrophic guardrailに留める。
- [ ] 厳密なthroughput閾値をいきなりPR必須gateにしない。

## やらないこと

- 最初からGitHub Actionsのwall-clock timeに厳密な閾値を置くこと。
- 実NAS / Windows Server / macOS SMBX の実転送速度をPR必須CI gateにすること。
- memory allocation byte数の厳密測定を最初から入れること。
- benchmark frameworkを先に導入すること。
- Debug buildの値を性能指標として扱うこと。
