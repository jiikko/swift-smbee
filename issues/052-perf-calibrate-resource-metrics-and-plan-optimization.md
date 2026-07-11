# 052 perf: resource metricsを校正し、測定根拠に基づく改善計画を作る

状態: **open**
起票: 2026-07-11
関連: `issues/done/004-ci-throughput-cpu-memory-regression-metrics.md` / `issues/003-ci-performance-regression-metrics.md` / `Tests/SMBeeTests/SMBeePerformanceRegressionTests.swift` / `.github/workflows/performance.yml`
観測run: https://github.com/jiikko/swift-smbee/actions/runs/29151622490

## 背景

issue 004で、Linux Release build上のsynthetic read/writeについて以下をCI Summaryへ出せるようになった。

- throughput (MiB/s)
- user/system CPU time (ms)
- XCTest process max RSS (MiB)
- workload size、run数、guardrail判定

最初の正常run (`29151622490`) では次の値を観測した。

| operation | throughput | user CPU | system CPU | XCTest max RSS |
|---|---:|---:|---:|---:|
| read | 737.364 MiB/s | 9.861 ms | 3.425 ms | 279.3 MiB |
| write | 7.313 MiB/s | 1093.225 ms | 4.260 ms | 279.3 MiB |

job全体ではRelease buildに194.21秒、wall clockに3分18.64秒、`/usr/bin/time -v`のmax RSSに
682,080 KiBを要した。実際のresource testは約3.6秒で、job時間の大半は依存関係を含むRelease buildである。

現在の値は観測開始点としては有用だが、まだ「通常範囲」や「改善目標」を決めるには不足している。
特にwrite throughputはcatastrophic guardrailの5 MiB/sに対して約1.46倍しかなく、ローカルLinuxで観測した
約14 MiB/sとの差も大きい。readは1 measured runあたり十数ms程度と短く、scheduler/timer noiseの比率が高い。

## 問題

### 1. baselineが1 runしかない

GitHub-hosted runnerのCPU世代、混雑、steal timeによる分散が不明である。単一runを基準にthresholdや
改善率を決めると、実装退行ではないrunner差でCIがflakeする。

### 2. read workloadが短すぎる

8 MiB readのuser CPUが約10 msであり、wall-clock sampleも短い。高速な経路ほど固定overheadとtimer分解能の
影響を強く受け、throughputの比較指標として不安定になる。

### 3. writeの支配コストが未分解

writeは8 MiBに約1.1秒のuser CPUを消費し、readとの差が大きい。ただし現時点では次のどれが支配的か不明である。

- SMB signing/暗号primitive
- `[UInt8]` chunk copy (`Array(data[range])`等)
- packet encode / frame append
- synthetic transportのoutbound全量保持
- actor hop / credit accounting

profile無しにコードを変更すると、測定fixtureだけを速くしたり、可読性と安全性を落として実利用には効かない
最適化を行う危険がある。

### 4. XCTest max RSSとjob max RSSの意味が異なる

- `PERF_RESOURCE *.max_rss_kb`: XCTest process全体のpeak。operation単体のallocation量ではない。
- `/usr/bin/time -v`: Release compilerを含む`swift test` process treeのpeak。

両者を混ぜて改善目標を作れない。operation固有のmemory growthを測る補助指標が必要である。

### 5. CIコストの大半が再build

`performance-regression`とは別jobなので、resource test数秒のためにRelease依存を約3分buildしている。
測定精度を守りつつ、job統合、cache、実行頻度のどれが適切か判断する必要がある。

## 目的

1. hosted runner上で再現性のある測定protocolを定義する。
2. 十分なrun数から通常範囲と分散を求める。
3. flakeしないguardrailと、性能改善の定量目標を分けて定義する。
4. profileで支配コストを特定し、効果をA/B測定できる改善backlogを作る。
5. 数秒のbenchmarkに対するCI buildコストを削減する。

## 測定計画

### Phase 1: workloadとログ形式を校正する

#### read

- 1 sampleのmeasured durationを最低200〜250 msにする。
- payloadを無条件に巨大化してRSSを増やすのではなく、8 MiB transferを同一sample内で複数iteration実行する。
- fixture生成、warmup、session生成を計測区間外へ分離できるか検討する。
- sinkはbyte/chunk countだけを保持し、受信payloadを集約しない。

#### write

- 現行8 MiBは約1秒なので、まずsizeを維持する。
- source生成とinbound response fixture生成を計測区間外へ置く。
- outbound全量保持の有無を明示し、実装測定とfixture測定を分離する。

#### 共通

- warmup 1回、measured runは最低5回とし、medianを代表値にする。
- 各sampleのraw値も`PERF_RESOURCE_SAMPLE`として保存する。medianだけでは分散やoutlierを後から評価できない。
- 次のmetadataをmachine-readableに残す。
  - commit SHA
  - Swift version
  - runner OS/arch
  - workload bytes / iterations / chunk size
  - Release configuration
- benchmark内でpayload byte countとexpected command/chunk countをassertし、速いが処理を省略した結果を排除する。

### Phase 2: baselineを収集する

- 同一workflow定義で最低20 runを収集する。
- 通常pushの自然な履歴が足りない場合、`workflow_dispatch`で同一commitを複数回実行する。
- metricごとに次を算出する。
  - median
  - p10 / p90
  - MAD (median absolute deviation)
  - coefficient of variation (参考。分布が歪む場合はMADを優先)
- read/write throughputのp10、CPU/RSSのp90を「通常の悪い側」として記録する。
- runner外れ値と実装退行を区別できるよう、job全体CPU/elapsed/RSSもartifactへ保存する。

履歴はSummaryだけに依存せず、JSONLまたはCSV artifact (`resource-performance.jsonl`) として14〜30日保持する。

### Phase 3: guardrailを決める

guardrailは「改善目標」ではなく「catastrophic regressionを落とす境界」とする。

- throughput lower bound:
  - baseline p10より十分低い値、または`median - 6 * MAD`
  - 少なくとも連続20 runでfalse positiveが0であること
- CPU upper bound:
  - runner差が安定したmetricだけ`median + 6 * MAD`を候補にする
  - 安定しなければObserveのままにする
- RSS upper bound:
  - XCTest process peakとoperation growth proxyを別々に定義する
  - process peakは絶対上限、growth proxyはpayload倍率に対するscalingで判定する

現行write 5 MiB/s thresholdはbaseline収集完了まで暫定値とする。7.313 MiB/sという単一観測との距離が小さいため、
flakeが出る場合は3 MiB/sへ緩和するかObserveへ戻し、測定基盤の失敗と製品性能退行を混同しない。

### Phase 4: profileで支配コストを特定する

同じcommit/fixtureで次を個別に測る。

1. codec only: WRITE packet encodeのみ
2. signing only: 固定packetへのsignature生成
3. session write: transport sendまで（outbound保持なし）
4. full synthetic write: 現行benchmark

macOSではInstruments/Time ProfilerとAllocations、Linuxでは`perf stat` / `perf record`（利用可能な環境）を使い、
次を確認する。

- top CPU symbols
- allocation count / allocated bytes
- copy回数と最大一時buffer
- chunkごとのactor hop数

profile結果にはsymbol別比率と再現commandを残す。推測だけの最適化taskは作らない。

### Phase 5: 改善backlogと目標を作る

profileで全体CPUの10%以上を占める、またはpayload増加に対して超線形に増える箇所だけを候補にする。
各候補は次の形式で記録する。

- hypothesis: 何が遅いか
- change: どのcopy/allocation/algorithmを変えるか
- expected effect: 対象metricを何%改善するか
- safety constraints: wire互換性、cancellation、data integrityを維持する条件
- A/B result: 同一runner/同一workloadでbefore/afterを交互に測ったmedianとMAD

最初の改善目標はbaseline収集後に決める。暫定的には次を「調査trigger」とし、達成義務にはしない。

- write user CPUがreadに比べて極端に大きい理由を説明できること
- write throughputのhosted-runner medianを現行値から20%以上改善できる候補を1件以上評価すること
- payloadを2倍にしたときXCTest RSSがpayload以上の倍率で増えないこと

### Phase 6: CIコストを削減する

測定の独立性を壊さない範囲で次を比較する。

1. `performance-regression`とresource testsを同一Release jobへ統合
2. SwiftPM `.build` cacheの利用
3. PRではdeterministic testのみ、resource testはmaster push/scheduleで実行

run `29151622490`ではbenchmark数秒に対してbuildが194秒なので、build再利用でjob時間を50%以上削減できるかを
目標にする。cache導入時は古いartifact混入を避けるkey (`Package.resolved`, Swift version, OS, arch) を使う。

## 成功判定

測定基盤は次を満たしたとき「問題ない」とする。

- 同一commit 20 runでguardrail false positiveが0。
- read/writeの各measured sampleが200 ms以上、または短い理由と誤差範囲が示されている。
- Summaryに代表値、良い方向、guardrail、Pass/Observe、workloadが表示される。
- raw sampleとrunner metadataがartifactに保存され、median/MADを再計算できる。
- CPU/RSSのObserve metricを、根拠なくCI failure条件へ昇格しない。
- benchmarkが処理byte数、command数、chunk数のcorrectness contractを同時に検証する。

性能改善は次を満たしたとき採用する。

- profileで対象箇所が支配コストであることを確認済み。
- 同一条件のA/Bでmedianが改善し、MADを考慮しても差が残る。
- full unit suiteとSamba E2Eがgreen。
- throughput改善のためにdata integrity、署名、cancellation、cleanup semanticsを弱めていない。

## 完了条件

- [ ] read measured durationを安定区間へ延長する。
- [ ] measured runを5回以上にし、raw sampleを出力する。
- [ ] JSONL/CSV artifactとrunner metadataを保存する。
- [ ] 同一workflowで20 run以上のbaselineを収集する。
- [ ] metricごとのmedian/p10/p90/MADを記録する。
- [ ] false positive 0を確認してguardrailを確定する。
- [ ] write経路をcodec/signing/session/fullの段階に分けてprofileする。
- [ ] profile根拠付きの最適化候補とA/B測定結果を作る。
- [ ] XCTest RSSとjob全体RSSをSummary上で区別する。
- [ ] resource-performanceのbuild時間を50%以上削減する案を検証する。
