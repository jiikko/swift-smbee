# 058 perf: Observe 用の CPU 正規化 metric を追加する

状態: **open**
起票: 2026-07-12
優先度: **P3**
コスト: **M**
関連: `bin/ci/publish-resource-performance-summary` / `bin/ci/write-resource-performance-artifact` / `Tests/SMBeeTests/SMBeePerformanceRegressionTests.swift` / `bin/ci/test-performance-scripts` / `.github/workflows/performance.yml` / `issues/done/052-perf-calibrate-resource-metrics-and-plan-optimization.md`

## 背景

resource performance のログには throughput、elapsed、user CPU、system CPU、RSS があり、write stage ごとの `PERF_WRITE_PROFILE` も出力される。`052` は CPU/RSS の Observe metric を根拠なく failure 条件へ昇格しない方針を示している。

## 問題

現在の summary と JSONL は CPU 時間を絶対値で表示しているため、workload size や elapsed の異なる測定を比較しにくい。write stage profile も stage ごとの時間・throughput はあるが、全体に占める比率を直接確認できない。

## 対応方針

- Observe-only の metric として、user/system CPU ms per MiB、CPU utilization（`(user + system) / elapsed`）、write stage profile ごとの比率を Summary と JSONL に追加する。
- 単位、分母（workload bytes または measured elapsed）、ゼロ除算時の扱いを契約化する。
- これらの metric を guardrail の failure 条件には昇格させず、`052` の決定を維持する。

## 完了条件

- [ ] JSONL に user/system CPU ms per MiB、CPU utilization、write stage 比率が保存される。
- [ ] Summary に各 metric の値、単位、Observe-only であることが表示される。
- [ ] workload size、elapsed、stage 時間から計算した期待値を fixture で検証する。
- [ ] elapsed や workload がゼロまたは欠落する入力の扱いが非曖昧で、テストされる。
- [ ] 新しい metric が guardrail の failure 判定、workflow の exit status、既存の throughput/RSS 判定を変更しない。

