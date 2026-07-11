# 057 perf: resource performance の環境 metadata と image を固定する

状態: **done**
起票: 2026-07-12
優先度: **P2**
コスト: **M**
関連: `bin/ci/run-resource-performance` / `bin/ci/write-resource-performance-artifact` / `bin/ci/swift-image` / `.github/workflows/performance.yml` / `bin/ci/test-performance-scripts` / `issues/done/052-perf-calibrate-resource-metrics-and-plan-optimization.md`

## 背景

現在の resource performance は `bin/ci/swift-image` から `.swift-version` を使って `swift:<version>` image 名を組み立て、`bin/ci/run-resource-performance` 内で Docker 実行と測定を行う。artifact metadata には commit、Swift image、runner OS/arch、baseline run 数が保存される。

## 問題

JSONL metadata に Swift version 全文、Docker image digest、kernel、CPU model/vCPU、`GITHUB_RUN_ID`/`GITHUB_RUN_ATTEMPT`、cache hit がないため、同じ image 名でも実行環境の差を後から特定できない可能性がある。image 名だけでは取得した image の digest を識別できない。

また、毎 run の `apt-get update` と `apt-get install time` が測定 job の実行経路に含まれている。これらは `/usr/bin/time swift test` の計測区間外だが、job の実行コストと外部依存（apt repository 到達性）を増やし、環境の再現性に影響する。

コストは image digest 固定・`time` 同梱 image・metadata 拡張まで含めると M〜L 相当。

## 対応方針

- JSONL metadata に `swift --version` の全文、Docker image digest、kernel、CPU model/vCPU、`GITHUB_RUN_ID`、`GITHUB_RUN_ATTEMPT`、cache hit を追加する。
- image digest を固定する、または `/usr/bin/time` を同梱した測定用 image を用意する。
- 代替として `getrusage` ベースで取得できる測定を検討し、`time(1)` 依存を削減する。
- metadata が取得できない環境では、値を無言で省略せず未取得として明示する。

## 完了条件

- [x] JSONL の metadata に指定した環境項目が保存され、`swift --version` 全文と image digest を別々に確認できる。
- [x] 同一 image 名で digest が異なる場合に、artifact metadata から識別できる。
- [x] `GITHUB_RUN_ID` と `GITHUB_RUN_ATTEMPT` が複数試行で区別される。
- [x] 測定 run で毎回の apt install を不要にする構成、またはその時間を測定結果から明確に分離する構成が検証される。
- [x] metadata の正常値・未取得値と cache hit の fixture が `bin/ci/test-performance-scripts` で検証される。

## 進捗（完了、2026-07-12）

上記の metadata 拡張、`PERF_ENV` の parser 契約、`/usr/bin/time` の条件付き導入、summary 表示、fixture 検証を実装した。
image digest は artifact metadata へ記録し、`.swift-image-digest` に manifest list digest を固定した。
`bin/ci/update-swift-image-digest` で `.swift-version` のタグに対応する digest を更新できる。

- [x] 測定 image のタグを digest 固定指定へ変更し、更新手順を定める。
