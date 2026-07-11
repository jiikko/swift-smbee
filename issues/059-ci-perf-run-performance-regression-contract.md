# 059 ci: run-performance-regression の目的と実行契約を整理する

状態: **open**
起票: 2026-07-12
優先度: **P3**
コスト: **S**
関連: `bin/ci/run-performance-regression` / `bin/ci/test-performance-scripts` / `.github/workflows/performance.yml` / `Tests/SMBeeTests/SMBeePerformanceRegressionTests.swift` / `issues/done/052-perf-calibrate-resource-metrics-and-plan-optimization.md`

## 背景

`bin/ci/run-performance-regression` は Docker 内で `swift test --filter SMBeePerformanceRegressionTests` を実行するスクリプトである。`bin/ci/test-performance-scripts` はこのスクリプトを `bash -n` で構文検査している。現在の performance workflow は resource performance の実行経路を呼び出している。

## 問題

`bin/ci/run-performance-regression` は workflow から呼ばれておらず、`test-performance-scripts` でも実行結果を検証していない。また、実行コマンドに `-c release` がないため、`052` の resource 測定経路（Linux Release build）と実行条件が一致しない。

## 対応方針

- standalone Debug contract として維持するなら、対象 test、Debug 実行であること、workflow 外で使う目的をコメントまたは docs に明記する。
- resource performance の regression contract として不要なら、参照箇所を確認した上でスクリプトを削除する。
- いずれの方針でも、`bin/ci/test-performance-scripts` の検証内容と `052` の Release resource 測定との境界を明確にする。

## 完了条件

- [ ] 維持または削除の決定と理由がスクリプトまたは docs に記録されている。
- [ ] 維持する場合、Debug contract、対象 test、workflow から呼ばれないこと、`-c release` を付けないことが明記されている。
- [ ] 削除する場合、リポジトリ内に参照がなく、削除後も workflow と `bin/ci/test-performance-scripts` が成立する。
- [ ] `bin/ci/test-performance-scripts` が選択した契約を bash 構文検査だけでなく、検証可能な形で確認する。

