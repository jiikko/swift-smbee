# 056 perf: 過去の成功 run と resource performance を比較する

状態: **done**
起票: 2026-07-12
優先度: **P2**
コスト: **L**
関連: `bin/ci/publish-resource-performance-summary` / `bin/ci/write-resource-performance-artifact` / `bin/ci/summarize-resource-baseline` / `.github/workflows/performance.yml` / `bin/ci/test-performance-scripts` / `issues/done/052-perf-calibrate-resource-metrics-and-plan-optimization.md`

## 背景

`.github/workflows/performance.yml` は resource performance の JSONL artifact を upload し、現在の summary はその run の値を表示する。`052` は履歴比較を guardrail とは分離し、観測と改善判断に使う方針を示している。

## 問題

現在の summary には、前回の master 成功 run と比較した throughput、CPU、RSS の変化率がない。同じ測定条件での改善・悪化を run 間で確認するには、artifact の取得と metadata の照合が必要である。

## 対応方針

- `bin/ci/compare-resource-performance` を追加する。スクリプトは検証済み JSONL 同士だけを比較し、GitHub API による artifact 選択・取得は workflow 側で行う。比較対象は「同一 workflow の `push` イベント run かつ `conclusion == success`」に限定し、artifact 名と保持期限（30日）を選択条件に含める。
- 比較する RSS は XCTest process の `max_rss_kb`（`PERF_RESOURCE` 由来）に固定し、`/usr/bin/time` の process tree RSS とは混同しない。workload の照合は summary 行の `size_mib`/`runs`/`iterations` を正とする（metadata 行には workload が無い）。
- swift image、runner、workload の metadata が一致する場合だけ throughput、CPU、RSS の median 増減率を計算し、job Summary に advisory として表示する。
- 初回、fork PR、artifact 期限切れ、取得失敗、metadata 不一致など比較不能な場合は `No comparable baseline` と明示する。
- 比較結果は failure 条件や guardrail に使わず、`052` の決定を維持する。

## 完了条件

- [x] `actions:read` を含む最小権限と、master 成功 run の選択条件が workflow/docs に明記される。
- [x] metadata 一致時に throughput、user/system CPU、RSS の metric ごとの median 増減率が Summary に表示される。
- [x] 初回、fork PR、artifact 期限切れ、API取得不能、metadata 不一致で `No comparable baseline` が表示され、job は失敗しない。
- [x] 比較結果が guardrail 判定や exit status を変更しないことをテストで検証する。
- [x] 複数 baseline run と同一・不一致 metadata の fixture が `bin/ci/test-performance-scripts` で検証される。

## 実装メモ

fork PR では previous artifact download step 自体をスキップする設計とした。実 CI での GitHub API/artifact 動作確認は人間または後続 run に委ねる。
