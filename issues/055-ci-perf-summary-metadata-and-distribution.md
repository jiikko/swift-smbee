# 055 perf: CI summary に実行 metadata と metric 分布を追加する

状態: **open**
起票: 2026-07-12
優先度: **P2**
コスト: **M**
関連: `bin/ci/publish-resource-performance-summary` / `bin/ci/write-resource-performance-artifact` / `bin/ci/summarize-resource-baseline` / `bin/ci/test-performance-scripts` / `.github/workflows/performance.yml` / `issues/done/052-perf-calibrate-resource-metrics-and-plan-optimization.md`

## 背景

resource performance の JSONL には commit、Swift image、runner、baseline run 数などの metadata と summary/sample 行があり、`bin/ci/summarize-resource-baseline` は複数値の統計を出力できる。job summary は `bin/ci/publish-resource-performance-summary` が生成する。

## 問題

job summary だけでは、異なる環境や実行条件の値を比較するための commit SHA、Swift image、runner、baseline run 数、sample 数、cache hit がまとまって表示されない。metric ごとの分布も現在の summary 表では代表値中心で、MAD、範囲または p10–p90、raw sample 数を確認しにくい。

また、whole `swift test` の RSS 表示では、`printf "%.1f"` に整数除算した `$((process_rss / 1024))` を渡しているため、小数精度がない。

## 対応方針

- job summary の先頭に commit SHA、Swift image、runner、baseline run 数、sample 数、cache hit を表示する。
- metric ごとに median に加えて MAD、min–max または p10–p90、raw sample 数を表示する。aggregation の単位と対象も明示する。
- process RSS の KiB から MiB への変換を浮動小数として行い、小数表示を保持する。
- JSONL に必要な metadata がない場合の表示も定義し、数値の出所を追跡できるようにする。

## 完了条件

- [ ] summary に commit SHA、Swift image、runner、baseline run 数、sample 数、cache hit が表示される。
- [ ] throughput、CPU、RSS、duration など表示対象 metric に median、MAD、分布（min–max または p10–p90）、raw sample 数が表示される。
- [ ] process RSS の表示が整数除算を使わず、fixture の 682080 KiB を 666.1 MiB と表示する。
- [ ] metadata 欠落時の表示と、実際の cache hit 値の入力元がテストで検証される。
- [ ] `bin/ci/test-performance-scripts` が新しい summary の全必須項目と統計値を検証する。

