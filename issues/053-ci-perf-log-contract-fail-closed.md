# 053 perf: PERF_* ログ形式を契約化し解析失敗を fail-closed にする

状態: **open**
起票: 2026-07-12
優先度: **P1**
コスト: **L**
関連: `bin/ci/run-resource-performance` / `bin/ci/write-resource-performance-artifact` / `bin/ci/publish-resource-performance-summary` / `bin/ci/test-performance-scripts` / `.github/workflows/performance.yml` / `issues/done/052-perf-calibrate-resource-metrics-and-plan-optimization.md`

## 背景

resource performance の測定ログは `bin/ci/run-resource-performance` が出力し、artifact と job summary は別のスクリプトが読み取っている。`052` では raw sample、metadata、guardrail、baseline の再計算可能性を測定基盤の条件としている。

## 問題

`bin/ci/write-resource-performance-artifact` と `bin/ci/publish-resource-performance-summary` は、それぞれ独立した awk で `PERF_*` 行をパースしている。ログ形式が変更された場合、必須フィールドが空の JSON を生成したり、summary に `Unavailable` を表示したりしても、解析処理自体が非ゼロ終了にならず、workflow が緑のまま通過する可能性がある。完了した測定 run と、途中で壊れた出力を区別する契約もない。

## 対応方針

- `PERF_FORMAT version=<整数>` の形式バージョンマーカーと、全測定・全出力が完了したことを示す `PERF_RUN_COMPLETE` 完了マーカーを test 出力およびスクリプトの契約に追加する。
- `bin/ci/parse-resource-performance` などの共通 parser（Python 実装可）を追加し、artifact 作成と summary 作成が同じ検証済みデータを利用する。
- 形式バージョン、完了マーカー、必須フィールド、数値形式、期待 sample 数を検証する。フィールド欠落、不正数値、malformed 行、成功 run における期待 sample 数不足は exit 非0 とする。
- `bin/ci/test-performance-scripts` に、フィールド欠落、不正数値、malformed 行、`throughput == floor`、`rss == 512 MiB`、`duration == 200 ms`、複数 baseline run の fixture と異常系アサーションを追加する。

## 完了条件

- [ ] PERF ログ形式と version marker、run 完了 marker が文書化され、producer と consumer が同じ parser を使用する。
- [ ] 必須フィールド欠落、不正数値、malformed 行、形式バージョン不一致、完了 marker 欠落で各解析スクリプトが非ゼロ終了する。
- [ ] 成功 run では期待 sample 数を検証し、欠落時に artifact や `Unavailable` summary を成功扱いしない。
- [ ] 境界値（throughput が floor と同値、RSS が 512 MiB と同値、duration が 200 ms と同値）が仕様どおり判定される。
- [ ] 複数 baseline run の fixture が全 run の sample と metadata を検証する。
- [ ] `bin/ci/test-performance-scripts` が正常系・異常系 fixture を実行して green になる。

