# 091 test: run-resource-performance の docker payload を実際に評価する caller scenario を足す

- 種別: test
- 起票: 2026-09-08 ([`done/090`](done/090-test-resource-performance-inner-script-testable.md) の残タスクの切り出し)
- 状態: **open**
- 関連: `bin/ci/run-resource-performance` / `bin/ci/test-performance-scripts` /
  `.github/workflows/performance.yml`

## 問題

`bin/ci/test-performance-scripts` の docker stub は **docker の argv を記録するだけで、
`bash -c` の payload を実行しない**。そのため payload 内の分岐 —

```sh
if [ "${RESOURCE_SKIP_BUILD}" != true ]; then
  bash bin/ci/prewarm-swiftpm-artifacts
fi
```

— を無条件実行に変異させても既存テストは緑のままで、**cache-hit 経路 (`RESOURCE_SKIP_BUILD=true`)
で prewarm が誤って走る退行を検知できない**。

## なぜ今これを起票するか

この盲点は issue 090 の D3 敵対レビューが P2-7 として指摘していた。私は「変更前から同じく未検査で、
今回の変更が作った退行ではない」と判断して静的 pin だけに留めたが、**その直後の CI run で
まさにこの盲点の中の退行 (exit 127) を出した** (done/090 の追記)。

そのときは docker の argv を完全一致で pin している `expect_resource_performance_docker_argv` が
mount を検査するようになったことで塞げたが、**payload の中身の分岐**は依然として argv の
文字列としてしか見られていない。

## 完了条件

- payload を実際に評価する caller scenario があり、`RESOURCE_SKIP_BUILD=true` / `false` の両方で
  prewarm が呼ばれた / 呼ばれなかったことを marker で assert する。
- 分岐を無条件実行にする変異を当てて **red** を確認する。
- その scenario が `.github/workflows/performance.yml` の `ci-script-tests` job から実行される
  (既存 harness に足せば自動的に満たされる)。

## 設計の注意

- stub に payload を評価させると、payload 内の `swift test` / `apt-get` まで走ろうとする。
  fake を PATH に置いて封じるか、payload を関数に切り出して分岐だけを評価する形を検討する。
- fake を PATH 先頭に置くときはグローバルルール `path-shim-must-resolve-real-binary.md` に従う。

## スコープ外

- payload 全体のフル実行 (`swift test` を含む)。それは E2E / Performance workflow の仕事。
