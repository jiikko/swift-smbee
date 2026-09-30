# 091 test: run-resource-performance の docker payload を実際に評価する caller scenario を足す

- 種別: test
- 起票: 2026-09-08 ([`done/090`](090-test-resource-performance-inner-script-testable.md) の残タスクの切り出し)
- 状態: **完了**（2026-09-30。下の「対応」節）
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

## 対応（2026-09-30、codex-lead で codex が方針をリード）

方針は「設計の注意」の 2 つ目（payload を関数に切り出して分岐だけを評価する）。payload は `/usr/bin/time -v swift test` を
絶対パスで呼ぶので、1 つ目（fake を PATH に置いて封じる）では止められない。

- `test(ci): issue 091 — resource performance の container 内の手順をスクリプトに切り出し、prewarm の分岐を実行して検査する`
  - payload を `bin/ci/resource-performance-container` へ切り出し、手順ごとの関数（install_time / reset_log / prepare_build /
    measure / publish_permissions）と `resource_performance_main` に分けた。prewarm と同じく SCRIPT_DIR から mount して
    `bash bin/ci/resource-performance-container` で呼ぶ（paired run の古い worktree には無いため）
  - `test_resource_performance_container_prewarm_branch`: スクリプトを source し、/usr/bin/time・swift・/root が要る 3 関数だけを
    差し替えて本物の `resource_performance_main` を scratch の workspace で走らせる。`RESOURCE_SKIP_BUILD=false` で prewarm が
    ちょうど 1 回、`true` で 0 回を marker で assert し、手順の順序も確かめる
  - docker argv の pin を payload の部分一致（先頭 25 行）から argv 全体の一致へ。payload の文字列 pin（time の fallback・環境情報）は
    スクリプト側へ移した。旧 wiring の字句 pin は上の scenario で置き換え、bash 3.2 の配列展開 pin は独立の scenario に残した
- `test(ci): issue 091 — prewarm 分岐の assert に失敗理由を出す`

### 検証

- `bin/ci/test-performance-scripts`: ran 25 scenarios、rc=0
- 変異検証（使い捨て worktree）: 分岐を無条件にする → "prewarm ran on the exact build-cache hit path" で red /
  main から prepare を外す → "prewarm must run exactly once" で red / 呼び出し側の mount を落とす →
  `test_run_resource_performance_log_path` の argv pin で red
- codex レビュー: Pass B（実装正当性）指摘 0 件。Pass C（敵対的）は paired run・旧 payload との挙動差・false green・scenario 数を攻めて
  壊せなかった

### 未確認リスク（記録）

- Pass C P2: `resource_performance_install_time`（apt-get）と `resource_performance_measure`（`swift test | tee`）の失敗伝播は、
  scenario が差し替えるので検査していない。旧 payload のときから未検査の範囲で、payload 全体の実行はこの issue のスコープ外。
  実 docker の Performance workflow が通ることで間接的に守られる
