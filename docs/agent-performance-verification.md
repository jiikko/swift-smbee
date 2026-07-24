# AI agent performance verification

Codex、Claude Code、その他のagentがpushした場合、作業完了前に次を実行する。

```sh
bin/ci/verify-agent-push
```

引数を省略すると`HEAD`を検証する。commitを明示する場合:

```sh
bin/ci/verify-agent-push <full-commit-sha>
```

このコマンドは対象SHAの`Test`、`E2E`、`Performance` workflowを並行して待つ。失敗時は
失敗jobとlogのエラー要点を表示し、成功時はPerformance artifactをダウンロードして次を機械的に検証する。

- 3 workflowと必須jobがsuccess
- workflowと必須stepがsuccess
- current/referenceを同一CPUで20ペア測定
- ペア順がAB/BA交互
- regression gateがsuccess
- current/reference双方のraw logとJSONL artifactが存在
- artifactからpaired effect、95% CI、Holm補正p値を再計算してgateがPASS

終了コードが0になるまで、agentはpush後の作業を完了扱いにしてはいけない。失敗時はrun URLと
失敗stepを調査・修正して再pushし、replacement runに対して再実行する。比較不能・gate skipは成功として扱わない。

`bin/ci/verify-agent-performance`はPerformanceだけを再検証する低レベルコマンドとして残す。通常は
workflow探索、失敗log取得、最終状態確認の往復を省ける`verify-agent-push`を使う。

performance-sensitiveに含むもの:

- `Sources/SMBee/`のtransport、framing、codec、session、signing、encryption
- READ / WRITE / streaming / transfer chunking / credit accounting
- performance benchmark、集計script、threshold、Performance workflow
- CPU、memory、allocation、copy回数、I/O command数に影響し得る最適化

Performanceの詳細検証は全pushで実行されるため、agentが変更種別を判断して省略しない。
