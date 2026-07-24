# AI agent performance verification

Codex、Claude Code、その他のagentがperformance-sensitiveな実装をpushした場合、作業完了前に次を実行する。

```sh
bin/ci/verify-agent-performance
```

引数を省略すると`HEAD`を検証する。commitを明示する場合:

```sh
bin/ci/verify-agent-performance <full-commit-sha>
```

このコマンドは対象SHAの`Performance` workflowを最大90分待ち、次を機械的に検証する。

- workflowと必須stepがsuccess
- current/referenceを同一CPUで20ペア測定
- ペア順がAB/BA交互
- regression gateがsuccess
- current/reference双方のraw logとJSONL artifactが存在
- artifactからpaired effect、95% CI、Holm補正p値を再計算してgateがPASS

終了コードが0になるまで、agentはperformance-sensitiveな作業を完了扱いにしてはいけない。失敗時はrun URLと
失敗stepを調査・修正して再pushし、replacement runに対して再実行する。比較不能・gate skipは成功として扱わない。

performance-sensitiveに含むもの:

- `Sources/SMBee/`のtransport、framing、codec、session、signing、encryption
- READ / WRITE / streaming / transfer chunking / credit accounting
- performance benchmark、集計script、threshold、Performance workflow
- CPU、memory、allocation、copy回数、I/O command数に影響し得る最適化

docsのみ、コメントのみ、performanceと無関係なtest fixtureのみの変更では必須ではない。ただし判断に迷う場合は実行する。
