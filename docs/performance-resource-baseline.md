# SMBee resource performance baseline

基準run: https://github.com/jiikko/swift-smbee/actions/runs/29155604555

- commit: `4faea896f7a312b6c7173a0adb2f27a7398b14be`
- Swift image: `swift:6.2`
- runner: `Linux/X64` (GitHub-hosted `ubuntu-latest`)
- baseline invocations: 20
- raw samples: 200 (read 100 / write 100)
- read workload: 160 MiB/sample (8 MiB × 20 transfer intervals)
- write workload: 8 MiB/sample

## Resource log contract (version 1)

`bin/ci/run-resource-performance` のログは `bin/ci/parse-resource-performance` が検証する。
各 `PERF_BASELINE_RUN run=N total=M` の後、resource 測定テスト開始時に
`PERF_FORMAT version=1` を出力する（resource operation ごとに1回）。必須行は
`PERF_RESOURCE_SAMPLE` と `PERF_RESOURCE` で、`read_stream` と `write_stream` の各 operation に
ついて、sample 数が対応する `PERF_RESOURCE ... runs=` と一致し、5つの resource metric が揃う必要がある。
各 operation の全 `assertAndPrint` 完了後に `PERF_RUN_COMPLETE operation=<operation>` を出力する。
baseline run は1から連続し、重複や欠落は失敗扱いとする。

`PERF_ENV`、`PERF_BUILD_CACHE`、`PERF_METRIC`、`PERF_WRITE_PROFILE`、`Maximum resident set size (kbytes):` は任意行だが、
存在する場合も数値とフィールドを parser が検証する。未知の `PERF_*` 行、必須フィールド欠落、
形式 version 不一致、完了 marker 欠落は解析失敗となる。artifact と job summary はこの共通 parser
の検証済み JSONL のみを利用する。`PERF_ENV <key> <自由テキスト>` の key は
`swift_version`、`kernel`、`cpu_model`、`cpu_count` に限定し、key の重複は解析失敗となる。
job summary の先頭には commit、Swift image、image digest、GitHub run ID/attempt、Swift version 全文、
kernel、CPU、runner、baseline run 数、operation 別 raw sample 数、build cache exact hit と、metric ごとの
代表値／分布（MAD・min–max・N）が表示される。

parser は検証済みの summary 行と write profile 行から、producer のログには現れない派生行も JSONL に追加する。
これらはログ形式 version 1 の producer 契約を変更しない parser 生成データである。

- `{"type":"derived","baseline_run":N,"operation":...}` は、summary の user/system CPU median を
  operation の `size_mib`（`PERF_RESOURCE_SAMPLE` の `total_size_mib`）で割った user/system CPU ms/MiB と、
  user + system CPU median を `sample_elapsed_ms` median で割った CPU utilization（比率）を持つ。
  workload または elapsed の分母が 0 または欠落する場合、該当値は JSON `null` となり、job summary では `n/a` と表示する。
  read の 160 MiB/sample と write の 8 MiB/sample は異なるため、ms/MiB を operation 間で直接比較しない。
- `{"type":"derived_stage","baseline_run":N,"stage":...}` は、同一 baseline の
  `PERF_WRITE_PROFILE` の `median_ms` を `full_synthetic` の `median_ms` で割った比率を持つ。
  `full_synthetic` がない場合はこの派生行を出力しない。分母が 0 の場合は比率を JSON `null` とする。

CPU efficiency と write stage の比率は Observe-only であり、guardrail の判定、workflow の exit status、
既存の throughput/RSS 判定を変更しない。

## Per-invocation representative metrics

各invocationは5 raw samplesのmedianを代表値とする。次の表は20代表値の分布。

| Metric | N | Median | p10 | p90 | MAD | CV | Min | Max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `read_stream.max_rss_kb` | 20 | 128480.000 | 124981.200 | 131691.200 | 316.000 | 0.2415 | 124668.000 | 278964.000 |
| `read_stream.sample_elapsed_ms` | 20 | 283.340 | 278.704 | 295.179 | 2.833 | 0.0348 | 267.460 | 314.630 |
| `read_stream.system_cpu_ms` | 20 | 28.170 | 24.929 | 34.139 | 1.440 | 0.1188 | 24.399 | 37.672 |
| `read_stream.throughput_mib_s` | 20 | 564.693 | 542.146 | 574.090 | 5.703 | 0.0332 | 508.534 | 598.221 |
| `read_stream.user_cpu_ms` | 20 | 306.918 | 300.677 | 321.635 | 3.451 | 0.0365 | 293.463 | 344.745 |
| `write_stream.max_rss_kb` | 20 | 128480.000 | 124981.200 | 131691.200 | 316.000 | 0.2415 | 124668.000 | 278964.000 |
| `write_stream.sample_elapsed_ms` | 20 | 1096.191 | 1091.404 | 1188.414 | 4.549 | 0.0476 | 1088.418 | 1299.748 |
| `write_stream.system_cpu_ms` | 20 | 0.000 | 0.000 | 0.000 | 0.000 | 0.0000 | 0.000 | 0.000 |
| `write_stream.throughput_mib_s` | 20 | 7.298 | 6.732 | 7.330 | 0.030 | 0.0434 | 6.155 | 7.350 |
| `write_stream.user_cpu_ms` | 20 | 1102.052 | 1097.485 | 1194.177 | 4.274 | 0.0473 | 1095.107 | 1305.863 |

## Raw sample throughput

| Operation | N | Median | p10 | p90 | MAD | CV | Min | Max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `read_stream` | 100 | 564.343 | 515.649 | 594.861 | 14.562 | 0.0617 | 451.390 | 620.329 |
| `write_stream` | 100 | 7.303 | 6.635 | 7.350 | 0.038 | 0.0494 | 5.393 | 7.379 |

## Process RSS

- first invocation (Release buildを含む): 666.7 MiB
- warm invocation median: 127.3 MiB
- warm invocation range: 123.5–136.7 MiB

最初のinvocationだけcompilerを含むため、XCTest process RSSの通常範囲やoperation間比較には使わない。
同様に`ru_maxrss`はprocess peakであり、read/write固有allocationの差分ではない。

## Guardrail decision

20/20 invocationでfalse positiveが0になることを確認した。

| Metric | Baseline decision | 理由 |
|---|---:|---|
| read throughput | `> 400 MiB/s` | 代表値medianの約71%、観測min 508.534より約21%低いcatastrophic境界 |
| write throughput | `> 5 MiB/s` | 代表値medianの約69%、観測min 6.155より約19%低く、現行値を維持可能 |
| sample duration | `>= 200 ms` | read min 267.460 / write min 1088.418で20/20 pass |
| XCTest max RSS | `< 512 MiB` | warm rangeと初回XCTest peakの双方から十分離れた絶対上限 |
| user/system CPU | Observe | 上側outlierがあり、現時点ではfailure条件にしない |

guardrailは改善目標ではない。改善のA/B判定にはmedianとMADを使い、同一runner/workloadで差を確認する。

## Reproduction

1. Performance workflowを`baseline_runs=20`でdispatchする。
2. `resource-performance-<sha>` artifactを取得する。
3. JSONLを集計する。

```sh
bin/ci/summarize-resource-baseline resource-performance.jsonl
```

## Write stage profile and A/B result

同一macOS Release build、8 MiB / 128 chunks / 5 runsのmedianで段階測定した。

| Stage | Before | After key reuse | Change |
|---|---:|---:|---:|
| codec only | 0.115 ms | 0.118 ms | noise range |
| AES-CMAC signing only | 640.369 ms | 404.875 ms | **-36.8%** |
| session + transport (outbound discard) | 658.768 ms | 417.499 ms | **-36.6%** |
| full synthetic write | 659.644 ms | 418.236 ms | **-36.6%** |
| full effective throughput | 12.128 MiB/s | 19.128 MiB/s | **+57.8%** |

Beforeではsigning onlyがfull wall timeの約97%を占め、outbound全量保持の差は1 ms未満だった。
`AESCMAC.authenticationCode`が各16-byte blockでAES-128 round keyを再展開していたため、CMAC呼び出しごとに
1回展開して全blockで再利用した。wire bytes、signature algorithm、鍵寿命は変更していない。RFC 4493 vector testで
互換性を検証し、同一stage profileのbefore/afterで20%調査triggerを超える差を確認した。

再現command:

```sh
swift test -c release --filter SMBeeResourcePerformanceTests/testSyntheticWriteStageProfile
```

profileは`PERF_WRITE_PROFILE`としてlog、Summary、JSONL artifactへ保存する。

## CI build cost

従来はdeterministic contractsとresource metricsが別runnerでそれぞれSwift packageをbuildしていた。
両方を同じRelease invocationへ統合し、resource testのための重複job/buildを1つ削除した。baseline収集時は初回だけ
contractsも実行し、2回目以降はresource testのみ同じ`.build`を再利用する。

統合前run `29155413131`のbuild合計は276.87秒（debug contracts 82.43秒 + Release resource 194.44秒）、
統合後run `29156285604`は193.51秒で、CPU build timeは30.1%減だった。50%目標には届かなかったため、`.build`を
OS、arch、Swift version、`Package.resolved`、commit SHAでkeyしたActions cacheを追加した。SHAを含むexact hitは
同一commitの再測定に使い、prefix restore後もSwiftPM自身がsource変更を検査して必要なtargetを再buildする。
cache hit時の結果は検証runをここへ追記する。

初回cache検証run `29157834623`ではDocker root所有のSwift index/ModuleCacheをActionsのtarが読めず保存に失敗した。
container終了前に`.build`へread/traverseだけを付与し（write権限は追加しない）、cache保存可能に補正した。

exact cache hit run `29158173179`はcache 156 MiBを復元したが、checkout後のsource timestampにより自packageを再compileし、
buildは109.00秒（cold 193.51秒比43.7%減）だった。そこでcommit SHAまで一致したexact hitに限り
`swift test --skip-build`を使う。別commitからのprefix restoreは`cache-hit=false`なので必ず通常buildし、古いbinaryを
実行しない。

最終exact-hit run `29158482813`では156 MiB cacheがcommit SHA完全一致で復元され、logにも
`PERF_BUILD_CACHE exact_hit=true`と`swift test -c release --skip-build`を記録した。`swift test` wall timeは
19.60秒、resource jobは統合直後run `29156285604`の4分10秒から1分8秒へ72.8%短縮した。cold build
193.51秒に対する再buildは0秒となり、50%削減目標を満たした。同runのwrite throughputは12.558 MiB/sで、
cacheによって測定対象が省略されていないことも確認した。
