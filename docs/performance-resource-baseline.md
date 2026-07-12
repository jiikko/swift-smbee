# SMBee resource performance baseline

基準run: https://github.com/jiikko/swift-smbee/actions/runs/29155604555

- commit: `4faea896f7a312b6c7173a0adb2f27a7398b14be`
- Swift image: `swift:6.2`
- runner: `Linux/X64` (GitHub-hosted `ubuntu-latest`)
- baseline invocations: 20
- raw samples: 200 (read 100 / write 100)
- read workload: 160 MiB/sample (8 MiB × 20 transfer intervals)
- write workload: 8 MiB/sample

測定用 Swift image は、リポジトリ直下の `.swift-image-digest` に manifest list digest を固定している。
`.swift-version` を変更した時、または意図的に測定 image を更新したい時は、
`bin/ci/update-swift-image-digest` を実行し、表示された old/new digest と差分を確認する。

## Resource log contract (version 1)

`bin/ci/run-resource-performance` のログは `bin/ci/parse-resource-performance` が検証する。
各 `PERF_BASELINE_RUN run=N total=M` の後、resource 測定テスト開始時に
`PERF_FORMAT version=1` を出力する（resource operation ごとに1回）。必須行は
`PERF_RESOURCE_SAMPLE` と `PERF_RESOURCE` で、`read_stream` と `write_stream` の各 operation に
ついて、sample 数が対応する `PERF_RESOURCE ... runs=` と一致し、5つの resource metric が揃う必要がある。
各 operation の全 `assertAndPrint` 完了後に `PERF_RUN_COMPLETE operation=<operation>` を出力する。
baseline run は1から連続し、重複や欠落は失敗扱いとする。

`PERF_ENV`、`PERF_BUILD_CACHE`、`PERF_METRIC`、`PERF_WRITE_PROFILE`、
`PERF_CMAC_SCALING_SAMPLE` / `PERF_CMAC_SCALING`、`Maximum resident set size (kbytes):` は任意行だが、
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
  `full_synthetic` がない場合はこの派生行を出力しない。分母が 0、またはpipeline外の比較用
  `pure_swift_signing_only`では比率をJSON `null`とする。

CPU efficiency と write stage の比率は Observe-only であり、guardrail の判定、workflow の exit status、
既存の throughput/RSS 判定を変更しない。

CMAC scalingは4 / 8 / 16 MiBの各payloadについて、1 sampleが512 MiBの署名処理になるようiterationを
調整する。sample raw値とinvocation内medianをartifactへ保存し、current RSSは署名区間の直前・直後、
max RSSはprocess lifetime high-waterとして区別する。いずれもObserve-onlyである。resource workloadの
`size_mib`は全iterationの合計であり、Summaryは`MiB/iteration × iterations/sample × samples`に分解して表示する。

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

## History comparison

master の `push` では、同一 workflow の直近の成功した `push` run（現在の run 自身を除く）にある、30日保持の
`resource-performance-*` artifact を参照する。swift image、runner、operation ごとの
`size_mib`/`runs`/`iterations` が一致した場合だけ、各 metric の代表値 median の増減率を比較する。
初回、fork PR、artifact 期限切れ、取得失敗、parse failure、metadata/workload 不一致では
`No comparable baseline` と表示する。この比較は Advisory であり、guardrail 判定と job の exit status には使わない。

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

## Issue 060: AES-CMAC profile and optimization

### Measurement identity

- before commit: `24f81d079b8831625315ee739fb6750ac9e393f2`
- before 10-run: https://github.com/jiikko/swift-smbee/actions/runs/29174853295
- after commit: `e91809a370f073f07155ee56526fc4101ba68fdf`
- after 10-run: https://github.com/jiikko/swift-smbee/actions/runs/29184222552
- Swift image（before/after共通）:
  `swift:6.2@sha256:dd349c6dfc3cd3040910a84ab3e5bd5d08efdd547e5fb9f77b765abed16fe5ff`
- runner（before/after共通）: GitHub-hosted `Linux/X64`
- stage workload: Release、8 MiB、128 × 64 KiB chunks、warmup後5 samples/invocation、10 invocations

beforeのresource representative値はwrite throughput 11.937 MiB/s（MAD 0.061）、user CPU
669.979 ms（MAD 2.516）、elapsed 670.204 ms（MAD 3.402）、XCTest max RSS 128,412 KiBだった。
afterはbenchmark自体を高速化後も200 ms以上に保つため8 MiB × 14 iteration（112 MiB/sample）へ変更し、
CPU snapshotをelapsedと同じtransfer-only区間へ補正した。このためresourceの絶対CPU/elapsedはbeforeとの
同一contract A/Bには使わず、同じ8 MiB stage profileを採用判断の正本とする。after resource値はwrite
334.014 MiB/s（MAD 2.282）、user CPU 341.676 ms / 112 MiB（MAD 3.883）、elapsed 335.317 ms
（MAD 2.293）だった。

### Profile evidence

macOS Time Profilerで変更前後の同じ8 MiB signing testを記録した。変更前6,347 samplesのうち
AES stackが6,156（97.0%）、AES stack上のallocation/copy symbolを含むsampleが1,987（31.3%）だった。
top leafには`_xzm_free` 602、`xzm_malloc_zone_size` 516、`_platform_memset` 321、
`mixColumns` 317、`swift_slowAllocTyped` 227、`malloc` 208が現れた。候補A後は1,995 samples中
AES stack 1,777（89.1%）、allocation/copy sample 35（1.8%）となり、top leafは`mixColumns` 323、
`subBytes` 278、bounds check 245、`addRoundKey` 231、`shiftRows` 169へ移った。

変更前のsourceとworkloadから数えられる8 MiBあたりのcopy-prone eventは次のとおり。

| Source | Count | Copied-byte proxy |
|---|---:|---:|
| AES round-key slices | 5,778,432 | 88.17 MiB |
| `shiftRows` Array CoW candidates | 5,253,120 | 80.16 MiB |
| CMAC message-block Arrays | 525,184 | 8.01 MiB |
| AES state CoW candidates | 525,312 | 8.02 MiB |
| SMB signature normalization | 128 | 8.01 MiB |
| **Total** | **12,082,176** | **約192.4 MiB** |

候補Aはround-key slice、message-block slice、`shiftRows` whole-state copyを除去し、AES stateをin-placeで
再利用した。候補Cの最終Apple backendもCBC出力を同じbufferへ書くため、CMAC内でpacket-sized bufferは
message copy 1本だけであり、別のciphertext全量bufferを作らない。最終Allocations traceは
`xcrun xctrace record --template Allocations`で採取し、CIではより再現可能なcurrent RSS before/afterと
process high-waterをJSONLへ保存する。

### Candidate decisions

| Candidate | Metric | Before median / MAD | After median / MAD | Change | Decision |
|---|---|---:|---:|---:|---|
| A: pure-Swift temporary allocation removal | signing-only（macOS） | 407.257 / 4.761 ms | 118.585 / 1.643 ms | -70.9% | adopt |
| A | full synthetic（macOS） | 424.344 / 12.201 ms | 133.676 / 0.868 ms | -68.5% | adopt |
| B: session expanded-key cache | AES block/key expansion call ratio | 525,312 / 128 | — | key expansion <0.024% of calls | reject before implementation |
| C: platform backend（Linux 10-run） | signing-only | 224.298 / 0.047 ms（optimized pure Swift） | 9.095 / 0.032 ms | -95.9% | adopt |
| C + A（Linux 10-run） | full synthetic | 669.927 / 1.409 ms（original） | 23.797 / 1.213 ms | **-96.4%** | adopt |

候補Bは10%事前条件を満たさず、176-byte expanded keyをsession寿命まで延ばすsecurity costもあるため
実装しなかった。候補CはAppleでCommonCrypto、Linuxでswift-crypto 4のstable `CryptoExtras.AES.CMAC`
（BoringSSL）を使う。unsupported platformではoptimized pure-Swift implementationへfallbackする。
AppleにCryptoExtrasをlinkするとcold build 63.99秒、`smbcli` 8,166,376 bytesまで増えたため、dependencyを
Linux条件付きにした。最終Apple cold buildは29.37秒、binaryは5,290,056 bytesで、beforeの37.03秒、
5,292,568 bytesに対してbinary増加はなく（-0.05%）、buildも悪化していない。

### CPU and RSS scaling

after 10-runは各sampleの総処理量を512 MiBに揃えた。payloadが増えてもthroughputとCPU効率はほぼ一定で、
署名区間のcurrent RSS delta medianは全sizeで0だった。payload fixtureを含むcurrent RSSは4→8 MiBで
+4.13 MiB、8→16 MiBで+8.15 MiBと線形に増え、超線形成長はない。

| Payload | Iterations | Elapsed median / MAD | Throughput | User CPU | Current RSS before→after | Process peak |
|---:|---:|---:|---:|---:|---:|---:|
| 4 MiB | 128 | 570.869 / 0.806 ms | 896.878 MiB/s | 570.719 ms | 32.689→32.689 MiB | 120.145 MiB |
| 8 MiB | 64 | 576.349 / 1.562 ms | 888.351 MiB/s | 576.255 ms | 36.822→36.822 MiB | 120.145 MiB |
| 16 MiB | 32 | 581.282 / 0.786 ms | 880.812 MiB/s | 581.224 ms | 44.967→44.967 MiB | 120.145 MiB |

afterのwarm `swift test` process RSS medianは120.9 MiB（120.5–130.2 MiB）で、beforeの127.0 MiB
（123.6–128.8 MiB）から悪化していない。

### Correctness and security

- RFC 4493 vectors、0/1/15/16/17/31/32/33/63/64/65/65,536-byte boundary differential tests
- 64 concurrent one-shot CMAC contextsと独立reference implementationの一致
- full unit suite: 312 tests、18 skipped、0 failures
- deterministic performance contracts: 8/8 pass
- local `make smoke`: SMB 3.0.2 encrypted-required / SMB 3.1.1 signing-requiredともpass
- GitHub Actions: Test `29182627772`、E2E `29182627762`、Performance `29182627747`ともpass

backend contextは呼び出しlocalで、sessionへexpanded keyやmutable CMAC stateを追加していない。
CommonCrypto cryptorはone-shot、CryptoExtras contextはfinalize後に解放され、BoringSSLはCMAC subkey/blockを
cleanseする。既存のsession key寿命、close/reconnect/cancellation、GMAC/encryption、wire packet、message ID、
credit accountingは変更していない。E2Eで次の署名付きrequestを含む実通信も検証済みである。

再現command:

```sh
swift test -c release --filter SMBeeResourcePerformanceTests
bin/ci/test-performance-scripts
make smoke
```
