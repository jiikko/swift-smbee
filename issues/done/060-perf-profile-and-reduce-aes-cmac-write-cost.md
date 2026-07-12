# 060 perf: AES-CMAC write costを測定し、根拠がある場合だけ最適化する

状態: **done**
起票: 2026-07-12
関連: `issues/done/052-perf-calibrate-resource-metrics-and-plan-optimization.md` / `docs/performance-resource-baseline.md` / `Sources/SMBee/AESCMAC.swift` / `Sources/SMBee/SMBSessionCrypto.swift` / `Tests/SMBeeTests/SMBeePerformanceRegressionTests.swift`
観測run: https://github.com/jiikko/swift-smbee/actions/runs/29172586105

## 背景

resource performanceの段階別測定により、synthetic writeではWRITE packet encodeやtransportのoutbound保持よりも
AES-CMAC signingが支配的であることが分かっている。鍵展開をCMAC呼び出し内で再利用する変更により、Linux上の
write throughputは約7.3 MiB/sから12 MiB/s台へ改善したが、最新runでも次を観測している。

- write throughput: 12.499 MiB/s
- write user CPU: 646.960 ms / 8 MiB（80.870 ms/MiB）
- write CPU utilization: 約101% of one core
- signing onlyはfull synthetic writeの大部分を占める
- deterministic performance contracts: 8/8 pass

この結果から追加改善の可能性はあるが、純Swift AES内部のallocation、block copy、round-key保持のどれが支配的かは
まだ定量化していない。先に実装を変えると、効果がない複雑化、暗号互換性の破壊、session key materialの長寿命化を
招く可能性がある。

## 目的

1. AES-CMAC signing内部のCPU時間、allocation、copyを再現可能な方法で分解する。
2. full writeへ10%以上寄与する箇所だけを最適化候補にする。
3. 同一条件のA/B測定でnoiseを超える改善を確認した変更だけを採用する。
4. wire互換性、署名検証、鍵materialのcleanup semanticsを維持する。

## 非目的

- benchmark専用の署名省略や弱いalgorithmへの変更
- guardrailを緩めて改善したように見せること
- 単一runやDebug buildの値だけで採用判断すること
- profile根拠なしにCryptoKit、CommonCrypto、OpenSSL等の依存を追加すること

## Phase 1: 測定protocolを固定する

既存の8 MiB / 128 chunks / Release構成を維持し、次をbefore値として保存する。

1. `codec_only`
2. `signing_only`
3. `session_no_outbound_retention`
4. `full_synthetic`
5. write throughput、user/system CPU、CPU ms/MiB
6. XCTest process peak RSS、whole process-tree RSS

測定条件:

- warmup後に最低5 samples、代表値はmedian
- raw samplesをJSONL artifactへ保存
- 同一commitで最低10 invocationsを収集し、median、p10/p90、MADを算出
- CPU model、Swift image digest、OS/arch、cache hitを一致させる
- command count、chunk count、payload bytes、signature vectorを同時に検証する
- A/Bは可能なら同一runner内で`before, after, before, after`の順に交互測定し、時間ドリフトを抑える

## Phase 2: profileで支配コストを確認する

macOSではInstruments Time Profiler / Allocations、Linuxで許可される場合は`perf stat` / `perf record`を使い、
少なくとも次を記録する。

- `AES128.expandKey`、`AES128.encryptBlock`、`AESCMAC.authenticationCode`のCPU比率
- 16-byte blockごとのArray生成回数とallocated bytes
- `Array(message[range])`、round-key slice、state copyの回数
- 8 MiB signing 1回あたりのpeak/current RSS差
- payloadを4 / 8 / 16 MiBにしたときのCPU時間とallocationのscaling

候補箇所がfull synthetic writeの10%未満、またはprofile上で識別できない場合はコードを変更せず、測定結果だけを
記録してissueを閉じる。

## Phase 3: 候補を一つずつA/B評価する

### 候補A: AES block処理の一時allocationを除去する

hypothesis:
16-byteごとの`Array` slice、round-key slice、state copyがsigning CPUとallocationを増やしている。

評価する変更:

- 固定長bufferまたはin-place state処理
- expanded round keyからのslice allocation除去
- message blockをArrayへ複製せず読み取る方法

採用条件:

- signing-only medianが10%以上改善
- full synthetic write throughputが10%以上改善、またはuser ms/MiBが10%以上低下
- 差が`max(10%, 3 * MAD相当)`を超える
- RSSが悪化せず、payload増加に対して超線形に増えない

### 候補B: expanded AES keyをsession signing contextで再利用する

hypothesis:
現在はCMAC呼び出しごとに残る鍵展開コストを、session単位のcontextで一度だけにできる。

事前条件:

- profileで鍵展開がfull writeの10%以上を占める
- expanded keyを保持することによる改善がmicrobenchmarkでnoiseを超える

safety constraints:

- session close / authentication failure / reconnectでcontextを破棄する
- plaintext credentialや不要になったsigning keyの寿命を延長しない
- Sendable、actor isolation、concurrent signingで共有可変stateを作らない
- AES-CMAC以外のGMAC/encryption pathを変えない

事前条件を満たさなければ実装しない。

### 候補C: platform crypto backendを比較する

候補A/B後もAES-CMACがfull writeの50%以上を占める場合だけ調査する。

- macOS/Linux双方で同じ署名bytesを生成できること
- dependency、binary size、platform availability、FIPS要件の有無を比較する
- pure Swift fallbackを残す必要性を判断する
- backend切替コストを含むfull write A/Bを行う

調査結果が20%以上の改善を示さない場合、依存追加は行わない。

## Correctness / security verification

各候補で次を必須とする。

- RFC 4493 AES-CMAC vectors
- SMB signing request/response vectors
- deterministic performance contracts 8/8以上を維持
- full unit suite
- Samba E2E smoke（SMB 3.0.2 encrypted-required、SMB 3.1.1 signing-required）
- cancellation、reconnect、session close後に署名contextが残留・再利用されないこと
- wire packet、signature field、message ID、credit accountingがbeforeと同一であること

## 結果の記録形式

各A/Bを次の表で`docs/performance-resource-baseline.md`へ追記する。

| Candidate | Metric | Before median / MAD | After median / MAD | Change | Decision |
|---|---|---:|---:|---:|---|

併せてcommit SHA、run URL、Swift image digest、CPU model、再現command、profile top symbolsを残す。

## 完了条件

- [x] 同一条件10 invocations以上のbefore baselineを保存する。
- [x] signing内部のCPU比率、allocation、copy回数をprofileする。
- [x] full writeの10%以上を占める候補だけをA/B評価する。
- [x] 候補Aのallocation除去を評価し、採用または棄却理由を記録する。
- [x] 候補Bは鍵展開比率が事前条件を満たす場合だけ評価する。
- [x] 候補CはA/B後もsigningが支配的な場合だけ評価する。
- [x] before/afterのmedian、MAD、変化率、runner metadataを記録する。
- [x] 採用変更でfull writeまたはCPU効率がnoiseを超えて改善する。
- [x] RSS scalingが悪化していないことを確認する。
- [x] cryptographic vectors、full unit suite、Samba E2Eを通す。
- [x] data integrity、署名強度、cancellation、cleanup semanticsを弱めていないことを確認する。

## 実施結果

実装・測定・採否の詳細は`docs/performance-resource-baseline.md`の
「Issue 060: AES-CMAC profile and optimization」に記録した。

- before 10-run: https://github.com/jiikko/swift-smbee/actions/runs/29174853295
- after 10-run: https://github.com/jiikko/swift-smbee/actions/runs/29184222552
- profileでoriginal signingがfull syntheticの約97%を占め、copy/allocation symbolを含むsampleが31.3%だった。
- 候補Aを採用し、pure-Swift signing medianをmacOSで70.9%短縮した。
- 候補Bはkey expansionがAES block call countの0.024%未満で10%事前条件を満たさず、実装せず棄却した。
- 候補Cを採用し、AppleはCommonCrypto、LinuxはCryptoExtras/BoringSSL、その他はoptimized pure Swiftとした。
- Linux同一runner 10-runでsigning-onlyは653.962→9.095 ms、full syntheticは669.927→23.797 ms。
- 4 / 8 / 16 MiB scalingはcurrent RSS delta 0、fixture RSS増分はpayloadに対して線形だった。
- RFC 4493・boundary・concurrency・312 unit tests・deterministic 8/8・Samba 3.0.2/3.1.1 smokeを通した。
- backend contextはone-shotで、session key cacheや共有mutable stateを追加していない。
