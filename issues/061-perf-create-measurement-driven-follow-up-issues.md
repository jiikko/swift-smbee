# 061 perf: 次の性能改善候補を測定駆動の個別issueとして起票する

状態: **open**
起票: 2026-07-12
関連: `issues/done/060-perf-profile-and-reduce-aes-cmac-write-cost.md` / `docs/performance-resource-baseline.md` / `.github/workflows/performance.yml` / `bin/e2e/smoke-all`

## 背景

issue 060ではAES-CMAC signingの支配コストをprofileし、synthetic writeを大幅に改善した。ただし、
in-memory synthetic benchmarkで得られたCPU改善が、実際のSamba接続におけるend-to-end throughput、latency、
CPU、RSSへどの程度反映されるかは未測定である。また、次の性能改善へ進む際に、実装案だけを先に起票すると、
測定開始条件、比較可能なbefore値、採用基準、終了条件が曖昧になりやすい。

このissueは性能改善そのものを実装するtaskではない。issue 060と最新のPerformance/E2E結果を出発点として、
次に検証すべき改善候補を整理し、各候補を独立した`issues/NNN-*.md`へ起票するためのメタissueである。

## 目的

1. synthetic benchmark、Samba E2E、実利用経路の間に残る測定gapを列挙する。
2. profileまたは実測で検証可能な改善候補だけを選ぶ。
3. 各候補を、測定開始手順から完了判定まで単独で実行できる個別issueにする。
4. 効果がなかった場合も、棄却結果を残して終了できるtask設計にする。

## 最重要要件: 各個別issueに必ず書くこと

「速くする」「測定する」だけのissueを作ってはならない。起票するすべての個別issueに、最低限次を明記する。

### 1. 測定をどう開始するか

- 測定対象のcommit SHAと、比較対象となるbefore commit SHA
- OS/arch、Swift version/image digest、CPU、Samba version、container/runtime、SMB dialect
- signing/encryption policy、network条件、cache状態、payload内容とsize
- warmup回数、sample回数、invocation回数、実行順序
- 実行commandと、必要なfixture/serverの起動・初期化方法
- throughput、elapsed、user/system CPU、RSS等のraw値を保存するartifact形式
- byte数、hash、command/chunk数等、処理省略や破損を防ぐcorrectness assertion

### 2. before/afterをどう比較するか

- 同一条件を保証するmetadataと、比較不能として扱う条件
- median、p10/p90、MAD、min/max等の集計方法
- runner driftやnetwork noiseを抑えるためのA/B順序または同一runner内比較方法
- 改善方向と、noiseを超えたと判断する定量threshold
- CPU改善、network律速、server律速を区別する分解測定

### 3. 何をもって完了とするか

- 採用条件と棄却条件の両方
- 最低sample数と、保存すべきraw artifact / run URL / runner metadata
- correctness、data integrity、署名、暗号化、cancellation、cleanupの必須検証
- full unit suite、関連sanitizer、Samba E2Eの必要範囲
- 結果を書き戻すdocumentと表形式
- 効果なし、noise以下、環境依存だった場合にもissueを閉じられる明示的な終了条件

測定開始方法と完了条件は、担当者が追加の設計判断をせず実行できる粒度で書くことを必須とする。

## 必ず起票する個別issue

### 実ネットワーク/Samba上での転送性能測定

少なくとも1件は、in-memory synthetic結果が実ネットワークのSamba transferへ反映されるかを測るissueにする。
この個別issueには、最低限次を含める。

#### 測定開始protocol

1. 対象commitを固定し、`bin/e2e`のSamba profileを使ってSMB 3.0.2 encrypted-requiredと
   SMB 3.1.1 signing-requiredを別々に起動する。
2. client/serverを同一host container networkで測るbaselineと、帯域・RTTを固定したnetwork条件を分ける。
   traffic shapingが利用できない環境は比較対象から除外し、その理由を記録する。
3. 1 MiB、64 MiB、1 GiB等の複数sizeについてupload/downloadを実行し、小file固定費とsteady-stateを分離する。
4. warmup後に各条件最低5 samples、同一commit最低10 invocationsを収集する。
5. client wall time、throughput、user/system CPU、client RSS、Samba/container CPU・RSS、送受信byte数を保存する。
6. `perf`/Time Profiler等が利用可能ならclient CPUをsigning、encryption、copy、socket waitへ分解する。
7. upload後とdownload後にSHA-256とsizeを照合し、dialect、signing/encryption結果、chunk/command数も記録する。
8. JSONL artifactとGHA Summaryまたは再現可能なlocal reportへraw値・metadata・集計値を残す。

#### 完了条件として必ず定義する内容

- AES-CMAC改善前後を同一Samba/network/workload条件で比較できること。
- 各条件のmedian、p10/p90、MADとraw samplesが保存されていること。
- synthetic改善が実転送のthroughput/CPUへ反映された割合を説明できること。
- network、server、client cryptoのどこが律速かを少なくとも1つの分解測定で判定できること。
- data hash、size、署名・暗号化policyを維持し、E2Eがgreenであること。
- 次の最適化候補が全体の10%以上を占める場合だけ実装issueを作ること。
- 10%以上の候補がない場合は「現条件ではnetwork/server律速」と結果を記録し、実装変更なしで完了できること。

## その他の候補を起票する基準

追加の個別issueは、既存artifact、profile、または新しいprobeで全体コストの10%以上を説明できる仮説に限る。
候補例はpacket normalization copy、write packet assembly、encryption、socket I/O、server response待ち、
large-file concurrency/credit windowだが、根拠を取得する前に実装taskとして確定しない。

各候補issueには次の表を用意する。

| Candidate | Metric | Before median / MAD | After median / MAD | Change | Decision |
|---|---|---:|---:|---:|---|

## 非目的

- このメタissue内で性能実装を行うこと
- 単一runやDebug値だけで改善taskを決めること
- synthetic throughputだけを実利用性能とみなすこと
- guardrailを緩めて改善扱いにすること
- data integrityやsecurityを犠牲にしたbenchmark専用pathを作ること

## 完了条件

- [ ] issue 060の測定結果と最新Performance/Samba E2E artifactから未測定gapを一覧化する。
- [ ] 「実ネットワーク/Samba上での転送性能測定」を独立した個別issueとして起票する。
- [ ] そのissueにserver起動からraw artifact保存までの測定開始protocolを明記する。
- [ ] そのissueに採用・棄却を含む定量的な完了条件を明記する。
- [ ] その他の候補は10%以上の寄与を検証可能な根拠があるものだけ個別issue化する。
- [ ] 起票した全issueにbefore/after比較方法、noise判定、correctness/security検証を記載する。
- [ ] 効果なしでも結果を記録して閉じられる終了条件を全issueに設ける。
- [ ] 親子issueの関連リンクと推奨実行順をこのissueへ追記する。
