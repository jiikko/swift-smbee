# 075 perf: Linux の SMB 3.0.2 AES-CCM pure-Swift fallback が約 0.3 MiB/s

状態: **open**
起票: 2026-07-30
関連: `Sources/SMBee/AESCCM.swift`（Linux pure-Swift fallback） /
`Tests/SMBeeTests/SMBeeE2ETests.swift`（4GiB 境界・全読 E2E）

## 問題

Linux の SMB 3.0.2 encrypted read は、AES-CCM が pure-Swift fallback（`AES128.encryptBlock`）に
落ちる構成で、ubuntu-latest runner の **debug ビルド**実測 end-to-end throughput が約 0.30 MiB/s
しか出ない（律速箇所の因果は profiling 未実施。release 構成の実測も未取得で、着手時に両方を
計測してから方式を選定する）。fixture 作成回帰を
commit `febd147` で直した後の `Large-file E2E` run
[30509016532](https://github.com/jiikko/swift-smbee/actions/runs/30509016532) では、
build 完了（141 秒）後の約 27 分 15 秒で 1 MiB READ が offset 509,607,936（約 487 MiB）までしか
進まず、30 分の job timeout で cancelled になった。この実測から単純外挿すると 4 GiB 全読は
約 229 分（約 3.8 時間）。GitHub-hosted job の上限 6 時間には理論上収まるが、週次とはいえ
4 時間級の runner 占有と timeout 余裕の無さは scheduled E2E として非現実的である。

（補足: 当初この issue は約 0.08 MB/s / 853 分と記載していたが、それは
`issues/done/014` の Apple Silicon・64 KiB・`-Onone` 単体ベンチの転用であり、
Linux runner の実測ではなかった。上記は run 30509016532 の実測に基づく訂正値。）

CI 修復を口実に暗号実装を変更すべきではないため、4GiB 境界検証の再構成とは分離してこの issue で追跡する。

## 調査結果

- swift-crypto 4.5.0 には公開された CCM API がない。
- `AES._CTR` / `AES._CBC` は underscored API であり、互換性が保証された安定依存にはできない。
- 公開 API の CMAC は CCM が内部で使う CBC-MAC と同一ではなく、そのまま CCM 実装の代替にはならない。
- 独自 C shim または BoringSSL への直接依存は実現可能でも、ABI・ビルド・platform matrix・脆弱性対応の
  保守コストが大きい。

したがって、高速化方式は性能だけでなく API 安定性と長期保守コストを比較して別途設計する必要がある。

## CI から外れた検証

PR/push E2E は `UInt32.max - 64 KiB` から 2 MiB の streaming range read を行い、境界より後方に
置いた非ゼロ sentinel の内容照合で「後続 READ offset が UInt32 に切り詰められず `UInt32.max` を
超えて進んだこと」を検証する（全域ゼロの sparse fixture では offset wrap を検出できないため）。
一方、次の検証は scheduled workflow の廃止（この issue と同じ変更で削除）により CI から外れた。

- offset 0 からの通し読み
- 累積 byte count が `UInt32.max` を超えること
- 4GiB+ sparse fixture の実 EOF に到達すること

この issue が解決して Linux CCM の throughput が CI timeout に収まる水準になった場合は、
scheduled 全読 E2E を復活させる選択肢がある。env gate 付きの
`testReadStreamCountsFileLargerThan4GiB` は手動検証と将来の復活のため残している。

## 完了条件

- Linux SMB 3.0.2 AES-CCM の read throughput を同一 runner・同一 fixture で再現可能に計測できる
  （debug / release 両構成。律速箇所は profiling で確定させる）。
- 公開・安定 API と保守コストを満たす高速化方式を選定し、暗号 correctness の test vector と
  encrypted Samba E2E を維持したまま実装する。
- 4 GiB 全読が現実的な job 時間（目安: 30 分以内）に収まるかを実測し、scheduled 全読 E2E を復活させるか判断する。

## 2026-08-01 実測と部分対応（key schedule hoisting）

### 実測（Apple container swift:6.2 Linux arm64、AESCCM micro-bench、1 MiB chunk。
Tests/SMBeeTests/AESCCMBenchmarkTests.swift = SMBEE_BENCH_CCM=1 gate で再現可能）

| 構成 | seal / open (改修前) | seal / open (hoisting 後) |
|---|---|---|
| Linux debug | 0.38 / 0.41 MiB/s | 1.11 / 1.10 MiB/s |
| Linux release | 8.51 / 8.79 MiB/s | **34.5 / 34.1 MiB/s (4.1 倍)** |
| macOS release (CommonCrypto) | ~1,100-1,260 MiB/s | 変化なし（経路不変） |

- **CI の ~0.30 MiB/s は debug ビルドが支配要因**（debug 実測 0.38-0.41 と整合。
  run 30509016532 の workflow は `-c release` なしで debug と確定）。
- 律速は AES block 暗号で、さらに **16-byte block ごとに key schedule を再展開していた**
  （1 MiB あたり ~13 万回）。seal/open ごとに 1 回の展開に hoisting し、CBC-MAC を in-place 化
  （T-table 化はしない: data-dependent lookup の拡大は side-channel 特性を変えるため今回対象外）。
- RFC 3610 vector / SMB3 transform round-trip / encrypted Samba smoke で correctness 維持。

### 残作業

1. **scheduled 4GiB 全読 E2E の復活は「x86 one-shot 実測」が前提**: ubuntu-latest で
   `swift test -c release --filter SMBeeE2ETests.testReadStreamCountsFileLargerThan4GiB` を
   workflow_dispatch で 1 回実測し、25 分以下（timeout 余裕 5 分）を確認してから schedule 化する。
   arm64 実測の外挿だけで確定しない。release lane は exact filter 限定
   （`swift test -c release` の全 suite 実行は SMBPerfLog の release 挙動で
   SMBWireDiagnosticsTests が壊れるため不可）。34.5 MiB/s なら 4 GiB ≈ 2 分 + build ~3-6 分。
2. **production 性能は未解決のまま open**: hoisting 後も 1GbE NAS 実効 (~100 MiB/s) の 1/3。
   対象は SMB 3.0/3.0.2 encrypted (CCM) の Linux client に限定（3.1.1 GCM は swift-crypto 経路）。
   着手 trigger（数値）: 実 Linux 利用で CCM read が 25 MiB/s 未満かつ CPU 律速、または
   10 GiB 級転送が 5 分超。次の候補は monomorphic な word 単位 AES 実装の見直しで、
   T-table 採用時は side-channel threat model の明文化を必須とする。
