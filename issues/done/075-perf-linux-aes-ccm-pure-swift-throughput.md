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

## 関連の追記 (2026-09-25)

実 Samba 転送 (CI の `samba-network-performance`、SMB 3.0.2 暗号化 = CCM) の律速の分解は [097](097-perf-samba-real-transfer-measurement.md) で行う。
097 で CCM が全体の 10% 以上と出たら、その数字をこの issue に書き足す (061 の決定)。


## 097 の実測（2026-09-30、GitHub-hosted ubuntu-latest、Linux release、Samba 4.19.5、smb302-encrypted-required）

097 の study（詳細は `docs/performance-resource-baseline.md` の「Issue 097: real Samba transfer」節）で、CCM の実転送を
invocation 10 回の median で測った。

| Run | 条件 | 64 MiB read | 64 MiB write | client CPU ÷ wall（read / write） |
|---|---|---:|---:|---:|
| A [36682108096](https://github.com/jiikko/swift-smbee/actions/runs/36682108096) | HEAD（Xeon 6973P） | 11.926 MiB/s | 21.174 MiB/s | 0.47 / 0.81 |
| D [36682119995](https://github.com/jiikko/swift-smbee/actions/runs/36682119995) | HEAD（EPYC 7763） | 8.759 MiB/s | 13.590 MiB/s | 0.61 / 0.93 |
| D | HEAD + TCP_NODELAY（EPYC 7763、同じ runner で ABBA） | 14.049 MiB/s | 13.984 MiB/s | 0.96 / 0.96 |

- 今の HEAD では、CCM の read は往復ごとの待ち（issue 099。frame header を別 send で送るための Nagle / 遅延 ACK）と CCM の CPU が
  混ざっている。write は CPU 律速（0.81〜0.93）
- **099 の待ちを消すと（TCP_NODELAY の arm）、read も CPU 律速になり（0.96）、約 14 MiB/s で頭打ちになる**。client CPU は
  1 MiB あたり約 68.5 ms（64 MiB で 4,384 ms）で、micro-bench の release 34.5 MiB/s（1 MiB あたり約 29 ms）より重い
  （copy・framing・署名検証を含む実転送の値。内訳は未分解）
- **上の「着手 trigger」（CCM read が 25 MiB/s 未満かつ CPU 律速）は、099 を直した後の CI runner の条件では満たしている**。
  runner は仮想化された 4 vCPU で、実 NAS 環境の値ではない点は残る
- runner の CPU model で絶対値が揺れる（A の Xeon と D の EPYC で write 21.2 と 13.6）。比較は同じ job の中だけにする

## 099 の修正後（2026-09-30）

issue 099（接続直後に TCP_NODELAY）で往復ごとの待ちが消えた後の CCM（smb302-encrypted-required）の実転送。fix-ab
（run [36701434912](https://github.com/jiikko/swift-smbee/actions/runs/36701434912)、runner EPYC 9V45、修正前後を同じ runner で ABBA × 10）:

- 1 MiB read 263.0 → 119.3 ms、write 224.4 → 118.6 ms。64 MiB read 7.03 → 8.55 MiB/s（client CPU ÷ wall 0.69 → 0.99）
- **64 MiB write は 9.48 → 8.31 MiB/s（-12.4%）に下がった**。client の user CPU が同じ仕事で約 17% 増えている（system は不変。user 空間のコードは
  前後で同じ）。097 の TCP_NODELAY A/B（EPYC 7763）では同じ行が変わらなかった。仮説（未検証）: 待ちが消えて client と Samba（こちらも CCM）が
  同時に CPU を使い、4 vCPU の runner で物理 core を取り合った。確かめるなら client と server を別の core に pin して A/B を取り直す
- 待ちが消えた後の CCM は read / write とも CPU 律速（CPU ÷ wall 0.96〜0.99）で、1 MiB あたりの client CPU は約 115 ms（この runner）。
  上の「着手 trigger」（CCM read が 25 MiB/s 未満かつ CPU 律速）は、099 の修正後の CI runner の条件で満たしている

## 2026-10-01 対応: 公開 API で CCM を組み立てる Linux の高速経路（codex-drive）

### 採用した設計
- 「公開 API では CCM を組めない」という前提は誤りだった。swift-crypto の CryptoExtras（Linux だけの依存）にある公開 API で組める:
  - CBC-MAC = `AES.CMAC` に zero pad 済みの完全 block 列を渡し、**最後の block にだけ K_1 = dbl(E_K(0)) を XOR** する（CMAC 内部の最後の XOR と打ち消し合う）
  - CTR = 先頭 16 byte は `AES.permute` で E_K(A_1)、17 byte 目以降は `AES.GCM.seal` を nonce `0x03 || nonce(11)` で **1 回** 呼んだ ciphertext（GCM の payload counter は 2 から始まり CCM の A_2 以降と一致。分けて呼ぶと keystream を繰り返す。GCM tag は捨てる）
  - tag マスク E_K(A_0) は `AES.permute`
  - 下限版: `AES.permute` は swift-crypto 2.2.4、`AES.CMAC` は 3.14.0 から在り、`from: "4.0.0"` で使える
- 対象は Linux（CryptoExtras あり・CommonCrypto なし）で nonce 11 byte（SMB 3.0.2）だけ。Apple は CommonCrypto、他の nonce 長と他 platform は pure-Swift のまま
- payload 長の上限（q=4 で < 2^32）を backend 選択の前の共通 `validate` へ移した（高速経路が上限を迂回しないため）
- K_1 の doubling は branchless（既存の `AESCMAC.dbl` は `carry` で分岐するので流用しない）
- CMAC 鍵の専用使用（SP 800-38B）: CMAC API は CCM の CBC-MAC と同じ値を計算する手段として使い、CMAC の tag は外へ出さない。CCM は元々同じ鍵を CTR と CBC-MAC に使う。ユーザー承認済み（2026-10-01）
- side-channel: AES / GHASH は swift-crypto 4.5.0 の BoringSSL の dispatch（hardware / vpaes / bitsliced constant-time の aes_nohw、constant-time の gcm_nohw）に依存。SMBee は table を持たない
- 却下: SealedBox 由来の copy（ピークで入力の約 4 倍）を `Data(bytesNoCopy:)` で消す案。SMB の frame は MaxRead/WriteSize で上限があり、unsafe な寿命管理を足す価値が無い（コードにコメント）

### 検証
- 独立な固定値: pyca/cryptography 46.0.7（OpenSSL）で nonce 11 / tag 16 を 20 組（AAD 32 と空、payload 0〜1 MiB+17、CBC-MAC 入力が 8,192 byte の flush 境界で終わる 2 組）。生成スクリプトはテストのコメントにある。macOS の CommonCrypto 経路も Linux の高速経路・pure-Swift もこの値と一致
- 変異（Linux container、6 本とも red）: B_0 の q flag / CTR を counter 2 から / flush で最後の block まで / K_1 補正を外す / K_1 の reduction を外す / tag 比較を常に true
- レビュー: D3（設計）2 本、実装後の 3 lens（正しさ・素通り・敵対）。採用 1 件（8,192 byte 境界の固定値）、却下 1 件（上の copy）。正しさ・敵対 lens は CCM と一致しない入力を作れなかった
- commit: `perf(crypto): issue 075 — Linux の nonce 11 byte の AES-CCM を swift-crypto の公開 API で組み立てる`

### 実測
- micro-bench（Apple container swift:6.2 linux/arm64 -c 4 -m 8G、release、`SMBEE_BENCH_CCM=1`、1 MiB × 8）: 実装時の codex の計測で、同じ container で before / after を交互に 3 組の median が seal 26.9 → 393.9 MiB/s、open 27.0 → 397.5 MiB/s（約 14.6 倍）
- micro-bench の独立な再計測（Claude、同じ条件で base 97fb630 / head d9cc852 を ABAB × 3、median）: seal 22.4 → 347.4 MiB/s、open 22.4 → 352.3 MiB/s（約 15.5 倍）
- debug（Linux arm64 container、1 回ずつ）: seal 0.98 → 53.4 MiB/s、open 0.86 → 52.8 MiB/s
- macOS（CommonCrypto 経路、R5 の非劣化の確認、release、base / head を ABAB × 3 の median）: seal 1,248 → 1,260 MiB/s、open 1,252 → 1,264 MiB/s（差なし。組ごとの揺れは ±20% 程度）
- 実転送 fix-ab（run [36800446125](https://github.com/jiikko/swift-smbee/actions/runs/36800446125)、Xeon Platinum 8370C 4 vCPU、smb302-encrypted-required、
  baseline 97fb630 と current d9cc852 を各 10 invocation、SHA-256 照合 160 件 pass。全行「difference」）:

  | 項目 | baseline | current | 変化 |
  |---|---:|---:|---:|
  | 1 MiB read wall | 68.4 ms | 10.2 ms | -85.1% |
  | 1 MiB write wall | 69.0 ms | 10.6 ms | -84.7% |
  | 64 MiB read | 15.1 MiB/s | 136.3 MiB/s | +801% |
  | 64 MiB write | 15.2 MiB/s | 140.0 MiB/s | +822% |
  | 64 MiB read の client CPU | 4,090 ms | 332 ms | -91.9% |

  64 MiB read の client CPU ÷ wall は 0.97 → 0.71。**上の「着手 trigger」（CCM read が 25 MiB/s 未満かつ CPU 律速）は外れた**
- 4 GiB 全読（`testReadStreamCountsFileLargerThan4GiB`、release、Linux arm64 の swift:6.2 container から smb302-encrypted-required の
  Samba container へ、手元 Apple container）: 38.4 秒で pass。fixture は `test/e2e/container-init.sh` の `truncate -s 4296998912` で作られ、
  テストは stat の size が UInt32.max を超えることと、読んだ累積 byte 数が stat の size に一致することを assert する（約 107 MiB/s）。
  x86 は未実測（fix-ab の 64 MiB read 136 MiB/s からの見積もりで 30 秒台 + build）
- 完了条件 3 の判断: 30 分の目安には十分収まる。**判断は「今は CI に全読を戻さない」**。理由は性能ではなく CI 費用（毎回 ~4.3 GB の転送と
  job が増える）。境界を跨ぐ読みは PR/push の 2 MiB range E2E が守っている。戻すときは issue の旧条件どおり x86 で one-shot 実測してから
- 完了条件 1 の扱い: release と debug の両方で CCM 単体の前後を計測した（debug は下に追記）。「律速を profiling で確定」は、旧経路の律速は
  2026-08-01 の節（AES block 暗号）で確定済みで、新しい経路の内訳は**測っていない**。設計レビュー（D3）で「合格基準（2 倍以上・trigger 外れ）を
  満たしたら内訳は要らない、満たさなかったときだけ測る」と決めたため。完了条件 1 のこの部分はこの決定で置き換えた
- 上の「残作業 2」（production 性能）の決着: trigger（CCM read が 25 MiB/s 未満かつ CPU 律速）は CI runner の fix-ab で外れた（136 MiB/s、CPU ÷ wall 0.71）。
  実 NAS / 実 Linux 利用の値は未実測。再開の trigger は旧と同じ数値（実 Linux 利用で CCM read が 25 MiB/s 未満かつ CPU 律速）
- smoke（`make smoke`）は macOS client（CommonCrypto 経路）で green。Linux の高速経路の実 Samba 照合は CI の E2E（Linux、smb302-encrypted-required）で green
- 古くなった記述を更新: `Tests/SMBeeTests/SMBeeE2ETests.swift` の 4 GiB 全読と 2 MiB range のコメント、`docs/coverage.md`、`todo2.md`
- 関連の未解決: `Tests/SMBeeTests/SMBeeSharedSessionRangedReadE2ETests.swift` の gate は「1 MiB の暗号化 response に 18〜26 秒かかる」を理由にしており、
  その gate を外す条件は issue 080 が持つ。この issue の結果（1 MiB read 10 ms）で前提が変わったことを 080 に書いた
