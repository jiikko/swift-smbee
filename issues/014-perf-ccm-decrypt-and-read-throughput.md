# 014 perf: 暗号化セッションの read が遅い (pure-Swift AES-CCM 復号 + 64KiB 直列 read)

- 種別: perf
- 起票: 2026-07-09
- 発見経緯: obaket の SMB 動画 preview が再生開始まで 10 秒超かかる。実効スループット
  約 80 KB/s (AVPlayer `observedBitrate:641244`) を観測し、原因を smbee 側で切り分けた。

## 症状 (事実のみ)

暗号化セッション (AES-128-CCM) での `withReadStream` が、debug ビルド (-Onone) の
consumer アプリで **約 80 KB/s** しか出ない。87.9 MB の動画ファイルの先頭 ~830 KB
(moov 解析分) の読み込みに約 10.5 秒かかった。

## 根本原因の分析 (A は単体ベンチで強く示唆。着手時に in-place 計測で確定させる)

### A. 最有力: pure-Swift AES-CCM 復号 (`AESCCM.open`)

`AESCCM` / `AESCMAC.AES128` はテーブル実装の pure-Swift AES。64 KiB チャンク 1 個の
`open` を単体ベンチした結果 (2026-07-09, Apple Silicon):

| ビルド | 1 チャンク | スループット |
|---|---|---|
| `-Onone` | **829 ms** | **0.08 MB/s** |
| `-O` | 15.6 ms | 4.2 MB/s |

観測値 80 KB/s = 0.08 MB/s と `-Onone` の実測が一致する。consumer (obaket) の
dev ビルドは SPM 依存も -Onone でビルドされるため、この経路がそのまま実効速度の
天井になりうる。release でも 4.2 MB/s が上限で、LAN の SMB としては 2 桁遅い。

注意: この一致は単体ベンチとの突合であり、`AVPlayer.observedBitrate` は SMB read の
直接計測ではない (コンテナ解析・要求間隔・consumer 処理も含む)。着手時はまず
`AESCCM.open` の累積時間 / `readChunk` の内訳を実セッションでログ計測し、
主犯であることを in-place で確定させてから修正に入る (codex P2 指摘)。

補足: GCM をネゴシエートできた場合は `SMBCrypto.aesGCMOpen` (CryptoKit, HW
アクセラレーション) を使うため問題ない。**CCM に倒れたときだけ** pure-Swift 経路になる
(SMB 3.0/3.0.2 暗号化必須サーバ、または GCM 非対応サーバ)。

さらに `AESCCM.open` は tag 検証のため内部で `seal` を呼び直しており、CTR keystream
生成を **2 回** 走らせる二重仕事になっている (`Sources/SMBee/AESCCM.swift` の
`open` → `seal`)。

### B. 第 2 の天井: 64 KiB 直列 read + credit window が 1 から育たない

A を直しても次はここが天井になる (スループット ≒ 64 KiB / RTT):

1. **チャンク上限 64 KiB 固定**: `negotiatedReadChunkSize()` /
   `creditAwareReadChunkSize()` / `creditAwareWriteChunkSize()` が
   `localLimit: 64 * 1024` をハードコード。negotiate で得た `maxReadSize`
   (通常 1〜8 MiB) を活かしていない。
2. **credit window が育たない可能性 (要実測)**: `SMB2Read.encodeRequest` /
   `SMB2Write.encodeRequest` が `credits: creditCharge` しか要求しない。サーバは
   要求数を超えて grant することも仕様上は可能 (MS-SMB2) なため「残高が 1 のまま」
   と断定はできないが、要求ベースの grant をするサーバでは窓が育たず
   `creditWindowChunkSize` が 1 credit 相当 (64 KiB) にクランプされ続ける。
   修正前に実ログで credit 残高の推移を観測して確定させる。
3. **streamRead が完全直列**: 1 チャンク要求 → 応答待ち → `onChunk` 完了待ち → 次、
   のループ (`SMBClient.streamRead`)。multi-flight demux は実装済み (issues/done/002)
   だが read pipeline では使っていない。

## 修正方針 (効果順)

1. **AES-CCM を CommonCrypto ベースに置換**。CTR 部は `CCCryptorCreateWithMode(...,
   kCCModeCTR, ...)` を使う (`CCCrypt` one-shot は CTR を直接指定できない — codex P1)。
   CBC-MAC 部も HW AES (ECB/CBC) で構成。速度向上幅は仮説であり、着手時に
   単体ベンチで before/after を実測する (CCM の CBC-MAC は直列依存のため
   「CommonCrypto = 数百 MB/s」を保証しない — codex P3)。Linux は
   `#if canImport(CommonCrypto)` で現行 pure-Swift にフォールバック。
   併せて `open` の二重 CTR を解消 (tag 検証は CBC-MAC の再計算だけで足り、
   keystream の再生成は不要)。既存 unit (RFC 3610 test vector 等) を green のまま維持。
2. **read チャンク上限と credit 要求の是正**: `localLimit` を数 MiB へ引き上げる。
   credits 要求は固定値の上乗せ (例: `max(charge, 64)`) ではなく、目標 in-flight 量・
   サーバ grant 実績・待機中要求を踏まえた credit request policy として設計する
   (codex P2)。`transformOverhead` を `maxReadSize` から差し引く現行クランプの
   意味的妥当性 (maxReadSize は READ データ長上限であり transform 込みフレーム長
   ではない) も MS-SMB2 で確認する (codex P3)。
3. **(切り分け) なぜ GCM にならないか確認**: サーバが SMB 3.1.1 + GCM 対応なら
   negotiate 側の問題の可能性。dialect / cipher の negotiate 結果を観測してから判断する。
4. (optional, 2 の後) streamRead の multi-flight pipeline 化。demux 基盤は既存。

## 計測ポイント (修正時の必須手順 — 推測で進めない)

修正の各段階で **ログ/実測を出してから** 次に進む:

- 修正前後で `AESCCM.open` 64 KiB の単体ベンチ (ms/chunk, MB/s) を記録する
- 実サーバ (container Samba, `bin/e2e/container-samba.sh` の encrypted profile) で
  `withReadStream` の実効スループットを before/after で記録する
- negotiate 結果 (dialect / cipher / maxReadSize / grant credits) をログで観測し、
  「CCM に倒れている」「credit 残高が 1 のまま」を修正前に実ログで確認する

## 受け入れ条件

- [ ] 暗号化 CCM セッションの read 実効スループットが release で 50 MB/s 以上
      (container Samba ローカルループバック基準。未実測の目標値であり、
      HW AES 化後の実測で達成不能と判明したら根拠つきで改訂する)
- [ ] debug (-Onone) でも動画 preview が実用になる (>5 MB/s 目安)
- [ ] RFC 3610 / 既存 crypto unit test green + E2E smoke (encrypted profile) green
- [ ] Linux ビルド green (CommonCrypto フォールバック)

## 関連

- `Sources/SMBee/AESCCM.swift` / `Sources/SMBee/AESCMAC.swift` (pure-Swift AES)
- `Sources/SMBee/SMBCrypto.swift` (GCM = CryptoKit の既存実例)
- `Sources/SMBee/SMBClient.swift`: `negotiatedReadChunkSize` / `creditAwareReadChunkSize` /
  `streamRead` / `readChunk`
- `Sources/SMBee/SMB2ReadCodecs.swift`: `SMB2Read.encodeRequest` (credits 要求)
- `issues/done/002-design-smbsession-concurrent-multiflight.md` (multi-flight 基盤)
- `issues/done/012-credit-window-followups.md` (credit window の既知残件)
