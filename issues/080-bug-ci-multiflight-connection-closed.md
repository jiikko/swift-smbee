# 080 bug疑い: CI の wire multi-flight ranged READ が future MessageId queue 直後に接続断する

- 種別: bug / wire protocol / CI-only timing
- 重要度: medium（調査中。再現したテストのみ local 専用 gate へ隔離）
- 起票: 2026-08-13
- 状態: open / 要調査
- 関連: `Tests/SMBeeTests/SMBeeSharedSessionRangedReadE2ETests.swift`
  (`testSharedSessionRangedReadsHaveMultipleWireResponsesInFlight`) /
  `Sources/SMBee/SMBClient.swift`（future message ID queue / `markRequestSent`） /
  obaket issue 462

## 症状

wire multi-flight E2E test
`testSharedSessionRangedReadsHaveMultipleWireResponsesInFlight` が GitHub Actions の E2E workflow
（`smb302-encrypted-required` / Linux）で 3 回連続失敗した。同じ `smb.conf` profile のローカル
Apple container では一度も再現せず、0.23 秒で green。

失敗 3 回の様態:

1. 4 MiB range × 3 本: `connectionLost(operation: READ)`、39.6 秒。9 秒の応答途絶後に切断。
2. 4 MiB range × 3 本（rerun）: `SharedSessionE2ETimeout`、47.3 秒。
3. **1 MiB range × 3 本: `connectionClosed`、12.4 秒。** 転送量を 1/4 にしても再現したため、
   単にテストが重すぎるという仮説を棄却する決定的な失敗。

対象 run は 31588752225（4 MiB）、31608937200（rerun）、commit `f725bd6` の run（1 MiB）。

## 失敗ログで観測した共通パターン

3 回中 2 回は、失敗直前が次の順序になっていた。

```text
SMB response queued for future message id N
CANCEL request failed: connectionClosed
```

- 1 回目は `N=394`、3 回目は `N=76`。
- すなわち、まだ送信済みとして登録されていない MessageId の応答を future-id queue に入れた直後に
  接続が閉じている。
- 失敗時の credit は健全（balance 317 / 614）であり、credit 枯渇ではない。
- CI ログには `credit charge=16` の READ が連続する wire 証拠があり、READ 2 本以上が実際に同時
  in-flight だった。

同じ CI・同じ commit では、512 KiB × 3 本の並行テスト 3 本
（`ReturnExactBytes` / `SurviveOneCancellation` / `RemainReusableAfterRepetition`）は安定して green。

## このテストだけが持つ条件

- consumer callback を止めず、full-speed で 3 本を並行して最後まで消費する。
- 3 本の range が重なる（offset stride 64 KiB）。
- wire multi-flight の証拠を取るため、別の sampling task が 5 ms 間隔で `SMBSession` actor を
  polling する。

したがって、これは**テストが暴いた潜在問題であり、テスト自体の欠陥と判断したものではない**。
consumer である obaket issue 462 の先読みは 2 本並行かつ consumer のペースで消費するため、
full-speed 3 本並行の本テストとは条件が異なる。今回の CI 隔離だけから consumer 経路への同じ症状の
発生・非発生を結論しない。

## 仮説（以下はすべて推測）

- `queued for future message id` → 接続断という並びは、送信 `Task` の spawn と
  `markRequestSent` の順序 race が絡む経路を示唆する。ただし接続を Samba server が切ったのか、
  client transport が切ったのかは未確定。
- SMB2 spec 上、無効な MessageId / range を受けた server は接続を終了する（SHOULD）。full-speed
  並行時に SMBee が不正な packet を送出している可能性はまだ排除できていない。
- overlapping range 自体、5 ms polling による actor scheduling、または両者と full-speed 送信の
  組み合わせが race の発生確率を変えている可能性がある。

## 調査手段の候補

1. CI で `SMBEE_TRACE_WIRE=1` を有効化し、失敗直前までの raw packet と MessageId / command / range
   の対応を採取する。
2. Samba 側の log level を上げ、server が connection を終了した理由（invalid parameter、decrypt、
   framing 等）を確認する。
3. future-id queue 経路に、pending 登録状態、send task の lifecycle、`markRequestSent` 前後、close の
   first cause を関連付ける diagnostics を追加する。

## 当面の扱い

このテスト 1 本だけを `SMBEE_E2E=1` に加えて `SMBEE_E2E_WIRE_MULTIFLIGHT=1` が必要な local 専用
テストとする。残り 5 本の shared-session ranged-read E2E は従来どおり CI で実行し、調査用の再現条件と
テスト本体は削除・弱体化しない。


## インパクト評価 (2026-08-13)

真因が未特定のため幅がある。優先度は **low-medium** (緊急でない) と判断し、当面は本 issue に
書き留めるのみで調査は着手しない (ユーザー判断)。

### 楽観側 (Samba / 環境要因なら): ほぼゼロ
- 再現は CI (Linux runner の暗号化必須 Samba) のみ。ローカル Apple container (同一 config) では
  未再現、consumer (obaket) の実機確認 (2026-08-13、SMB 上の 427 MB mp4 の先読み再生 + seek) でも
  問題なし
- CI テストの発火条件は攻撃的 (3 本 full-speed + 重なり range + 5 ms polling)。consumer の実経路は
  どれもそれより穏やか: 動画先読みは 2 本 + AVFoundation ペース消費 / サムネイルは幅 1 gate で直列 /
  transfer は concurrency hint=1 で直列

### 悲観側 (client の送信 race なら): medium
- 「future message id への応答 → 直後に切断」は送信 Task spawn と登録順序の race を示唆する。
  不正 packet を wire に出す race なら、遅いネットワーク・遅い NAS で実機でも発火しうる
- **実 NAS の多くも中身は Linux の Samba** なので「CI 限定」と言い切れる根拠はまだ無い

### 発火した場合の実害の上限は低い
- read only なのでデータ破壊は構造的に起きない
- `SMBRetryableStreamRead` の connection-lost 単発透過リトライで隠れる可能性が高い
- 最悪でも「読み込みエラー → 開き直せば直る」。ただし放置期間が長いと「SMB でたまに切れる」系の
  再現困難なバグ報告の潜在原因になる

### 着手する場合の最小の一歩
調査手段 1 (CI で `SMBEE_TRACE_WIRE=1` + gate を立てて 1 run)。不正 packet が出ていれば
client race 確定、出ていなければ環境側に倒せる。1 run で証拠が取れる見込みでコストは小さい。
