# 068 perf: prefix read 並行時の credit FIFO head-of-line blocking を実測する

状態: **close (2026-07-29)。実測で credit FIFO の HoL blocking は発火せず (credit_wait 0 件)、issue 012 の判断を追認。WRITE 競合時の 5-6 倍遅延という別事実は下記に記録**
起票: 2026-07-27（issue 067 A の敵対的レビューで検出、codex 反証レビューで訂正済み）
関連: `Sources/SMBee/SMB2Header.swift`（`SMB2CreditWindow.resumeReadyWaiters` — 「FIFO on purpose」の
rationale コメントあり） / `issues/done/012-credit-window-followups.md`（FIFO 採用の判断） /
consumer 側: obaket のサムネイル生成（prefix read 4 並列 + 転送の同居）

## 前提（先に事実を固定する）

- credit waiter の厳密 FIFO は **issue 012 で「大 request の飢餓防止のため意図的」と判断済み**で、
  コードにも rationale コメントがある。本 issue はその判断を覆す提案ではない。
- 敵対的レビューが挙げた単純な発火シナリオ（「初期 credit 1 で 1 MiB WRITE が charge 16 の waiter
  として先頭に居座る」）は**そのままでは成立しない**: chunk size は現在の credit 残高で clamp
  されるため、credit 1 なら WRITE も charge 1 相当に縮小される。
- ただし **競合順序によっては大きな waiter が先頭に残る**: 要求 packet を credit が潤沢な時点で
  作成し、reserve までの間に別 operation が credit を消費した場合。issue 067 A で「同一 session
  上の多数の小 READ（prefix read 4 並列）+ 転送」という利用パターンが現実になったため、
  この競合窓を踏む頻度が上がった可能性がある。

## やること（計測のみ。防御コードを先に入れない）

1. container Samba に対し「大きな WRITE（数十 MiB）実行中の prefix read レイテンシ」を
   `SMBPerfLog` で計測する（単独時との差分）。
2. 差が実害レベル（サムネイル表示が体感で待たされる規模）で出た場合のみ、対応を検討する:
   - 大 WRITE 側の charge を credit 窓に合わせて分割する（FIFO は維持）
   - consumer 側で session を分ける（obaket `macOS/issues/437` の候補と同じ）
3. 差が出なければ、計測結果を本 issue に記録して close する（issue 012 の判断を追認）。

## 計測結果（2026-07-29、container Samba smb302-encrypted-required、localhost）

計測: `SMBeeWireStressE2ETests.testCreditFIFOHeadOfLineBlockingMeasurement`
（96 MiB WRITE 実行中の 64 KiB prefix read × 20 回を baseline と交互に測定。2 run）。

| 条件 | p50 | p95 | max | credit_wait 発生数 |
|---|---:|---:|---:|---:|
| baseline（WRITE なし） | 2.32 / 1.64 ms | 2.99 / 2.46 ms | 4.28 / 4.79 ms | **0** |
| competing（WRITE と重複、overlap=full 20/20） | 12.53 / 9.55 ms | 14.86 / 13.88 ms | 15.54 / 14.19 ms | **0** |
| 比（competing / baseline） | **5.4〜5.8 倍** | 5.0〜5.6 倍 | 3.0〜3.6 倍 | — |

**結論: この issue が仮説とした credit FIFO の head-of-line blocking は発火していない。**
競合の重なりが全サンプルで成立している（`write_overlap=full` 20/20）にもかかわらず、
`[wire] credit_wait` イベントは baseline / competing の**両方で 0 件**だった。
つまり prefix read は credit 待ちに入っておらず、issue 012 の「FIFO は意図的」という判断は
実測でも覆らなかった。**この issue は close してよい。**

ただし副産物として別の事実が判明した: **大きな WRITE と重なると prefix read の p50 が 5〜6 倍に伸びる**。
credit ではないので、原因の候補は (a) issue 072 で導入した送信直列化（大 WRITE の frame 送信中は
小 READ の送信が待つ）、(b) socket / サーバ側の帯域競合、(c) その両方。**未切り分け**。
`[wire] pending → sent → recv` の時刻差から「送信待ち」と「サーバ応答待ち」を分ければ切り分けられるが、
現在の wire イベントは request 側のタイムスタンプを持たないため今回は計測できなかった
（計測テストが `CREDIT_FIFO_HOL_READ_TIMING ... available=false reason=wire_events_have_no_request_timestamps`
と出力する）。obaket 側で「転送中にサムネイルが遅い」が実害になったときに、この切り分けから始めること。

## 関連

- `issues/done/012-credit-window-followups.md` — FIFO 意図的採用の一次情報
- issue 067 / 069 / obaket `macOS/issues/437`
