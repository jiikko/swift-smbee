# 068 perf: prefix read 並行時の credit FIFO head-of-line blocking を実測する

状態: **open（計測 issue。FIFO 自体は issue 012 で意図的採用済み — 設計変更の提案ではない）**
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

## 関連

- `issues/done/012-credit-window-followups.md` — FIFO 意図的採用の一次情報
- issue 067 / 069 / obaket `macOS/issues/437`
