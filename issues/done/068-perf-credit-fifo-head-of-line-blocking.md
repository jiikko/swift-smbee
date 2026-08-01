# 068 perf: prefix read 並行時の credit FIFO head-of-line blocking を実測する

状態: **done (2026-08-01)。実 waiter ベース診断で再計測し、credit HoL 未観測・遅延はサーバ応答待ちと確定。issue 012 の FIFO 判断を追認して close**
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

### この計測では判定できなかった

競合の重なりは全サンプルで成立していた（`write_overlap=full` 20/20）が、当時の
`[wire] credit_wait` は `SMB2CreditWindow` の実 waiter 入りを観測していなかった。
`SMBSession.reserveCredit` が別 actor 呼び出しの前に balance を事前観測し、不足していた場合だけ
出すログだったため、事前観測時には足りていても実際の `reserve` 時には不足して waiter に入る競合を
取りこぼす。したがって baseline / competing ともに `credit_wait 0 件` だったことは、
「credit 待ちが起きなかった」ことの証拠にならず、HoL blocking の有無も判定できない。
この診断は本 reopen 時の変更で、waiter enqueue 時の `credit_wait` と解放時の
`credit_granted` を `SMB2CreditWindow` 内から出すよう修正する。

さらに、この計測条件は issue が想定した発火条件を作れていなかった。WRITE の charge は
`localWriteChunkLimit` 1 MiB を 64 KiB 単位で数えるため最大 16 であり、credit window は 256 を
目標に補充される。一方、competing 側は prefix read 1 本だけだった。この組み合わせでは
「charge の大きい waiter が FIFO の先頭にいて、その後ろに多数の小 READ が並ぶ」条件を
意図的にも決定論的にも作れていない。

次の計測では、修正後の `credit_wait` / `credit_granted` で実待機を観測し、credit 残高を記録するか
固定する。その上で charge の大きい request を意図的に先頭へ置き、その後ろへ charge 1 の request を
複数投入する決定論的な条件を作り、後続 request の待ち時間を測る。

ただし副産物として別の事実が判明した: **大きな WRITE と重なると prefix read の p50 が 5〜6 倍に伸びる**。
これはこの環境における **2 run の点推定**として残す。各 p50 は 20 件の nearest-rank であり、
表の比は対応するサンプルごとのペア比ではなく、baseline と competing の独立な p50 同士の比である。
credit ではないので、原因の候補は (a) issue 072 で導入した送信直列化（大 WRITE の frame 送信中は
小 READ の送信が待つ）、(b) socket / サーバ側の帯域競合、(c) その両方。**未切り分け**。
`[wire] pending → sent → recv` の時刻差から「送信待ち」と「サーバ応答待ち」を分ければ切り分けられるが、
現在の wire イベントは request 側のタイムスタンプを持たないため今回は計測できなかった
（計測テストが `CREDIT_FIFO_HOL_READ_TIMING ... available=false reason=wire_events_have_no_request_timestamps`
と出力する）。obaket 側で「転送中にサムネイルが遅い」が実害になったときに、この切り分けから始めること。

## 関連

- `issues/done/012-credit-window-followups.md` — FIFO 意図的採用の一次情報
- issue 067 / 069 / obaket `macOS/issues/437`

## 再計測結果（2026-08-01、container Samba smb302-encrypted-required、localhost、M1 診断後）

計測: 同テストを 2 run（baseline / competing 各 20 sample、AB/BA 交互、write_overlap=full 20/20）。
M1（commit 432c261）で credit_wait / credit_granted は実 waiter ベース + request 相関
（message_id / command）になり、READ の pending → sent → recv を ts_ns で分解できるようになった。

| 区間 | baseline p50 / p95 | competing p50 / p95 |
|---|---|---|
| pending→sent（credit 待ち + sign/encrypt + 送信直列化 + socket write） | 0.068–0.077 / 0.075–0.089 ms | **0.069–0.079 / 0.087–0.088 ms（不変）** |
| sent→recv（サーバ処理 + 応答） | 0.774–0.803 / 0.985–1.151 ms | **2.708–2.904 / 3.305–4.913 ms** |
| credit_wait 発生数（実 waiter ベース） | **0 / 40 sample** | **0 / 40 sample** |

## 結論（close）

1. **credit FIFO HoL blocking は対象 workload（96MiB WRITE + 64KiB prefix read）で未観測**。
   実 waiter ベース診断で credit_wait は baseline / competing とも 0 件。構造的に不可能とは
   言わない（packet 構築と reserve の間の競合窓は理論上残る）が、FIFO 意味論自体は
   `testCreditWindowPreservesFIFOHeadOfLineBlocking`（M1）で決定論固定した。issue 012 の
   FIFO 採用判断を追認する。
2. **5〜6 倍遅延の正体は送信側ではない**: pending→sent が完全に不変なので、issue 072 の
   送信直列化も credit も原因ではない。増分は全て sent→recv（サーバ処理 / 帯域競合）と、
   prefix 全体（CREATE + READ + CLOSE）への同様の競合。localhost Samba でも WRITE 負荷中は
   サーバ応答が ~3.5 倍遅くなる、という結果。
3. **実害 gate 未達**: competing の追加遅延は p50 で +10ms 前後（gate: +16.7ms 以上で QoS 検討）。
   QoS 対応・session 分離は現時点で行わない。consumer（obaket）で実害が出たら、この診断
   （CREDIT_FIFO_HOL_READ_TIMING）をそのまま実環境で回して再評価する。
