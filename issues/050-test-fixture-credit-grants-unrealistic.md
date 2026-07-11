# 050 test: fixture の credit grant 方針が暗黙 (常に 1) で、会計バグを長期間隠した

- 種別: test infrastructure
- 重要度: medium
- 状態: open
- 関連: `Tests/SMBeeTests/SMBeeTests.swift` の応答ヘルパー群 (`smb2StatusResponse` / `smb2CreateResponse` 等),
  `Tests/SMBeeTests/SMBeePerformanceRegressionTests.swift`, 3da1a41 の charge-0 会計修正

## 問題

テストの応答 fixture はすべて `SMB2Header` の既定値 `credits: 1` で「毎応答 1 credit grant」する。
これは grant 方針としてテストごとに選ばれたものではなく、既定値が暗黙に流れているだけである。

3da1a41 以前は、`SMBSession.reserveCredit` が request header の `CreditCharge` (多くのエンコーダで 0) を
そのまま `SMB2CreditWindow.reserve` に渡しており、`reserve(charge: 0)` は残高を消費しない。
一方で応答は毎回 1 grant するため、charge-0 リクエストのたびに残高が水増しされ、
multi-credit リクエスト (charge≥2 の WRITE 等) が「渋い grant の fixture」でも偶然通っていた。
つまり **暗黙の 1-grant fixture と session 層の会計すり抜けが打ち消し合い、両方が隠れていた**。

会計修正後は「毎応答 1 grant」前提が表に出て、複数テストの deadlock / チャンク分割ずれとして噴出し、
場当たり的に `initialCredits: 64` を個別テストへ埋め込む対応になった。

## 影響

- credit 会計の退行が unit で検出されにくい (grant 方針がテストの意図として表明されていないため、
  何が「正しい残高遷移」なのか fixture から読み取れない)。
- 新しいテストを書く人が「応答ヘルパーの credits はいくつが正しいのか」を判断できない。
- `initialCredits: 64` のマジックナンバーが複数テストに散在する。

## 対応方針

1. 応答ヘルパー群に grant 方針を明示するパラメータを導入する (既定は変えず、意図を書けるようにする):
   - `.fixed(N)`: N を grant (現在の 1 は `.fixed(1)` と等価)
   - `.echoRequestCharge`: 対応するリクエストの charge と同数を grant
     (注: 実サーバの grant はサーバ側の裁量であり、常に charge 相当とは限らない。
     これは「残高が定常な代表パターン」としての選択肢)
2. 散在する `initialCredits: 64` を「negotiate 済みで十分な credit を持つサーバ」を表す
   共通ヘルパー / 名前付き定数に集約する。
3. 会計退行の番犬として、「charge=2 の reserve → grant」の残高遷移を直接 assert する unit test を
   追加する (`SMB2CreditWindow` の reserve/grant 単体で足りる)。
