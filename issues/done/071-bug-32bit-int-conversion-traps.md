# 071 bug: 32bit 環境で Int(UInt32.max) 変換が trap する（read 経路に複数箇所）

状態: **解決済み (2026-07-29、commit e20bf26)。read/write/credit 経路の該当変換を Int(clamping:) /
guard 先行に置換。64bit は挙動不変 (既存テスト green が担保)。32bit 実環境が無いため実機検証は不可**
起票: 2026-07-27（issue 067 A の敵対的レビューで検出）
関連: `Sources/SMBee/SMBClient.swift`（`negotiatedChunkSize` 周辺 / `creditAwareReadChunkSize`） /
`Sources/SMBee/SMB2ReadCodecs.swift`（READ response の dataLength 処理）

## 症状（未再現・レビュー由来の構造指摘。64bit では発火しない）

32bit 環境（32bit Linux / 32bit Swift）では `Int` が 32bit のため:

1. `creditAwareReadChunkSize` / `creditAwareWriteChunkSize` の `Int(UInt32.max)` は
   **`min` の引数評価時点で実行される**ため、交渉値の大小に関係なく 32bit では通常経路でも
   trap する（未交渉 session に限らない）。`negotiatedChunkSize` の `Int(negotiatedLimit)` も同様。
   prefix read（issue 067 A）は必ずこの経路を通るため、新 API でも同様。
2. READ response codec（`SMB2ReadCodecs.swift` の dataLength 処理）が `UInt32` を guard より先に
   `Int` 化しており、巨大値・悪意ある応答で境界検証の前に trap しうる。

## 発火可能性の評価（対応の優先度判断）

- 現在の CI は 64bit のみ（macos-26 / ubuntu-latest）。**32bit のビルド・実行環境は無い**。
- consumer（obaket）は macOS / iOS の 64bit のみ。
- よって現時点で実害は無く、優先度は低い。「32bit をサポートする」と決めたときに直すのでは
  なく、防御的変換（`UInt64` で `Int.max` にクランプしてから `Int` 化）として安く直せるなら
  直してよい、という位置づけ。

## 対応候補

- `UInt32` → `Int` の直接変換を、`Int(clamping:)` または `UInt64` 経由のクランプに置換する
  （read 経路の該当箇所を grep で洗い出して一括。挙動は 64bit では不変）。
- 2 の「検証前の Int 化」は 64bit でも設計として筋が悪いので、guard を UInt32/UInt64 のまま
  先に行う形へ並べ替える。

## 関連

- issue 067（prefix read が本経路の利用頻度を上げた）
