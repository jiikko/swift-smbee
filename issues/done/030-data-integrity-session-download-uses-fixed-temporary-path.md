# 030 data integrity: persistent session downloadのtemporary pathが固定文字列になる

- 種別: data integrity / concurrency / filesystem safety
- 重要度: high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`SMBClientSession.download`)

## 問題

temporary filenameでUUIDを補間する意図のコードが通常文字列になっている。

```swift
.appendingPathComponent(".smbee-(UUID().uuidString).part")
```

このため同じdirectoryへの全downloadが`.smbee-(UUID().uuidString).part`という同一pathを使う。
`FileManager.createFile`の戻り値も確認されず、既存temporary fileをそのまま開く。

## 影響

- 同じdirectoryへ並行downloadすると、複数handleが同じfileへ書き込み、内容が混在・切断される。
- 一方のdownloadのdefer cleanupが、他方が利用中のtemporary fileを削除する。
- crash後のstale fileや事前作成されたpathと衝突する。
- predictable pathがsymlinkとして用意された場合、filesystem実装次第で意図しないtargetへ書く危険がある。

## 対応方針

1. `".smbee-\(UUID().uuidString).part"`のように実際に一意な名前を生成する。
2. exclusive createを使い、既存pathやsymlinkとの衝突を拒否する。
3. temporary URLとhandleの所有権を1 downloadに閉じ、cleanupを一度だけ行う。
4. static downloadとpersistent session downloadで共通temporary-file helperを使う。

## リグレッションテスト

- 同じdirectoryへの2つの並行downloadが異なるtemporary pathを使用し、両方の内容が一致する。
- stale temporary fileとsymlinkが存在しても上書き・追跡しない。
- 一方の失敗cleanupが他方のdownloadへ影響しない。
- 成功・error・cancellation後にtemporary fileが残らない。

