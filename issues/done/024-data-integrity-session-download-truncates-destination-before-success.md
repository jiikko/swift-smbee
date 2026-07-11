# 024 data integrity: persistent session downloadが成功前に既存ファイルを切り詰める

- 種別: data integrity / API consistency
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`SMBClientSession.download`)

## 問題

`SMBClientSession.download(path:localFile:overwrite:)`は保存先へ直接`createFile`し、そのhandleへ
streamを書き込む。既存ファイルはremote readが成功する前に切り詰められる。

```swift
FileManager.default.createFile(atPath: localFile.path, contents: nil)
let handle = try FileHandle(forWritingTo: localFile)
try await withReadStream(path: path) { chunk in ... }
```

途中で通信切断、キャンセル、disk full、署名検証errorが起きると、元のファイルは失われ、
途中までの内容が最終pathに残る。一方、staticな`SMBClient.download`は同じdirectory内のtemporary
fileへ書き、成功後にreplace/moveするため、API間で整合性保証が異なる。

## 影響

- overwrite対象の正常な既存ファイルを失う。
- callerが最終pathの存在だけで成功と誤認し、部分ファイルを利用する可能性がある。
- persistent sessionを性能目的で選ぶと、static APIよりデータ保護が弱くなる。

## 対応方針

1. persistent session版もdestinationと同じfilesystem上のtemporary fileへdownloadする。
2. close/flushまで成功した後だけatomic replaceまたはmoveする。
3. error/cancellation時はtemporary fileを削除し、既存destinationを保持する。
4. direct streamingが必要な利用者向けには`withReadStream`を使わせ、file download APIは安全側に統一する。

## リグレッションテスト

- 既存destinationがある状態で途中error/cancellationを注入し、元内容が保持される。
- 新規destinationへの失敗で最終pathとtemporary fileが残らない。
- overwrite falseの競合と、replace失敗時のcleanupを確認する。
