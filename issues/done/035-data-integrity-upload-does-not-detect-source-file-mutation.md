# 035 data integrity: upload中のlocal source変更を検出しない

- 種別: data integrity / filesystem race
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`SMBClientSession.upload(fileURL:)`)

## 問題

file uploadは開始前にlocal sizeを取得するが、openしたhandleをEOFまで読み、完了時に読取byte数や
file identity/metadataを再確認しない。

```swift
let totalBytes = ...attributesOfItem...
let handle = try FileHandle(forReadingFrom: fileURL)
try await session.write(...) { ... handle.read(upToCount:) ... }
try await session.flush(...)
```

転送中にsourceがtruncateされると開始時sizeより短いremote fileを成功扱いできる。appendされると
開始時sizeを超えた内容までuploadし、progressの`bytesTransferred > totalBytes`も起こり得る。
同じpathが別inodeへ置換された場合はopen済みhandleと後続verificationが異なるobjectを見る可能性もある。

## 影響

- callerが成功を受け取っても、開始時点・終了時点のどちらとも一致しないremote contentになる。
- CLIの後段size/hash verificationがpathを再openするため、uploadしたinodeと別objectを比較し得る。
- backupやmedia uploadなど、書込み中fileを誤って対象にした場合にsilent corruptionになる。

## 対応方針

1. 開始時にopenしたhandleからidentity、size、mtimeを取得する。
2. expected remaining bytesだけを読み、早いEOFと追加dataを明示errorにする。
3. flush前後に同じhandleのsize/identity/mtimeを再確認し、変更時はupload失敗として扱う。
4. snapshot semanticsを保証できないplatformでは、sourceを固定temporary fileへclone/copyするoptionを検討する。

## リグレッションテスト

- upload途中でsourceをtruncateすると成功せず、short source errorになる。
- upload途中のappendを開始時sizeで止めるか、mutation errorとして拒否する。
- pathを別fileへrename/replaceしてもopen済みsourceとのidentity混同が起きない。
- 変更されないfileはprogress最終値とremote sizeが開始時sizeに一致する。
