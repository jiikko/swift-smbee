# 025 data integrity: resume downloadがlocal fileのサイズと内容を検証せず追記する

- 種別: data integrity / API semantics
- 重要度: medium
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (static `download(... resume:)`)

## 問題

resume downloadは既存local fileのサイズをremote read offsetとして、そのまま末尾へ追記する。

```swift
let existingSize = try localFileSize(at: destination, fileManager: fileManager)
try handle.seekToEnd()
try await withReadStream(... range: SMBReadRange(offset: existingSize, length: UInt64.max))
```

remote fileの現在サイズを先に確認していないため、local fileの方が大きい場合でも明示的に拒否しない。
また、同じサイズまでのprefixが同じremote object由来か検証しないため、remote fileが差し替わった後や
別fileを誤って保存先に指定した場合に、新旧内容を連結した破損ファイルを正常終了として返し得る。

## 影響

- local > remoteでは余分な末尾を保持したまま成功する可能性がある。
- remote更新後のresumeで、旧prefix + 新suffixという検出しにくい破損が起きる。
- 完了後のsize/hash検証が必須でないため、callerは成功をデータ一致と解釈できない。

## 対応方針

1. resume前にremote statを取得し、`existingSize > remoteSize`を拒否する。
2. `existingSize == remoteSize`はsize一致だけで完了扱いにするか、verification policyを選べるようにする。
3. 少なくとも境界付近のoverlap rangeを再読してlocal prefix末尾と比較し、remote差し替えを検出する。
4. 強い保証が必要な場合はhash/identity metadataをresume tokenとして保持・照合する。
5. 完了後に最終local sizeが開始時のremote sizeと一致することを確認する。転送中のremote変更もerrorにする。

## リグレッションテスト

- local sizeがremoteより大きい場合を拒否する。
- 同サイズだが内容が違う場合のpolicyを固定する。
- prefix不一致、転送中のremote truncate/extendを検出する。
- 正常なpartial fileはoffsetから再開し、最終内容がremoteと一致する。
