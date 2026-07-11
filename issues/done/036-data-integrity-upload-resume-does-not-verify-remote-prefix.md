# 036 data integrity: upload resumeがremote prefixの内容を検証しない

- 種別: data integrity / resume semantics
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`SMBClientSession.upload(fileURL:resume:)`)

## 問題

resume uploadはremote fileのsizeだけを取得し、そのoffsetまでlocal sourceをseekしてsuffixを追記する。

```swift
remoteSize = try await stat(path: path).size
try handle.seek(toOffset: remoteSize)
try await session.write(... offset: remoteSize)
```

remoteの先頭`remoteSize` bytesが同じlocal file由来か確認しない。remoteに同サイズ以下の別内容や、
以前の別versionがある場合、古いremote prefixと現在のlocal suffixを連結して正常終了する。

download resumeにはprefix比較が追加されているが、upload側には同等のguardがない。

## 影響

- final sizeが一致しても内容が壊れ、size verificationでは検出できない。
- hash verificationを明示しないlibrary利用者はsilent corruptionを成功として受け取る。
- `remoteSize == localSize`では書込みなしで成功し、完全に異なる同サイズfileを完了扱いする。

## 対応方針

1. resume前にremote prefixまたは境界overlapをreadし、localの同範囲と比較する。
2. 同サイズ時も少なくとも選択したverification policyを適用する。
3. 強いresume tokenとしてremote file identity、mtime、size、hashの保持を検討する。
4. prefix不一致時は上書きrestartへ黙ってfallbackせず、callerに選択させる。

## リグレッションテスト

- remote prefixが異なるpartial fileを拒否する。
- remote/localが同サイズで内容だけ異なる場合を成功扱いしない。
- 正しいpartial prefixは指定offsetから再開し、最終hashがlocalと一致する。
- resume確認後、書込み開始前にremoteが差し替わる競合も検出する。
