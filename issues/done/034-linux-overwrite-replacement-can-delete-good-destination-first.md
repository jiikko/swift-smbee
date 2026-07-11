# 034 data integrity: Linuxのoverwrite置換が既存destinationを先に削除する

- 種別: data integrity / portability / filesystem failure
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`smbReplaceItem`, download replacement paths)

## 問題

LinuxではFoundationの`replaceItemAt`を避けるため、既存destinationを削除してからtemporary sourceを
moveしている。

```swift
try? fileManager.removeItem(at: destination)
try fileManager.moveItem(at: source, to: destination)
```

remove成功後にmoveが失敗すると、正常だった既存destinationと新規downloadの両方を最終pathから失う。
permission変更、disk/filesystem error、競合process、source消失で到達できる。remove errorも握りつぶすため、
その後のfailure原因が不明瞭になる。

またpersistent session downloadはこのhelperを使わず`replaceItemAt`を直接呼び、コメント上既知の
swift-corelibs-foundation不具合を再び踏む経路になっている。

## 影響

- download自体がtemporary fileへ安全に完了していても、commit段階のfailureで既存データを失う。
- static/persistent APIでLinuxの置換挙動が異なる。
- callerへerrorは返るが、元destinationを復旧できない。

## 対応方針

1. 同一directoryでdestinationをbackup名へrenameし、source move失敗時にrollbackする。
2. Linuxで利用可能なら`renameat2(RENAME_EXCHANGE)`等のatomic primitiveをfeature detectionして使う。
3. remove errorを握りつぶさず、commit/rollback failureを区別して報告する。
4. 全download APIを共通replacement helperへ統一する。

## リグレッションテスト

- destination退避後のsource move failureを注入し、元destinationが復元される。
- remove/rename permission errorで既存内容を保持する。
- Linuxでstatic/persistent file downloadとatomic directory downloadの置換semanticsを揃える。
- 成功後にbackup/temporary artifactが残らない。

