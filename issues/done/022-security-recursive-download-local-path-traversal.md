# 022 security: 再帰downloadがserver由来のentry名でローカル保存先を脱出できる

- 種別: security / input validation
- 重要度: high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`downloadDirectoryRecursive`), `Sources/smbcli/BatchCommands.swift` (`MGet`)

## 問題

再帰downloadはQUERY_DIRECTORY応答の`entry.name`を検証せず、ローカルURLへ直接追加する。

```swift
let localChild = localDirectory.appendingPathComponent(entry.name)
let actionChild = reportedDirectory.appendingPathComponent(entry.name)
```

remote path側の`joinSMBPath`も単純な文字列結合で、`SMBPath.normalize`が持つ`.`、`..`、
separatorの検証を通らない。通常のSMB serverは不正な名前を返さない想定でも、接続先serverや
中間装置から届くdirectory entryは信頼境界の外にある。

## 影響

悪意あるserverが`..`、絶対path相当、またはpath separatorを含むentry名を返した場合、
download先/staging directoryの外へファイルやdirectoryを作成・上書きする可能性がある。
`atomic` downloadでもstaging rootからの脱出を防げない。

同じentry名から作られる`RemoteBatchFile.relativePath`を
`URL.appendingPathComponent`へ渡すrecursive `mget`経路も同じ検証を必要とする。

## 対応方針

1. directory entry名専用validatorを追加し、空文字、`.`、`..`、`/`、`\\`、NULを拒否する。
2. `appendingPathComponent`後のstandardized URLが期待するroot配下にあることも確認する。
3. remote child生成にはthrowingな`SMBPath.join`を利用する。
4. 不正entryは黙ってskipせずprotocol/input validation errorとして扱う。`continueOnError`時はfailureへ記録する。

## リグレッションテスト

- `..`、`../outside`、`a/b`、`a\\b`、絶対path形式を含むfixtureを拒否する。
- atomic/non-atomic、recursive `mget`、dry-run、`continueOnError`の全経路で保存root外に作用しない。
- 通常のUnicode名は従来どおりdownloadできる。
