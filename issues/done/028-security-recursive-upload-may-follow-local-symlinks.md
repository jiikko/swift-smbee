# 028 security: 再帰uploadがlocal symlink経由でroot外を送信し得る

- 種別: security / filesystem traversal / API semantics
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`uploadDirectoryRecursive`), `Sources/smbcli/BatchCommands.swift` (`localRecursiveBatchGlobEntries`)

## 問題

再帰uploadはdirectory列挙後に`isDirectoryKey`だけを取得し、symbolic linkかどうかを確認しない。
batch `mput -r`もenumeratorと`isRegularFileKey`だけを使う。

filesystem APIのsymlink追跡挙動に依存するため、root内のlinkがroot外のdirectory/fileを指す場合、
利用者が指定したupload root外の内容をSMB serverへ送信する可能性がある。directory symlinkを
辿る場合はcycleもrecursion depth上限まで繰り返し得る。

現API/documentationには「symlinkをskipする」「link targetをuploadする」のpolicyがない。

## 影響

- 意図しないcredential、設定ファイル、private dataをremote shareへ送信する。
- symlink cycleにより不要なnetwork operationと重複uploadが発生する。
- libraryのdirectory uploadとCLI `mput -r`で挙動が異なる可能性がある。

## 対応方針

1. recursive uploadのdefaultをsymlink非追跡にし、`isSymbolicLinkKey`で明示的にskipまたはerrorにする。
2. 追跡をoption提供する場合、解決後URLがstandardized/resolved root配下であることを確認する。
3. directory identityでvisited setを持ちcycleを検出する。
4. library APIとbatch CLIで同じpolicyをdocumentする。

## リグレッションテスト

- root外fileとdirectoryを指すsymlinkがdefaultでuploadされない。
- root内symlink cycleが有限時間で検出され、同じfileを重複uploadしない。
- 通常file/directoryとroot内の実体pathは従来どおりuploadされる。
- macOS/Linuxのfixtureでlibrary uploadと`mput -r`のpolicyが一致する。

