# 038 robustness: directory copyの自己配下判定がSMBのUnicode同一視と一致しない

- 種別: recursion safety / Unicode / server compatibility
- 重要度: medium
- 状態: open
- 関連: `Sources/SMBee/SMBPath.swift` (`validateDirectoryCopyTarget`)

## 問題

directory copyがdestinationをsource自身または配下と判定する際、Swiftの`lowercased()`だけを使う。
コードコメントどおりUnicode normalizationは適用されていない。

```swift
let foldedSource = source.lowercased()
let foldedDestination = destination.lowercased()
```

SMB server/filesystem側のcase mappingやUnicode normalizationがclientと異なる場合、clientでは別path、
serverでは同一pathまたはsource配下として解決される組合せがある。macOS系serverの正規化、Windowsの
upcase table、locale非依存case mappingはSwiftの単純lowercaseと完全には一致しない。

これはserver/filesystemの名前比較規則に依存する互換性リスクであり、全serverで再現する確定bugではない。
そのため実server fixtureで再現条件を固定してから修正方式を選ぶ。

## 影響

- sourceを自身の配下へrecursive copyし、copyしたdestinationを再列挙して増殖する可能性がある。
- case-only/normalization-only pathでserverごとに上書き、collision、再帰判定の挙動が変わる。
- depth上限で停止しても、その前に多数のdirectory/fileを作成し得る。

## 対応方針

1. SMB path比較専用のcomponent-wise canonicalization方針を定める。
2. 少なくともUnicode canonical normalizationとlocale非依存case foldingを組み合わせる。
3. server側file IDが取得できる場合、source/destination ancestor identityで実体の自己包含を検証する。
4. ambiguousなcase-only/normalization-only copyは安全側に拒否するoptionを設ける。

## リグレッションテスト

- NFC/NFDが異なる同一見た目のsource/destinationを自己copyとして拒否する。
- Unicode case foldingが単純ASCIIと異なる名前をfixture化する。
- Samba、macOS SMB server、Windows互換環境で同じ安全判定になる。
- 通常の兄弟directory間copyは拒否されない。
