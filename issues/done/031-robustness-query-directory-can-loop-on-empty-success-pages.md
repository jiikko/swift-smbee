# 031 robustness: QUERY_DIRECTORYが空のsuccess pageで無限loopする

- 種別: resource exhaustion / protocol progress
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`queryDirectory`), `Sources/SMBee/SMB2ReadCodecs.swift`

## 問題

directory列挙は`STATUS_NO_MORE_FILES`だけを終端条件にしている。

```swift
while true {
    let entries = try await queryDirectoryPage(...)
    guard let entries else { return }
    for entry in entries { ... }
}
```

serverが`STATUS_SUCCESS`と空のentry listを返すと、clientは進捗がないまま次の
QUERY_DIRECTORYを送り続ける。同じpageを繰り返すserverに対するprogress検証やpage/entry上限もない。

## 影響

- malformedまたは悪意あるserverが無限request loopを発生させ、CPU・network・creditを消費する。
- `list` APIではserverが異なるentryを返し続けることでcollector memoryも無制限に増える。
- recursive operationは当該directoryで停止し、全体timeoutがない利用では戻らない。

## 対応方針

1. success + empty pageを終端またはprotocol errorとして扱う。
2. page fingerprintやfile indexなど利用可能な情報で、同一pageの反復を検出する。
3. optionalなmax entries/max pagesをpublic APIへ設け、超過を明示errorにする。
4. streaming APIでもprogress invariantを適用する。

## リグレッションテスト

- success + zero entriesが有限回で終了またはerrorになる。
- 同じnon-empty pageの反復を検出する。
- 大規模だが正常な複数page列挙と`STATUS_NO_MORE_FILES`終端を維持する。
- entry/page上限超過時にhandle cleanupが行われる。
