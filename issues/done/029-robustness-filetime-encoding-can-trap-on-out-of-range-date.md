# 029 robustness: FILETIME encodingが範囲外Dateでruntime trapする

- 種別: boundary value / crash safety
- 重要度: medium
- 状態: open
- 関連: `Sources/SMBee/SMB2ReadCodecs.swift` (`dateToFiletime`), metadata update API

## 問題

`dateToFiletime`はFoundation `Date`から計算した`Double`を検証せず`UInt64`へ変換する。

```swift
UInt64((date.timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
```

1601-01-01より前の日付、非常に遠い未来、非有限値ではUInt64の表現範囲外になり、throwではなく
runtime trapでprocessが終了し得る。public metadata update APIからcaller指定Dateで到達できる。

既存のtrapping integer cast対策(issue 011)は可変長fieldを対象としており、この日時変換は残っている。

## 影響

- 不正または極端なmetadata入力だけでlibrary利用process全体がcrashする。
- CLI/APIが入力errorとして回復・表示できない。

## 対応方針

1. tick値がfinite、0以上、`UInt64.max`以下であることを変換前に検証する。
2. 範囲外は`SMBCodecError.invalidValue`としてthrowする。
3. SMBの「変更なし」等のsentinel FILETIME値と通常Dateを型/API上で区別する。

## リグレッションテスト

- 1601-01-01ちょうどと通常日時を正しくencodeする。
- 1601年以前、遠未来、非有限Dateをprocess crashせずthrowで拒否する。
- nil/sentinelの既存metadata更新semanticsを維持する。
- encode/decode round-tripで許容範囲内の境界値を確認する。

