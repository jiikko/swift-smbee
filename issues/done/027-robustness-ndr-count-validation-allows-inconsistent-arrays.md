# 027 robustness: NDR array count検証が不整合値を受理する

- 種別: input validation / robustness
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/LSARPC.swift`, `Sources/SMBee/DCERPC.swift` (`NDRReader`)

## 問題

LSARPC domain配列のcount検証は次の条件になっている。

```swift
guard count == Int(entries) || count >= 0 else { ... }
```

`count`は`UInt32`から`Int`へ変換されるため常に0以上であり、条件は常にtrueになる。
`entries`とconformant countが不一致でも受理され、server指定のcount回だけheaderを読み進める。

また`NDRReader.readRPCUnicodeStringBuffer`は`maxCount`を読み捨て、`actualCount <= maxCount`を
検証しない。headerの`MaximumLength`も無視され、Lengthとの整合性が確認されない。

## 影響

- malformedまたは悪意あるRPC応答で過剰なloop/配列拡張を試み、CPU・memory消費や長時間parseにつながる。
- deferred fieldの境界がずれ、後続domain/name/statusを誤ってdecodeする。
- 同種のNDR string decoder間でvalidation強度が異なる。

direct-TCP frame上限によりwire入力は約16MiBに制限されるが、count由来の計算量・allocationを
入力実サイズへ明示的にboundする必要がある。

## 対応方針

1. 常時真の条件を厳密なcount一致へ修正する。
2. array countをremaining bytesから導ける最大要素数以下に制限してからloop/allocationする。
3. conformant/varying stringで`offset + actualCount <= maxCount`を検証する。
4. RPC_UNICODE_STRINGのLength、MaximumLength、actualCountをbyte/UTF-16 unit単位で整合確認する。
5. NDR count/offset検証を共通helperへ集約する。

## リグレッションテスト

- `entries != conformantCount`のdomain/name配列を拒否する。
- `actualCount > maxCount`、Length > MaximumLength、奇数byte Lengthを拒否する。
- `UInt32.max`のcountを持つ短いstubが即時errorになり、大量loop/allocationを行わない。
- 正常なmapped、some-not-mapped、none-mapped responseを維持する。

