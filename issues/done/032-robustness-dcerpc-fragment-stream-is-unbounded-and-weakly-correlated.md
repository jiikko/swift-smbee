# 032 robustness: DCE/RPC fragment streamにsize上限とcall correlationがない

- 種別: resource exhaustion / protocol validation
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`pipeTransceive`), `Sources/SMBee/DCERPC.swift`

## 問題

named pipe RPC responseはlast-fragment flagが現れるまでREADを続け、`output`へ無制限にappendする。

```swift
while !(try DCERPC.responseHasLastFragment(output)) {
    let chunk = try await readChunk(...)
    output.append(contentsOf: chunk)
}
```

各socket readがtimeout内に返る限り、serverはfragmentを送り続けてmemoryを増やせる。
DCE/RPC decoderもfragment間のcall ID一致、FIRST/LAST flag順序、data representation、
context ID、auth lengthを十分に検証していない。

## 影響

- server-controlledな無制限memory/network消費によるprocess termination。
- 別callのfragmentや順序異常fragmentを1つのstubとして連結し、RPC結果を誤decodeする。
- malformed streamがnamed pipe handleとsessionを長時間占有する。

## 対応方針

1. operationごとの最大RPC response bytesと最大fragment数を設ける。
2. 最初のPDUからexpected call ID/contextを取得し、全fragmentで一致を要求する。
3. FIRST/LAST flagの状態遷移、frag length、alloc hint、auth lengthを厳密に検証する。
4. 上限・相関違反はprotocol errorとしてpipe/session cleanupを行う。

## リグレッションテスト

- LAST flagを返さず小fragmentを送り続けるfixtureが上限で停止する。
- fragment途中でcall ID/context IDが変わるresponseを拒否する。
- LASTのみ、FIRST重複、zero-progress fragmentなど不正flag遷移を拒否する。
- 正常な単一fragment・複数fragmentのSRVSVC/LSARPC responseを維持する。

