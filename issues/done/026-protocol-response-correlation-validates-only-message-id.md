# 026 protocol: response correlationがmessage ID以外を検証しない

- 種別: protocol state machine / robustness
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`SMBPendingResponse`, `demuxedWireTransaction`, `dispatchReceivedPacket`)

## 問題

pending responseはlabel、long-poll flag、continuationだけを保持し、受信packetはmessage IDだけで
requestへ対応付けられる。request command、session ID、tree IDは照合されない。

```swift
guard var pending = pendingResponses[header.messageId] else { ... }
pending.continuation.resume(returning: packet)
```

各response decoderの多くはbodyのStructureSizeを確認するが、期待commandを一貫して検証しない。
そのためserverが同じmessage IDに別command、別tree、別sessionのpacketを返すと、body layoutが
偶然適合した場合に誤ったoperationの成功として扱う可能性がある。

署名検証はpacketがserver由来であることを保証するが、request/responseの状態遷移までは保証しない。

## 影響

- stale/misrouted responseを別operationへ配送し、返却データやstatusを取り違える。
- server実装不具合やsession再接続境界の異常を早期検出できず、後続状態が壊れる。
- decoderごとのcommand検証有無により、同じ異常への挙動が一貫しない。

## 対応方針

1. pending entryへexpected command、session ID、必要ならtree IDを保存する。
2. dispatch時にmessage IDと合わせてheader fieldsを照合し、不一致はsession-fatal protocol errorにする。
3. async STATUS_PENDINGではasync header semanticsを考慮し、最終responseまで同じexpected commandを維持する。
4. NEGOTIATE/SESSION_SETUPなどsession確立前の例外を状態として明示する。

## リグレッションテスト

- 同じmessage IDでcommandだけ異なるresponseを拒否する。
- session ID/tree IDが異なるresponseを拒否し、全pending waiterをterminal resumeする。
- 正常response、STATUS_PENDINGからの最終response、暗号化responseは従来どおり配送される。
- 複数in-flight requestのresponse順序が入れ替わっても正しくcorrelateされる。

