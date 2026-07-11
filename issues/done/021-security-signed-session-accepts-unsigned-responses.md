# 021 security: 署名済みセッションが未署名の応答を受理する

- 種別: security / protocol validation
- 重要度: high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`verifySigned`, `signedWireTransaction`, `close`)

## 問題

`SMBSession.verifySigned` は signing key が存在していても、応答ヘッダに
`SMB2_FLAGS_SIGNED` がなければ検証せず正常終了する。

```swift
guard let signingKey else { return }
let header = try SMB2Header.decode(packet)
guard (header.flags & SMB2Flags.signed) != 0 else { return }
```

さらに NEGOTIATE 応答の `signingRequired` は `SMBProbeResult` までdecodeされるが、
認証セッションの状態として保持されていない。したがって「署名が必須だったか」を応答検証時に
判定できない。`close` は `verifySignature: false` を明示しており、署名付き応答でも検証しない。

## 影響

- signing key確立後の未署名応答が、message IDさえ一致すれば後続decoderへ渡る。
- signing requiredを通知したserverとの通信でも、応答改ざんやdowngradeをfail closedにできない。
- CLOSE応答のstatus改ざん・破損を検出できず、server/clientのhandle状態が食い違う可能性がある。

暗号化transformはAEADで保護されるため対象外。問題は署名のみを使うセッションの平文SMB2応答。

## 対応方針

1. NEGOTIATE結果のsigning policyを`SMBSession`に保持する。
2. signing key確立後の平文応答は、少なくとも署名必須セッションではSIGNED flagを必須にする。
3. SIGNED flagがある場合は常にMACを検証し、欠落時と不一致時を明確なprotocol errorにする。
4. `close(... verifySignature: false)`の理由を再検証し、互換性上必要なら対象serverと条件を限定する。
5. SESSION_SETUP中などkey確立前の例外フェーズを状態として明示する。

## リグレッションテスト

- signing required + 未署名応答を拒否する。
- signing required + 正しい署名を受理し、不正署名を拒否する。
- CLOSE応答も同じpolicyで検証される。
- 暗号化transform応答は既存のAEAD検証経路を維持する。
