# 037 security: 認証後もsessionがplaintext credentialを保持し続ける

- 種別: security hardening / secret lifetime
- 重要度: medium
- 状態: open
- 関連: `Sources/SMBee/NTLM.swift` (`SMBCredential`), `Sources/SMBee/SMBClient.swift` (`SMBSession`, reconnect)

## 問題

`SMBCredential`はpublic mutable `String password`または`[UInt8] ntHash`を持ち、`SMBSession`は
credential全体を`let` propertyとしてsession終了まで保持する。NTLM SESSION_SETUP後の通常operationは
derived signing/encryption keyだけで実行できるが、元password/hashもactorと同じ期間memoryに残る。

認証計算ではpasswordからUTF-16 buffer、NT hash、NTOWFv2、session keyなど複数の一時配列も作られ、
使用後の明示的な寿命短縮やzeroization方針がない。

## 影響

- crash dump、memory inspection、use-after-compromise時に元password/hashを取得できる時間が長い。
- reconnect用credential providerが別に保持されているため、接続済み`SMBSession`内の元credential保持は重複する。
- value typeのcopyによりsecretの複製数を追跡しにくい。

## 対応方針

1. SESSION_SETUP完了後、`SMBSession`から元credentialを破棄する。
2. reconnectは既存のcredential providerから必要時だけ再取得する。
3. password APIとNT hash APIをsecret container型へ寄せ、不要なpublic mutation/copyを減らす。
4. Swiftで完全zeroizationを保証できない制約をdocumentしつつ、mutable byte storageはbest-effort wipeする。
5. debug/error descriptionへsecretが出ないcontract testを維持する。

## リグレッションテスト

- 認証完了後のsession stateがpassword/NT hashを保持しないことを内部contract testで確認する。
- reconnect時だけproviderが再度呼ばれ、通常operationではcredentialへアクセスしない。
- credential、authentication error、debug logの文字列表現にsecretが含まれない。
- password認証、pass-the-hash、anonymousの既存接続を維持する。
