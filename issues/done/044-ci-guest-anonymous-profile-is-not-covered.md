# 044 CI: guest/anonymous SMB profileが自動E2E対象に入っていない

- 種別: CI / authentication compatibility / E2E gap
- 重要度: medium-high
- 状態: open
- 関連: `test/e2e/smb/guest.conf`, `.github/workflows/e2e.yml`, `Tests/SMBeeTests/SMBeeE2ETests.swift`

## 問題

guest用Samba configは存在するが、コメントに手動smoke手順があるだけで、`e2e.yml`と
`samba-compat.yml`のmatrixには含まれない。`testProbeNegotiatesExpectedProfile`のswitchもguest profileを
扱わず、通常E2Eは常にusername/password credentialを作る。

anonymous NTLMはsession keyを持たず、署名・暗号化を使わない専用branchを通る。通常のauthenticated
profileではこのbranchを一切検証できない。

## 影響

- guest SESSION_SETUP、unsigned request/response、tree connectのregressionがCIで検出されない。
- signing policy強化時にanonymousだけ接続不能になってもauthenticated E2Eはgreenになる。
- CLIのusernameなしURL、`--guest`、`--anonymous`の実server動作が未保証になる。

## 対応方針

1. guest profileをPR E2E matrixへ軽量smokeとして追加する。
2. guest専用testでprobe、list、read、書込み可否、closeを確認する。
3. CLI smokeにもusernameなしURLと`--guest`の最低1経路を追加する。
4. guest profileではsigning/encryptionが無効であることを明示assertする。

## リグレッションテスト / CI受け入れ条件

- guest configに対しanonymous credentialでknown fileをlist/readできる。
- wire fixtureまたはserver logでguest trafficが署名・暗号化を要求していないことを確認する。
- password付きauthenticated profileの既存matrixを維持する。
- guest書込みpolicyをconfigとtestで固定し、意図しないprivilege拡大も検出する。
