# 045 CI: 4GiB境界のstream E2Eが全自動jobでskipされる

- 種別: CI / large-file correctness / E2E gap
- 重要度: medium
- 状態: open
- 関連: `Tests/SMBeeTests/SMBeeE2ETests.swift` (`testReadStreamCountsFileLargerThan4GiB`)

## 問題

4GiB超stream testは`SMBEE_E2E_LARGE=1`と事前作成fileを要求するが、どのworkflowもenvを設定せず、
Samba setupも`large-4gib-plus.bin`を作らない。このためPR、master、週次compatibilityの全jobで常にskipされる。

unit testはUInt64 offset計算を検証できるが、実serverで4GiB境界を越えるREAD request/response sequence、
credit、暗号transform、EOF処理はこのE2Eでしか確認できない。

## 影響

- offsetの32bit truncationや4GiB付近のloop終了regressionが自動検出されない。
- testがsuiteに登録されているため、E2E coverageがあるように見えるが実際は毎回skipされる。
- 大容量testの手動実行頻度と最終成功時点が追跡されない。

## 対応方針

1. 週次またはmanual workflowでsparseな4GiB+1 fileをSamba container内に作成する。
2. `SMBEE_E2E_LARGE=1`をそのjobだけ設定し、専用timeoutとdisk/network budgetを持たせる。
3. 毎PR向けには4GiB境界付近のrange readを使い、全4GiB転送せずoffset encodingを実serverで確認するtestを追加する。
4. skip理由と件数をjob summaryへ出し、重要testのunexpected skipをfailさせる。

## リグレッションテスト / CI受け入れ条件

- PR smokeが`UInt32.max`前後の複数rangeを実serverから正しく読む。
- scheduled large jobが4GiB境界を越えてstreamし、総byte数とEOFを確認する。
- large fixtureはsparse作成し、artifactやrepositoryへ巨大fileを保存しない。
- large testがskipされた場合、専用jobはgreenにせず理由を明示する。
