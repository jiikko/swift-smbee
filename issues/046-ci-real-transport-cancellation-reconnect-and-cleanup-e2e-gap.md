# 046 CI: real transportでのcancellation/reconnect/cleanupがE2Eされていない

- 種別: CI / resource lifecycle / concurrency E2E gap
- 重要度: high
- 状態: open
- 関連: `.github/workflows/e2e.yml`, `Tests/SMBeeTests/SMBeeE2ETests.swift`, issues/040, issues/041

## 問題

現行E2Eは正常系operationを広くcoverするが、実socket/Sambaで次のfailure lifecycleを検証しない。

- in-flight READ/WRITE/CHANGE_NOTIFYのtask cancellation
- persistent sessionのkeepalive中close
- watchの`autoReconnect`とsubscription gapのoverflow通知
- copy/recursive operation中cancel後のserver-side handle解放
- transport切断時のpending continuation/credit waiter drain

unit fixtureはmessage IDやresponse順を決定的に検証できる一方、POSIX socket cancellation、Samba handle lifetime、
TCP closeとのraceは実transportでしか確認できない。

## 影響

- continuation hang、socket/handle leak、cleanup未送信がunit greenのまま再発する。
- issue 018/019/023/040/041の修正が実server lifecycleまで有効かCIで保証されない。
- `watch --reconnect`はpublic機能だが、PR E2Eのwatchは通常subscriptionのみで再接続を起こさない。

## 対応方針

1. lifecycle専用E2E test classを作り、短いbounded timeoutでcancel/closeを注入する。
2. Sambaの`open_files`/statusまたはserver logを使い、test前後のopen handle数を比較する。
3. proxyまたはSamba container操作でTCP切断・server restartを起こし、reconnect/overflowを検証する。
4. flakyなsleep依存を避け、request開始signalやserver log pollingで注入時点を同期する。
5. PRでは小さなcancel/close smoke、重いrestart/stressはscheduled jobへ分ける。

## リグレッションテスト / CI受け入れ条件

- CHANGE_NOTIFY待機中cancelが期限内に完了し、server handleがbaselineへ戻る。
- upload/copy途中cancel後にsession closeが完了し、次の接続・operationが成功する。
- server restart後にautoReconnectがoverflowを1回通知して再subscriptionする。
- lifecycle jobにjob-level timeoutと失敗時のclient/Samba stack・open handle dumpを付ける。
