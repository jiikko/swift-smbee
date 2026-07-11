# 040 leak: batch CLIのsession closeがfire-and-forgetでprocess終了と競合する

- 種別: resource leak / structured concurrency / CLI cleanup
- 重要度: medium
- 状態: open
- 関連: `Sources/smbcli/BatchCommands.swift` (`MGet.run`, `MPut.run`)

## 問題

batch commandはpersistent session作成後、同期`defer`からunstructured Taskを起動してcloseする。

```swift
defer { Task { await session.close() } }
```

deferはTaskの完了を待たないため、operation closureとcommandはTREE_DISCONNECT、LOGOFF、transport closeより
先にreturnできる。CLI processが直後に終了すればcleanup taskは完走を保証されない。error/cancellation pathでも
同じ構造になる。

## 影響

- server側tree/sessionとsocketがprocess終了までgracefulに解放されない。
- unit testやlong-lived command runnerではclose taskが後続test/operationへ持ち越される。
- close中のerrorやhangをcallerが観測・制御できない。

## 対応方針

1. async scopeを`do/catch`で囲み、success/error両方で`await session.close()`してからreturnする。
2. cancellation済み親taskでもcleanupできる既存のshielded disconnectを利用する。
3. session lifetime helperを用意し、batch commandごとの手書きcleanupをなくす。

## リグレッションテスト

- success、通常error、cancellationの各pathでcommand完了前にsession closeが完了する。
- TREE_DISCONNECT、LOGOFF、transport closeの順序と各1回実行を確認する。
- commandを連続実行してもbackground cleanup taskが残らない。
- close response欠落時もbounded timeoutまたはtransport closeで終了する。
