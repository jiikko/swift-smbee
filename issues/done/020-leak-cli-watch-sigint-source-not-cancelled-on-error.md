# 020 leak: smbcli watch の SIGINT DispatchSource が error path で cancel されない

- 種別: bug / resource leak
- 起票: 2026-07-11
- 状態: open

## 症状 / リスク

`smbcli watch` は `DispatchSourceSignal` を作って `sigint.resume()` した後、`task.value` が正常終了または `CancellationError` の場合だけ末尾の `sigint.cancel()` に到達する。watch task が通常の error を throw した場合、`sigint.cancel()` が実行されずに source / handler capture が残る。

CLI process は多くの場合そのまま終了するため実害は限定的だが、テストや将来の long-lived command runner では signal source と capture のリークになる。

## 根拠

該当箇所:

- `Sources/smbcli/SMBCLI.swift`: `Watch.run()`
- `Sources/smbcli/SMBCLI.swift`: `makeSIGINTSource(...)`

現在の構造:

```swift
let sigint = makeSIGINTSource { task.cancel() }
sigint.resume()
do {
    try await task.value
} catch is CancellationError {
}
sigint.cancel()
```

`task.value` が `CancellationError` 以外を throw すると、`sigint.cancel()` を飛ばして `run()` から throw する。

## 修正方針

`sigint.resume()` の直後に `defer { sigint.cancel() }` を置く。必要なら `task.cancel()` も defer で入れ、error path で watch task が残らないようにする。

## 受け入れ条件

- [ ] watch task が通常 error を throw しても `DispatchSourceSignal.cancel()` が呼ばれる
- [ ] SIGINT cancellation の既存挙動が維持される
- [ ] unit test か小さな helper 分離で error path cleanup を検証する

## リグレッションテスト

- watch taskが非CancellationErrorで終了した場合にもSIGINT sourceのcancel handlerが1回呼ばれる。
- 正常終了、SIGINT cancellation、初期化後の即時errorを同じcleanup helperで検証する。
- 複数回watchを実行するtestでsignal sourceやhandlerが前回分から残らないことを確認する。
