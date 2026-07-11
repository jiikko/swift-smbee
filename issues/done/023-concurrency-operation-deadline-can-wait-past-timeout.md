# 023 concurrency: operation deadlineがキャンセル非協調な処理をtimeout後も待ち続ける

- 種別: concurrency / cancellation / API semantics
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBOperationDeadline.swift`, `issues/018-leak-pending-wire-continuations-on-cancel-or-close.md`

## 問題

`SMBOperationDeadline.run`はoperationとsleepをstructured task groupで競争させ、先に完了した
結果を得た後に`group.cancelAll()`する。ただしtask groupのscopeは、全child taskが終了するまで
抜けられない。

```swift
let result = try await group.next()
group.cancelAll()
return result
```

timeout childが先に完了しても、operationがキャンセルを観測しない、blocking I/Oから戻らない、
またはpending continuationがresumeされない場合、`run`自体は設定時間で返らない。
現在のwire transactionにはキャンセル後も元のcontinuationがserver応答待ちになり得る経路があり、
issue 018と組み合わさるとper-file timeoutが実質的に無効になる。

## 影響

- recursive transferの`perFileTimeout`が上限時間として機能しない。
- timeout後もCLIや呼び出しtaskが停止し、後続fileの処理へ進めない。
- timeoutというAPI名と実際の保証が一致しない。

## 対応方針

1. まずwire transactionのキャンセル時にpending continuationを確実にfailさせる(issue 018)。
2. transportのconnect/send/receiveがキャンセルで有限時間内に終了することをtestする。
3. deadline helperの契約を「operationをキャンセルし、終了を待つ」とするか、「期限で必ずcallerへ返す」とするか明文化する。
4. hard deadlineが必要なら、operationを所有するsession/transportを期限時にcloseして待機を解除する設計にする。

unstructured taskへ逃がして即returnするだけでは、処理やresourceをbackgroundに残すため解決にならない。

## リグレッションテスト

- 応答しないtransportを使い、指定timeout付近で`run`が完了する。
- timeout時にpending response、credit waiter、socketが残らない。
- operation先行成功、operation先行error、親task cancellationも決定的に完了する。
