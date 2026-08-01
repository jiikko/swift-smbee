# 065 leak: cleanup wire operationに期限がなくsessionとsocketを永久保持し得る

- 種別: bug / resource leak / cleanup liveness
- 重要度: high
- 起票: 2026-07-26
- 状態: done
- 関連: `Sources/SMBee/SMBClient.swift` (`SMBSession.bestEffortClose`, `SMBSession.disconnect`, `SMBClientSession.close`, `SMBClient.withSession`)

## 問題

caller cancellationを継承せずにSMB handle/sessionを解放するため、cleanupは`Task.detached`で
`CLOSE`、`TREE_DISCONNECT`、`LOGOFF`を送っている。しかしcleanup task自身にはdeadlineがなく、
各wire transactionはserverのresponseを待ち続ける。

既定の`POSIXSocketTransport`は`timeout: nil`で作られるため、serverがTCP接続を維持したまま
cleanup responseを返さない場合、socket-level timeoutも働かない。このときcleanup callerも
`task.value`をawaitしているので、次のresourceが期限なく保持される。

- local socket fdとtransport
- `SMBSession` actor、crypto key、pending response state
- server側file handle / tree / authenticated session
- cleanup完了を待つpublic operationまたは`SMBClientSession.close()`のtaskとcapture

これは単にgraceful closeが遅いだけではない。`disconnect`は`closeTransport()`を
`TREE_DISCONNECT`と`LOGOFF`の後にしか呼ばないため、最初のresponse欠落時には強制解放へ到達しない。

## 根拠

### file handle cleanup

`SMBSession.bestEffortClose`はcaller cancellationを遮断する一方、detached taskの完了を無期限に待つ。

```swift
func bestEffortClose(treeId: UInt32, fileId: [UInt8]) async {
    let task = Task.detached { [self] in
        try? await self.close(treeId: treeId, fileId: fileId)
    }
    await task.value
}
```

`close(...)`は通常の`signedWireTransaction`なので、CLOSE responseがterminal eventになるまで完了しない。
read/upload/stat/watch/ACL/sparse/recursive operationなど多数のpathがこのhelperをawaitする。

### session cleanup

`SMBSession.disconnect`も同様に期限なしのdetached taskをawaitし、最後にだけtransportを閉じる。

```swift
func disconnect(treeId: UInt32) async {
    let task = Task.detached { [self] in
        try? await self.treeDisconnect(treeId: treeId)
        try? await self.logoff()
        await self.closeTransport()
    }
    await task.value
}
```

このpathはpersistent sessionの`SMBClientSession.close()`だけでなく、one-shot APIの成功時に
`SMBClient.withSession`からも必ず呼ばれる。そのため、本体operationが成功していてもcleanup responseの
欠落だけでAPI全体がreturnしない。

### timeout default

`SMBClient.resolvedTransportFactory`はtimeout未指定時に`POSIXSocketTransport(timeout: nil)`を作る。
POSIX transportのblocking `recv()`には、その場合`SO_RCVTIMEO`が設定されない。

## 発生条件

1. CREATE/READ/WRITE等の本体operationは成功する。
2. clientがCLOSE、TREE_DISCONNECTまたはLOGOFFを送る。
3. server、proxy、fault-injection transportがTCPを切らずにresponseだけをdropする。
4. cleanup taskはcancelされず、transportも閉じられず、callerがreturnしない。

特にpersistent sessionでfile handleのCLOSEだけがdropされた場合、他operation用の接続を維持したい意図と
cleanupを必ず終わらせる要件が衝突するため、明示的なsession invalidation policyが必要になる。

## 対応方針

1. cleanup専用の短いbounded deadlineを導入する。
2. `bestEffortClose`が期限切れになった場合は、handle stateが不明なsessionをsuspectとして
   `closeTransport()`し、server側resourceをconnection teardownで回収させる。
3. `disconnect`は各graceful stepをboundedにし、失敗・timeout・cancellationのいずれでも
   `closeTransport()`へ必ず到達する構造にする。Swiftの同期`defer`からasync closeを呼べないため、
   `do/catch`またはtask groupでterminal pathを明示する。
4. public socket `timeout`とは別にcleanup deadlineを固定するか、internal policyとして一元化する。
5. cleanup timeoutを通常operation errorへ上書きするかはAPI contractを決める。少なくともresource解放は
   error reportingより優先して実行する。

## リグレッションテスト

- CLOSE requestを受信後、responseを返さず接続を開いたままにするtransport fixtureを作る。
- `bestEffortClose`が有限時間内にreturnし、transport closeが1回呼ばれることを確認する。
- TREE_DISCONNECT response dropとLOGOFF response dropを個別に注入し、どちらでも
  `SMBClientSession.close()`が有限時間内に完了することを確認する。
- one-shot APIの本体responseだけ成功させ、teardown responseをdropしてもAPIとtransportが終了することを確認する。
- timeoutと正常responseを競合させ、pending continuationの二重resumeが起きないことをstress testする。

## 完了条件

- [x] cleanup wire operationがserver無応答時にもbounded timeで終了する。
- [x] cleanup失敗時にtransportが必ず閉じられる。
- [x] local fd、pending continuation、server handleを接続timeoutまで保持し続けない。
- [x] persistent sessionをinvalidateする条件がdocs/API contractに明記される。
- [x] CLOSE / TREE_DISCONNECT response dropのunit testが追加される。LOGOFFは同じbounded helperを使用する。

## 対応結果

- cleanup専用deadlineを`SMBSession`へ追加し、production defaultを5秒にした。
- `bestEffortClose`、scoped tree close、session disconnectをbounded化した。
- cleanup failure/timeout時はtransportを閉じ、pending responseとcredit waiterをdrainする。
- `closeTransport()`をidempotent化し、複数cleanup pathが競合してもtransport closeは1回にした。
- responseを返さないtransport fixtureでCLOSEとTREE_DISCONNECTの回帰testを追加した。
