# 039 concurrency: 同期progress callbackがsession actorとwire処理を停止できる

- 種別: concurrency / callback contract / availability
- 重要度: medium
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`SMBTransferProgressEmitter`, read/write/upload/download)

## 問題

progress callbackは同期`@Sendable` closureで、transfer loopから直接呼ばれる。全経路がsession actor上で
動くわけではないが、少なくとも`SMBSession.write(data:)`はactor-isolated method内で`progress.emit`を
実行するため、そのcallbackの実行時間中はsession actorが占有される。

callbackがdisk I/O、logging lock、main-thread同期処理などでblockすると、同じactorのreceive loop、
credit grant、cancel、close、keepaliveなどが進まない。callbackのqueue/executor、最大実行時間、
reentrancy contractはpublic APIに明示されていない。

## 影響

- 遅いUI/progress処理がnetwork timeoutや全in-flight operationの遅延を引き起こす。
- callbackから同じsessionを操作するTaskを起動して待つ設計ではdeadlockに近い停止が起き得る。
- progress有効時だけthroughputやcancellation応答性が大きく変わる。

## 対応方針

1. protocol actorから任意のuser callbackを直接実行しない。
2. bounded/coalescing progress channelを介し、専用task/executorで通知する。
3. 遅いconsumerに対してeventを無制限queueせず、最新値へcoalesceする。
4. callback ordering、delivery executor、最終event、cancellation時のcontractをdocumentする。

## リグレッションテスト

- progress callbackを意図的にblockしても別in-flight response、cancel、closeが処理される。
- 高頻度chunkでnotification queueが無制限に増えず、最終bytes値は失われない。
- callbackから別session operationを開始してもhangしない。
- progress nil時と有効時で転送結果・error semanticsが一致する。
