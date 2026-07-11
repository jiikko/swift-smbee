# 019 leak: cleanup の CLOSE/TREE_DISCONNECT/LOGOFF が task cancellation で送られない可能性

- 種別: bug / resource leak
- 起票: 2026-07-11
- 状態: open

## 症状 / リスク

多くの API は SMB file handle を開いた後、成功/失敗 path で `try? await session.close(...)` を呼んでいる。しかし `close(...)` 自体が通常の cancellable wire transaction なので、親 task が既に cancelled の状態では cleanup の `CLOSE` が送信前に失敗し得る。

結果として、サーバ側 file handle / named pipe handle / tree session が transport close か server timeout まで残る可能性がある。特に persistent `SMBClientSession` では process 側の transport を閉じないまま操作だけキャンセルされるケースがあり、server-side handle leak として見える。

## 根拠

該当箇所:

- `Sources/SMBee/SMBClient.swift`: `SMBClientSession.list/stat/read/withReadStream/upload/...`
- `Sources/SMBee/SMBClient.swift`: static `SMBClient` APIs の `do/catch { try? await session.close(...) }`
- `Sources/SMBee/SMBClient.swift`: `SMBSession.close(treeId:fileId:)`
- `Sources/SMBee/SMBClient.swift`: `SMBSession.disconnect(treeId:)`

`SMBSession.close(...)` は `signedWireTransaction(...)` に乗るため、内部で `Task.checkCancellation()` を通る send path に影響される。cleanup 用の `try? await close` はエラーを握りつぶすため、キャンセルで CLOSE が未送信でも caller からは観測しづらい。

## 修正方針

1. cleanup 用の non-cancellable best-effort close path を用意する。
2. `withSMBHandle` のような helper を作り、CREATE と CLOSE の対応を集約する。
3. cleanup close が失敗した場合、persistent session では該当 session を suspect として transport close するか、明示的に caller へ知らせる方針を決める。
4. `TREE_DISCONNECT` / `LOGOFF` も close path と同じく cancellation shield する。

## 注意点

- Swift task cancellation を完全に無視して無制限に cleanup 待ちすると shutdown が遅くなる。短い timeout 付きの best-effort cleanup が現実的。
- `CLOSE` 送信に失敗した後も同じ session を使い続けると、server-side handle が残ったままになり得る。失敗時の session invalidation も設計対象。

## 受け入れ条件

- [ ] operation cancel 後も opened file handle に対して `CLOSE` が best-effort で送られる
- [ ] cleanup close が送れない場合の session/transport 扱いが明文化される
- [ ] `withReadStream` / `list` / `stat` / named pipe RPC の cancellation test を追加する

## リグレッションテスト

- CREATE成功直後に親taskをcancelしても、CLOSE送信またはtransport closeのどちらかが必ず観測される。
- READ/QUERY_DIRECTORY/named pipe RPCの途中cancelでserver側handle数がbaselineへ戻る。
- cleanup中にCLOSE応答が欠落するfixtureでもtimeout後にsession teardownが完了する。
- 正常終了時はCLOSE、TREE_DISCONNECT、LOGOFFが重複せず従来順序で送信される。
- [ ] persistent session で cancel を繰り返しても server 側 open handle 数が増え続けない
