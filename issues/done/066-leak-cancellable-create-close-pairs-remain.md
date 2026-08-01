# 066 leak: CREATE後にcancellableな直接CLOSEを使うpathが残っている

- 種別: bug / resource leak / cancellation consistency
- 重要度: medium-high
- 起票: 2026-07-26
- 状態: done
- 関連: `Sources/SMBee/SMBClient.swift`
- 関連issue: `issues/done/019-leak-cleanup-close-operations-are-cancellable.md`, `issues/done/041-leak-direct-cancellable-close-remains-after-cleanup-helper-migration.md`

## 問題

issue 019/041対応後、多くのCREATE/CLOSE pairは`bestEffortClose`へ移行した。しかし現在の実装にも、
CREATEでserver handleを取得した直後、cleanup guardなしで通常のcancellable `close(...)`を呼ぶpathが残る。

親taskがCREATE成功後にcancelされた場合、CLOSE transactionはcancelされ得る。CLOSEの送信前cancel、送信後の
SMB2 CANCEL、response lossのいずれでもserver側handleの解放は保証されない。persistent sessionではtransportを
維持したままoperationだけが終了できるため、同じsessionで繰り返すとopen handleが蓄積し得る。

## 確認した残存箇所

### public persistent-session mkdir

`SMBClientSession.makeDirectory`はCREATE後に直接CLOSEし、`do/catch`または`bestEffortClose`がない。

```swift
let fileId = try await session.create(treeId: treeId, request: .makeDirectory(path: path))
try await session.close(treeId: treeId, fileId: fileId)
```

### one-shot mkdir

`SMBClient.makeDirectory`のoperation closureも同じCREATE/direct CLOSE pairを持つ。error時にはouter
`withSession`がtransportを閉じるため最終回収は期待できるが、CLOSEのcancellation semanticsに依存し、
persistent-session版とcleanup policyが一致していない。

### delete-on-close

`SMBSession.deleteNonRecursive`はfile/dir双方のCREATE後に直接CLOSEする。delete-on-closeの確定には
CLOSE responseがoperation resultとして重要だが、cancel/error時に残ったhandleを回収するfallbackがない。

### recursive copy/delete

- `copyDirectory`のdestination directory CREATE後
- `deleteRecursively`のreparse child DELETE CREATE後
- `deleteRecursively`の各entry DELETE CREATE後

これらも直接CLOSEを使う。`continueOnError`ではCLOSE errorをcollectorへ記録して走査を継続できるため、
同一persistent session内で未回収handleが複数積み上がる可能性がある。

## issue 041との差分

issue 041はcleanup目的の`try? await close(...)`を`bestEffortClose`へ移す内容で完了扱いになった。
今回の残存箇所は`try?`ではなく、CREATE/CLOSE自体がoperation semanticsを担うpathである。そのため単純な
置換では不十分で、次の2つを分ける必要がある。

1. CLOSE responseをoperation成功条件としてcallerへ返す処理
2. 1がcancel/throwした後にhandleまたはtransportを必ず回収するfallback cleanup

## 対応方針

1. `withCreatedHandle`のような共通helperを導入し、CREATE成功後は全terminal pathでcleanupを実行する。
2. 正常pathでは通常CLOSEのresponseを検証する。
3. 通常CLOSEがcancel/throwした場合、issue 065のbounded cleanup policyを使う。ただし同じFileIdへCLOSEを
   再送できるか不明な場合はtransportをinvalidateし、connection teardownで回収する。
4. delete-on-closeでは「CLOSE成功が削除成功」のcontractを維持しつつ、失敗時のsession invalidationと
   destination state確認方針を明記する。
5. lintまたは構造testで、CREATE結果を受け取ったscopeにcleanup fallbackがない直接CLOSEを検出する。

## リグレッションテスト

- persistent `makeDirectory`でCREATE成功直後にcancelし、CLOSE成功またはtransport closeのどちらかを必須にする。
- `deleteNonRecursive`のfile/dir retry双方でCLOSE errorを注入し、handleが回収されることを確認する。
- recursive copy/deleteの各CREATE直後にcancel/errorを注入する。
- `continueOnError`で複数entryを処理してもtracked open handle数がbaselineへ戻ることを確認する。
- 正常pathではCLOSEを重複送信せず、既存のdelete-on-close semanticsを維持する。

## 完了条件

- [x] CREATE成功後の直接CLOSE pathを`closeCreatedHandle`へ集約した。
- [x] CLOSE失敗時にpersistent sessionを再利用できないようtransportをinvalidateする。
- [x] cleanup不能時はsession/transportをinvalidateしてresourceを回収する。
- [x] response欠落を注入する`closeCreatedHandle`回帰testを追加した。
- [x] production call siteに直接のCREATE/通常CLOSE pairが残っていないことを検索で確認した。

## 対応結果

- `closeCreatedHandle`を追加し、通常CLOSE responseをoperation成功条件として維持した。
- CLOSEのtimeout/cancel/error時はtransportを閉じ、FileIdの状態が不明なsessionを再利用しない。
- persistent/one-shot mkdir、non-recursive delete、recursive copy/delete、reparse deleteをhelperへ移行した。
- cleanup deadline testによりresponse欠落時の`SMBTransportError.timedOut`とtransport closeを固定した。
