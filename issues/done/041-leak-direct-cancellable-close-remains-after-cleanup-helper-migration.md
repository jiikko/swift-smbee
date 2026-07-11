# 041 leak: cleanup helper移行後もcancellableな直接CLOSEが残っている

- 種別: resource leak / cancellation consistency
- 重要度: medium-high
- 状態: open
- 関連: `Sources/SMBee/SMBClient.swift` (`copyFile`, `copyDirectory`, `deleteRecursively`, named pipe cleanup)

## 問題

issue 019対応で`bestEffortClose(treeId:fileId:)`が追加され、多くのpublic operationはcaller cancellationを
継承しないcleanupへ移行した。一方、内部のcopy/recursive delete/named pipe経路には次の形式が残る。

```swift
try? await close(treeId: treeId, fileId: fileId)
```

親taskがcancel済みの場合、通常のCLOSE transactionはsend前の`Task.checkCancellation()`で失敗できる。
errorを`try?`で破棄するため、persistent sessionを維持したままserver-side handleだけが残る。

## 影響

- copyやrecursive operationを繰り返しcancelするとserver側open handleが増える。
- source/destinationの2 handleを使うcopyでは一度に複数handleが残り得る。
- cleanup policyがcall siteごとに異なり、issue 019の再発防止が不完全になる。

## 対応方針

1. cleanup目的の`try? await close(treeId:fileId:)`を`await bestEffortClose(...)`へ移行する。
2. operation本体としてCLOSE結果が必要な箇所と、cleanupのCLOSEをAPI名・lintで区別する。
3. 複数handleを開くoperationは共通scope helperで逆順cleanupする。
4. shielded cleanupにも期限を設け、応答欠落時はtransportをinvalidateする。

## リグレッションテスト

- copyのsource/destination open後、各await pointでcancelを注入して両handleが閉じる。
- recursive copy/deleteのquery callback中cancelでdirectory handleが残らない。
- named pipe bind/request/close各段階のerrorでpipe handleが閉じる。
- lintがcleanup内の新しい`try? await close(treeId:)`を検出する。
