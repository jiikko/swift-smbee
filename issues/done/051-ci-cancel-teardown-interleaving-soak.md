# 051 CI: cancel × teardown の interleaving を狙い撃つ stress テストが無い

- 種別: CI / test coverage
- 重要度: low-medium
- 状態: open
- 関連: `testClientSessionKeepAliveSendsPeriodicEchoUntilClose` の CI flake (5ffdec0 / d87198c で修正),
  issues/047 (sanitizer job), issues/013 (hang 時の sample 取得), `.github/workflows/test.yml`

## 問題

keepalive close の flake は「遅い CI ランナーでのみ出る interleaving」で、ローカルでは CPU 負荷を
かけた 60 回反復でも再現しなかった。この class (cancellation × credit window × teardown の競合) は
単発実行の unit テストでは捕まらず、master 到達後に CI で間欠的に落ちて初めて発覚する。

## 影響

- 間欠 flake は「再実行で通る」ため退行として認識されにくく、真因調査が後回しになる。
- concurrency まわりのリファクタの安全網が実質 CI の 1 回実行しかない。

## 対応方針

段階的に導入する (最初から nightly 数百回反復にはしない — 実行時間と flake ノイズの増加を避ける):

1. まず決定論的な interleaving テストを増やす: cancel のタイミングを transport 側で制御できる
   テストフック (応答の enqueue を suspend できる ControlledReceiveTransport の拡張) で、
   「echo in-flight 中の close」「park 中 cancel 後の grant」を決定的に再現する。
2. 次に bounded stress: cancel/teardown 系テストを既存 Test workflow 内で小回数 (〜20 回) 反復する
   step を追加し、全体 timeout と hang 時の process sample (issues/013 の仕組みを流用) を付ける。
3. 効果を見てから nightly の大回数 soak へ拡張するか判断する。トリガの paths フィルタは
   `Sources/SMBee/` 全体にする (SMBClient.swift 限定だと SMB2Header.swift の credit window 変更を取りこぼす)。
4. issues/047 の TSan job が入れば同じ対象を TSan 下でも回す (data race は検出できるが、
   actor 間の論理的順序競合・無限待機は soak / timeout 側の担当)。
