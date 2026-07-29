# 069 design: 単一 handle の cleanup 失敗が closeTransport で共有 session 全体を巻き添えにする

状態: **open（未修正バグではなく、cleanup 失敗時の session invalidation policy の再検討）**
起票: 2026-07-27（issue 067 A の敵対的レビューで検出、codex 反証レビューで位置づけを訂正）
関連: `Sources/SMBee/SMBClient.swift`（`SMBSession.bestEffortClose` / `closeTransport`） /
`issues/065-leak-cleanup-wire-operations-have-no-deadline.md`（状態 done・cleanup timeout はここで実装済み。本 issue はその timeout が効いた後の巻き添え範囲の話）

## 位置づけ（codex 反証レビューの結論）

現挙動は**意図的な設計**である: コードコメントに「FileId の寿命が不明な場合、session を再利用しては
ならない → shared transport を invalidate する」と明記されている。CLOSE の成否が分からない handle を
抱えたまま session を使い続けるのは安全でない、という判断自体は正しい。
本 issue が問うのは「その invalidation の**範囲**が、並行利用が前提になった今も適切か」だけ。

## 症状（未再現・レビュー由来の構造指摘）

`bestEffortClose` は CLOSE がタイムアウト・失敗すると `closeTransport()` に落ちる。
`closeTransport()` は transport を閉じ、同一 session の **全 pending response と credit waiter** を
`connectionClosed` で解決する。つまり 1 つの handle の後始末に失敗しただけで、並行して動いていた
無関係な list / read / write がすべて巻き添えで失敗する。

発火条件（構築されたシナリオ。実測はしていない）:

1. 同一 `SMBClientSession` 上で複数 operation が並行している（prefix read 4 並列 + list など）。
2. どれか 1 本が cancel / エラーで `bestEffortClose` に入る。
3. サーバが CLOSE に応答しない / cleanupTimeout（5s）を超える / credit 待ちになる。
4. `closeTransport()` が発火し、他の operation の pending / waiter が全部 `connectionClosed`。

「dead session を確実に畳む」ためのこの設計は単発 operation では妥当だが、issue 067 A で
同一 session 上の並行利用が前提になったため、誤爆コストが上がった。

## 対応候補

- 「共有 session を安全に再利用できる条件」を定義した上で、handle 単位の cleanup 失敗と
  session 全体の transport 障害を区別する（CLOSE 失敗 = handle を諦めるだけにできるのは
  どの条件下か、を先に言語化する。無条件の分離は現コメントの安全判断を壊す）。
- または consumer 側でサムネイル用 session を browsing 用と分離する
  （obaket `macOS/issues/437` の Phase 2 表にある「サムネ用の session を分ける」と同じ話。
  どちらで吸収するかは 437 側の設計と合わせて決める）。

## 先にやること

「CLOSE 無応答 → closeTransport → 並行 operation 全滅」を fixture（応答を返さない
InMemoryTransport）で再現する unit を書き、現挙動を固定してから対応方針を決める。
✅ unit で固定済み (2026-07-29、`testBestEffortCloseTimeoutClosesTransportAndFailsConcurrentPendingOperations`)。
072 で追加した send failure 経路のテストとは別に、CLOSE 無応答から並行 operation 全滅までを再現する。

## 関連

- `issues/065-leak-cleanup-wire-operations-have-no-deadline.md`（状態 done。cleanup timeout の実装。本 issue はその timeout が「効いたとき」の巻き添え範囲の話）
- obaket `macOS/issues/437`（session 分離で consumer 側に吸収する案）
