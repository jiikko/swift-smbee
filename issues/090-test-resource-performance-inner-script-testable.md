# 090 test: run-resource-performance の inner script を分離して retry/purge をテスト可能にする

- 種別: test
- 起票: 2026-09-08 (retro [`085`](085-retro-perf-ci-swiftpm-cache-2026-08-28.md) 項目 4 の切り出し)
- 状態: **open / 頻度を見てから着手**
- 関連: `bin/ci/run-resource-performance` / `bin/ci/test-performance-scripts` (shell test の先例) /
  prewarm を導入した commit `68ab66d`

## 問題

commit `68ab66d` で `run-resource-performance` に SwiftLint binary の **prewarm + retry + cache purge** を
入れた。しかし既存の shell test (`bin/ci/test-performance-scripts`) は docker stub で外側だけを回すため、
**inner bash の retry / purge は 1 度も実行されない**。

つまり「transient な download 失敗から回復する」という主張は、**現状テストで守られていない**。
issue 085 の D3 設計レビューと実装後の敵対レビューが**両方とも**「inner script を分離して
fake `swift` で走らせる harness」を提案していた。

## なぜ今すぐやらないか

発火条件 (GitHub からの transient な部分応答) の**頻度が分かっていない**。
2026-08-28 の修正後、warm cache では download 0 件で安定している (run 33150668326 で確認済み)。
retry が実際に必要になる頻度が低いなら、harness の維持コストの方が高くなりうる。

## 対応方針 — trigger 待ち

**次のどちらかが起きたら着手する**:

1. **prewarm の retry が実際に発火した run が観測されたとき** (ログに retry / purge の痕跡が出る)。
2. **prewarm / purge のロジックを次に変更するとき**。

## 対応案

`run-resource-performance` の inner bash を `bin/ci/prewarm-swiftlint-binary` 等に切り出し、
`PATH` 先頭の fake `swift` で次を決定論的に回す:

- 1 回目が部分応答 → purge → 2 回目で成功する
- 3 回とも失敗 → 明示的に失敗する (沈黙して緑にしない)
- cache path が読めない / 既に存在する

🚨 fake を PATH 先頭に置くときはグローバルルール `path-shim-must-resolve-real-binary.md` の規律に従う
(実体を絶対パスで解決してから exec する。相対名だと PATH 先頭の自分自身に解決して無音で無限再帰する)。

## 完了条件

- 切り出した script の retry / purge / 全失敗の 3 経路が shell test で回り、
  **その test がどの workflow の step から実行されるかまで配線されている**
  (`bin/ci/test-performance-scripts` は現状 launcher / prewarm を検査対象にしていない)。
- 各経路に**変異を 1 つ当てて red** を確認する (retry 回数を 1 に落とす / purge を消す / 失敗を握り潰す)。

## スコープ外

- prewarm そのものの設計変更。現行の 3 回 retry + purge は CI で機能している。
