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

## 対応 (2026-09-08) — 完了

### 「trigger 待ち」からの逸脱について

本 issue は「頻度を見てから着手」と書いていたが、**ユーザーの明示指示** (2026-09-08:
「089 / 090 をやって」) により着手した。上記 2 つの trigger はどちらも発火していない。

### 切り出した script の名前

起票時の案は `bin/ci/prewarm-swiftlint-binary` だったが、実際に prewarm しているのは
SwiftLint binary 単体ではなく `swift package resolve` の依存解決全体なので
**`bin/ci/prewarm-swiftpm-artifacts`** にした。

### 変更

| ファイル | 変更 |
|---|---|
| `bin/ci/prewarm-swiftpm-artifacts` (新規) | retry / purge の方針を切り出し。purge 対象の拒否ガード付き |
| `bin/ci/run-resource-performance` | docker payload 内の 15 行を `bash bin/ci/prewarm-swiftpm-artifacts` に置換 |
| `bin/ci/test-performance-scripts` | scenario 6 本 + 実行数 pin + `test_syntax_checks` への登録 |

配線: `bin/ci/test-performance-scripts` は既に `.github/workflows/performance.yml` の
`ci-script-tests` job (`ubuntu-latest`) から実行されているので、追加の workflow 配線は不要。

### 破壊的操作のガード (脅威モデル)

purge 対象は host の bind mount 先 (`${{ github.workspace }}/.build/swiftpm-cache`) を指すので、
`rm -rf` の**手前**で拒否する。守るのは「空 / 未設定 / typo / symlink の張り替えによる意図しない削除」
であって、**環境変数を自由に設定できる相手による意図的な指定ではない** (その相手は script を
介さず `rm -rf` を直接打てる)。特に守りたいのは**テスト scenario の設定ミスで working tree を
消すこと**。ガードは `rm -rf` の直前に毎回評価する (検査と実行の間に `swift package resolve` が
数分入るため。`sandbox-real-destructive-test-apis.md`)。

### 実測: bash 3.2 で拒否がクラッシュしていた

codex の初版は空配列を `set -u` 下で展開しており、**macOS の `/bin/bash` (3.2) では
`SWIFTPM_ARTIFACTS_DIR=/` が rc=2 の拒否ではなく rc=1 の `unbound variable` になっていた**。
CI は Linux の bash 5 なので緑のまま見えない形。配列を使わない実装に直し、両 bash で
rc=2 に揃うことを実測した。再発は `test-performance-scripts` の字句 pin が止める
(コメント行を除いてから走査する。pin 自身も変異検証済み)。

### scenario と、それぞれを red にした変異

| scenario | 主張 | red にした変異 |
|---|---|---|
| `test_prewarm_retry_then_success` | 1 回失敗 → purge 1 回 → 2 回目成功で rc=0 | M1 / M2 / M4 |
| `test_prewarm_exhausts_attempts` | 3 回失敗で rc=1・purge 3 回・既存の文言 | M3 / M6 |
| `test_prewarm_success_does_not_purge` | **初回成功では purge しない** | M9 |
| `test_prewarm_refuses_unsafe_targets` | 不正な purge 対象を rc=2 で拒否・`swift` は 0 回 | Gb / Gc / Gd / Ge / Gf / Gg |
| `test_prewarm_handles_path_with_space` | 空白を含むパスで正常に 3 回 purge | M7 |
| `test_run_resource_performance_prewarm_wiring` | payload の配線 + 配列展開不在の字句 pin | M8 / 配列展開の追加 |

変異の内訳: M1 retry 既定 3→1 / M2 `rm -rf` 削除 / M3 最終 `exit 1`→`exit 0` /
M4 成功時 `exit 0`→`:` / M6 purge を 1 回目だけに / M7 `rm -rf` のクォート除去 /
M8 payload から呼び出し削除 / M9 初回成功時にも purge / Gb〜Gg はガードの規則を 1 つずつ無効化。

**13 変異中 12 が red**。baseline は各変異の前後で緑を確認し、変異ごとに `bash -n` が通ることと
diff が意図どおりであることを見てから read した。

### red にできなかったもの (穴として記録)

- **Ga (空文字チェックの削除) は GREEN**。空文字は「絶対パスでない」規則にも引っかかるため、
  空文字チェックは**規則 b と冗長**。単独で効かせるには規則 b と d を同時に外す必要があり、
  現実的な単一の退行ではない。冗長性として**残す**が、独立に変異検証されていないことを記録する。

### 却下した指摘 (D3 敵対レビュー)

却下はゼロ。全 12 件を採用・部分採用・記録に振り分けた。部分採用の内訳:

- 「任意の絶対パスから host bind mount を消せる」→ 意図的な指定は脅威モデルの射程外と明示し、
  **repo 配下/祖先の拒否**だけ足した (テストの設定ミスで working tree を消す経路を塞ぐ)。
- 「caller の `RESOURCE_SKIP_BUILD` 分岐が docker stub で実行されない」→ **今回の変更が作った
  退行ではなく、変更前から同じく未検査**。静的な配線 pin だけ足し、挙動テストは残タスクへ。

### 残タスク

- [ ] `run-resource-performance` の docker payload を実際に評価する caller scenario
      (現状 stub は docker の引数を記録するだけなので、`RESOURCE_SKIP_BUILD=true` の
      cache-hit 経路で prewarm が誤って走る退行を検知できない)。**変更前から同じ状態**で、
      今回の変更が悪化させたものではない。
