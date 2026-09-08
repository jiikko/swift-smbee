# issues/ — issue 管理

このリポジトリで **issue と言えば `issues/*.md`** を指す。GitHub Issues は運用していないので
`gh issue` / GitHub MCP の issue 系ツールで探さない（0 件しか返らない）。

運用の骨格は dotfiles の `issues/README.md` に揃えているが、**このリポジトリの実態に合わせて
一部は採用していない**（下の「採用していないもの」）。

## ファイル命名規約

```
issues/NNN-<カテゴリ>-<スラッグ>.md
```

- **NNN**: 3 桁ゼロ埋めの連番。**`issues/` 配下の全体**（直下・`done/`・将来の `pending/` / `waiting/`）で
  最大番号 + 1 を採番する。**番号は再利用しない**。状態ディレクトリへ移動してもファイル名は変えないため、
  コードコメント・commit message から「issue 010」で安定して参照できる
- **カテゴリ**: 下表から選ぶ
- **スラッグ**: kebab-case の短い説明。`retro` は末尾に `-YYYY-MM-DD` を**必須**で付ける

次番号の確認（`ls` でなく `find` を使う。深さを切らないため）:

```sh
git fetch origin
find issues -type f -name '[0-9][0-9][0-9]-*.md' | sed 's|.*/||' |
  grep -oE '^[0-9]{3}' | sort -n | tail -1
```

### カテゴリ

新規 issue は次から選ぶ。

| prefix | 用途 |
|---|---|
| `bug` | 不具合修正 |
| `perf` | 速度・メモリ・リソースの改善（実測の裏付けを本文に置く） |
| `refactor` | 挙動を変えない構造改善・複雑性削減 |
| `test` | テスト・検証の追加/改善 |
| `ci` | CI / workflow / ビルド周辺 |
| `design` | 設計検討（成果物がコードでないもの） |
| `docs` | ドキュメント・規約整備 |
| `chore` | 雑務（依存更新・表示の手直しなど、機能でも不具合でもないもの） |
| `human` | **人間しかできない作業**（動作確認・目視レビュー・外部サービス操作・判断待ち）。`期限:` 必須 |
| `retro` | **セッションの振り返り**（下節） |

🚨 **既存ファイルには上表に無い prefix がある**（`leak` / `robustness` / `data` / `security` /
`concurrency` / `codec` / `credit` / `diag` / `acl` / `protocol` / `share` / `dfs` / `auth` / `cli` /
`linux` / `api` / `workflow`）。これらは**改名しない** —— 番号とパスでの参照が切れるコストの方が
高いため。機械検査も prefix の語彙は見ない（形だけを見る）。

## 番号の一意性は機械が守る

`bin/ci/test-issue-conventions`（`.github/workflows/test.yml` の `issue-conventions` job から実行）が
次を検査する:

- 番号の重複
- 命名が `NNN-<category>-<slug>.md` の形か
- `human` に `期限: YYYY-MM-DD`（行頭・半角コロン）が在るか
- `retro` のファイル名末尾に `-YYYY-MM-DD` が在るか
- **本文の相対リンクが解決するか**（`done/` へ移すと `../NNN` 形式が切れる。2026-09-08 に 2 回踏んだ）

**検査しないもの**: 本文の正しさ・重要度・カテゴリ語彙の妥当性。これらは人とレビューの責務。

### 衝突してしまったときの寄せ方

**参照の少ない側を空き番号へ寄せる**。tracked 参照（`git grep`）と commit message 参照
（`git log --grep`）を両方数え、**commit message は履歴なので直せない**ため、そちらから
参照されている側は動かさない。改名したファイルの冒頭には
「過去のメモの『旧番号』がこの話ならこの issue」と注記を残す。

実例: 2026-09-08 に `004` が 3 ファイル、`010` が 2 ファイルで衝突していたのを解消した
（`094` / `095` / `093` へ移動。いずれも冒頭に旧番号の注記がある）。

## `期限:` — 人が読む期限

本文冒頭のメタ行に `期限: YYYY-MM-DD` を書ける。

- **`human` は必須**（人間待ちの作業は放置すると価値が腐る）。他カテゴリは任意
- 書式は**行頭 `期限:` + 半角コロン + `YYYY-MM-DD`**
- 期限は「読んで確認する期限」であって「直す期限」ではない
- **既読の唯一の出典はファイルの位置**（`issues/` = 未読、`issues/done/` = 確認済み）。
  既読ヘッダー・チェックボックスは使わない（本文の書き換え忘れで嘘が残るため）

## `retro` — セッションの振り返り

Claude が**実質的な作業をやり切った時点**で `NNN-retro-<スラッグ>-YYYY-MM-DD.md` を自発的に起票する。
typo 修正・数行の chore・調査だけで終わったセッションは対象外（薄い retro を量産すると形骸化する）。

- 中身は「どこで踏んだか / 何が回りくどかったか / 次に効きそうな改善」。うまくいった話は書かない
- **各項目に切り出し先の提案を添える**（新規 issue / `~/dotfiles/_claude/rules/` への追記 / 却下）。
  切り出しの実行はユーザーの判断を待つ
- **done の条件は「本文の残課題が空になったこと」**（実装の有無では判定しない）
- ルールに落ちた項目は rules 側を正本とし、retro には要約を残さない（二重管理は乖離を生む）
- 却下した項目は消さずに「却下: 理由」を 1 行残す（同じ気づきが次の retro で再生産されるのを防ぐ）

## ディレクトリ構成

- `issues/*.md` — open な issue
- `issues/done/` — 完了した issue の移動先（**ファイル名は変えずに移動する**）
- `issues/pending/` — **凍結**した issue。着手条件・trigger を本文冒頭に書く。
  再開の主導権は**自分**にある（条件が揃ったと判断したら `issues/` へ戻す）
- `issues/waiting/` — **着手済みだが、こちらから起こせない事象を待っている** issue。
  pending との違いは**再開の主導権が誰にあるか**（再現待ち・観測待ち・外部イベント待ち）。
  本文冒頭に**待っているもの**と**それが来たとき何が分かるか**を書く

`pending/` と `waiting/` は**必要になった時点で作る**（空ディレクトリは git に乗らない）。

### 採用していないもの

- **`issues/next/`（着手の claim）** — 採用しない。claim 規律は「複数マシンが同じ issue 列を
  処理する」ための仕掛けで、このリポジトリではその運用をしていない。必要になったら
  `next/` を作ることが opt-in になる（規範は dotfiles の `_claude/rules/claim-issue-in-next-and-push.md`）
- **`issues/epic/<name>/`（group issue）** — 採用しない。件数がまだ 1 階層で扱える規模
- **glogx の issues viewer / SessionStart hook** — dotfiles 側の道具で、このリポジトリ用の
  配線はしていない。期限・未決着 retro の点検は人と `bin/ci/test-issue-conventions` が受け持つ

## 運用ルール

- 対応が完了したら `issues/done/` へ移動する
- **issue に関わる作業は、commit のたびに当該 issue の本文へ進捗・結果・残タスクを追記する**
  （chat の報告は流れる。issue 本文が唯一残る）
- issue の新規作成・大幅改訂は commit 前に codex レビューへ通す
  （dotfiles の `_claude/rules/issue-creation-codex-review.md`）
- **issue の記述を鵜呑みにしない。** 着手前に実コードと git 履歴で検証する
  （既に修正済み・false positive を弾く）。「〜は存在しない」のような**不在の主張は数え直す**
