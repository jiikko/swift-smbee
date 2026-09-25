# 096 retro: issue 087 (E2E launcher の共通化) の振り返り

起票日: 2026-09-25

## 概要

issue 087 で launcher 2 本の同一実装を `test/e2e/launcher-common.sh` に寄せ、fake runtime の回帰テスト
`bin/ci/test-e2e-launchers` と CI の実行判定 `bin/ci/require-xctest-passed` を新設した。
変異検証と敵対レビュー 2 周で、**自分で書いたテストの偽の緑が 2 つ**見つかった。どちらも他の repo・
他の shell テストでも同じ形で起きるので、提案に引き上げる。

## どこで踏んだか

1. **`||` の中で呼ぶ関数の中の assert が効いていなかった。** fake `sleep` の中で間隔を assert したが、
   それを呼ぶ helper が `helper || status=$?` の形で呼ばれていたため、関数の中では errexit も ERR trap も
   働かず、assert の失敗は誰にも拾われなかった。`sleep 1` → `sleep 2` の変異が緑のままで、
   敵対レビューが見つけた。
2. **エラーメッセージの grep がロケールで空振りした。** 「guard で止まったのか、後で `set -u` が落としたのか」を
   区別するために stderr の `unbound variable` を grep したが、この Mac の bash は日本語で出すので一致せず、
   変異が緑のままだった。CI (ubuntu, C.UTF-8) なら通るので、**手元でだけ偽の緑**になる形。
   最終的には文言をやめて「guard の後に runtime が 1 回も呼ばれていない」(副作用の記録) で判定した。
3. 前の guard が消えても後ろの `set -u` が同じ rc で落とすため、「rc とメッセージと起動しないこと」の
   assert だけでは guard の有無を区別できなかった (2 の出発点)。

## 次に効きそうな改善 (提案)

- **A. shell テストで「条件文脈の中の assert」を禁じる**: `if` / `||` / `&&` / `!` の中から呼ばれる関数の中では
  `set -e` も ERR trap も働かない。fake / callback の中では値を**記録するだけ**にして、比較は条件文脈の外で行う。
  他の repo の shell テストでも同じ形で起きる。
  切り出し先: `~/.claude/rules/mutation-verify-new-tests.md` の「assert と期待値」節へ追記
  (既存の「前提の assert が停止しない形」の shell 版なので、新規ルールにはしない)。
- **B. 外部コマンドのエラーメッセージを判定に使わない。副作用で判定する**: 文言はロケールや版で変わり、
  変わると検査は緑のまま空振りする。何が起きたか (呼び出しの記録・ファイル・exit code) で判定し、
  文言しか手段が無いなら `LC_ALL=C` を固定したうえで、その理由をコメントに残す。
  切り出し先: `~/.claude/rules/mutation-verify-new-tests.md` の「観測の設計」節へ追記。

**決着 (2026-09-25)**: ユーザー指示で A・B とも `~/dotfiles/_claude/rules/mutation-verify-new-tests.md` に追記した
(A は「assert と期待値」節、B は「観測の設計」節。由来は `_claude/rules-rationale/mutation-verify-new-tests.md`)。
dotfiles の commit「rules(mutation-verify): 条件文脈の中の assert とエラー文言の grep を「守っていないテスト」に足す」。

## 却下

- 却下: 「後ろの guard が前の guard の変異を隠す」を新しい提案にする — `mutation-verify-new-tests.md` の
  「先に効く別の防御が影になって、狙った分岐に到達していないか」で既にカバーされている。今回もその観点で見つけた。

## 残課題

- [x] 提案 A・B を rule に追記する — 追記済み (上記)。残課題なし
