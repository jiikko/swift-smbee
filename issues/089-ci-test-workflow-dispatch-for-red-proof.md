# 089 ci: test.yml に workflow_dispatch を足して「赤の実証」に意図的な赤 commit を使わないようにする

- 種別: ci
- 起票: 2026-09-08 (retro [`084`](084-retro-audit-analyzer-rules-2026-08-27.md) 項目 5 の切り出し)
- 状態: **open**
- 関連: `.github/workflows/test.yml` / `.github/workflows/wire-stress-e2e.yml` (`workflow_dispatch` の先例) /
  [`done/083`](done/083-ci-swiftlint-analyzer-unused-declaration.md)

## 問題

新設した検査が **CI で本当に落ちるか**を実証するには、その検査が守っている修正を revert して
CI を赤にして見せる必要がある (グローバルルール `verify-execution-not-just-exit-code.md` の
「新設した検査が CI で走っているか、同じ commit で確認する」)。

2026-08-27 の issue 083 (swiftlint analyzer rules) では、この実証を
**master に意図的な赤 commit を積む**形で行った (ユーザー選択)。履歴に
`0cfccc9 test(ci): [意図的に赤] issue 082 の削除を一時 revert して swiftlint analyze の red を実証する` が残る。

赤 commit を master に積むと:

- `git bisect` / `git log` を読む人が「本当に壊れていた時期」と区別できない。
- 直後の revert commit とペアで読まないと意味が取れない。
- 連続 push になるため、`cancel-in-progress` で前の run が消える
  (CLAUDE.md「push後のCI確認」の注記の原因でもある)。

## 対応案

`.github/workflows/test.yml` に `workflow_dispatch` を足す (`ref` を指定して任意の commit / branch で
起動できるようにする)。`wire-stress-e2e.yml:5-6` が既に `workflow_dispatch` を持っているので同形でよい。

これで「赤の実証」は次の形になる:

1. 実証用の変更をローカルの一時ブランチに commit して push (master には積まない)。
2. `gh workflow run test.yml --ref <その branch>` で起動し、赤を確認して run URL を issue に残す。
3. ブランチを削除する。

## 完了条件

- `test.yml` に `workflow_dispatch` があり、**master 以外の ref を指定して起動できることを 1 回実際に確認**する
  (起動して run URL を残す。設定を足しただけでは「起動できる」の証拠にならない)。
- 「赤の実証」の手順を CLAUDE.md か `docs/testing.md` のどちらかに 1 行足す
  (道具を足したら入口も更新する)。

## スコープ外

- 他の workflow (`e2e.yml` / `performance.yml`) への `workflow_dispatch` 追加。
  必要になった時点で同じ形を足す。
