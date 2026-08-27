# 084 retro: /audit 全滅 → dead-code 1 件から analyzer rules 導入まで (2026-08-26〜27)

状態: **open**
起票: 2026-08-27
種別: `retro`

## 何をやったか

- /audit を 18 タイプ・9 エージェント並行で起動 → Claude session limit で 8 体途中死。
  codex に 4 本再投入 → codex usage limit で 4 本とも最終回答前に停止。確定した成果は
  dead-code 監査の 1 件 (`DCERPC.responseHasLastFragment`) だけ (issue 082)
- その 1 件から「なぜ 6 週間残ったか」を切り出した issue 083 を実装: `swiftlint analyze` の
  analyzer rules を `bin/ci/lint-analyze` で配線、baseline 整備で未使用宣言 7 件・import 14 件を削除、
  CI で red 実証まで完了 (done/082, done/083)

## 反省と気づき

1. **監査の投げ方が予算を踏み抜いた**。18 タイプ × 9 体並行 + codex 4 本同時で、両方の limit に
   ほぼ同時に到達し、結論に届いたのは 1 体。トークンは 30 万以上使って発見 1 件。
   → 切り出し先: `_claude/rules/` 候補「監査エージェントは 2〜3 体ずつ直列に回し、1 波が完走してから
   次を投げる」。または audit skill 側に上限を書く。**判断はユーザーに委ねる**
2. **エージェントの「他に dead code は無い」は誤りだった**。sonnet の全数走査は「定義以外の参照ゼロ」
   の grep で、overload (`withSession(credentialProvider:)` など名前が同じで signature 違い) を
   見落とした。`swiftlint analyze` は 9 件を追加で拾った。
   → 切り出し先: `subagent-model-tiering.md` の検閲観点に「grep ベースの『未使用ゼロ』は
   overload を数えられない。ツール (analyzer / compiler) の結果で裏取りする」を 1 行足す案
3. **書きかけの issue に未検証の断定を 2 回書いた** (「`unused_declaration` は SwiftLint に存在しない」/
   「削ると Linux build が落ちる」)。どちらも実測前に commit しかけて、直前の実測で訂正した。
   → 却下 (既存ルール「主張は証拠ではない」で足りる。今回は commit 前に自分で捕まえた)
4. **push ゲート (smoke マーカー) と CI の `cancel-in-progress` の相互作用**を 2 回踏んだ:
   docs だけの commit を push すると直前の run が取り消され、`verify-agent-push` の対象が消える。
   → 切り出し先: CLAUDE.md「push 後の CI 確認」に「連続 push するなら verify は tip に対して
   1 回」を 1 行足す案
5. **red 実証を master の意図的な赤 commit で行った** (ユーザー選択)。履歴に
   `0cfccc9 [意図的に赤]` が残る。次回同種の実証が要るときの選択肢として、`workflow_dispatch` を
   test.yml に足しておけばブランチも赤 commit も不要になる。
   → 切り出し先: 新規 issue 候補「test.yml に workflow_dispatch (ref 指定) を足す」。要否はユーザー判断

## 残課題

- [ ] 上記 1 / 2 / 4 / 5 の切り出し要否の判断 (ユーザー)
