# 111 (retro): issue 106 Commit 4（069 M2）の実装後の敵対レビュー 5 周と、codex での 081 / 108 / 094 / 003 の片付けの振り返り

起票日: 2026-10-12

経緯と数字は issue 106 の「Commit 4」節、`done/069`、`done/081`、`done/108`、094、003 にある。ここには、踏んだことと次に効く改善だけを書く。

## どこで踏んだか

1. **同じ不変条件が、周ごとに別の場所で破られた。** 「record を消す前に、Tree の barrier の receipt を完了してよいかを判定する」が、
   3 周目（final の受理で record が先に回収される）と 4 周目（catch が未精算の credit のまま record を消す）で続けて破られた。
   3 周目の修正で receipt の**判定**は 1 関数に寄せたが、record を**消す側**が 7 か所に散ったままで、catch の 1 か所は判定の関数を呼んだ後、
   判定が「まだ完了できない」と返しても record を消していた（判定の結果に回収が従っていなかった）。
   4 周目の修正で個別の record の回収を 1 関数に寄せ、回収の条件を満たさないなら消さない形にし、直接の removeValue を source の検査で禁じて、5 周目で収束した。
2. **テストが actor の再入を見落としていた（CI で発覚）。** 「credit の actor の中で hook を suspend させれば、その actor への refund も止まる」という前提のテストが、
   CI で落ちた（actor は await の間に別の呼び出しを受け付けるので、refund が先に済む順序がある）。最初の手元の検証では通っていたが、修正前の連続実行の 9 回目で同じ形に再現した。
3. **試験用の hook が、未設定でも実行順を変える形で production に入りかけた。** codex が credit の actor の claim と accept の間に
   `await token.runHook(...)`（nonisolated な async の呼び出し）を置いた。hook が無くても actor を離れる suspension point になり、claim と accept の間に割り込みを許す。
   既存の hook と同じ `await hook?(...)`（未設定なら呼ばない）に直した。
4. **CI で発覚したテストの失敗が 3 本あり、どれもテストの待ち方だった**（待つ合図と assert する事象が違う 2 本、件数の waiter が「条件の確認 → 件数の読み取り」の順で合図を取りこぼす 1 本）。
   形は issue 110 の 5 と既存ルール（`adversarial-review-own-safeguards.md` §5 ③ の「自作のテスト基盤も check-then-act を問う」）のとおりで、規則の欠落ではない。
5. **codex の長い run を `run_in_background` で起動し、Bash の background の時間の上限で止められた**（実装と検証は終わっていて、最後の計測だけ失った）。
   codex-drive の skill は 15 分を超える起動の detach を既に求めている（局所の手順の誤り。以後は nohup で detach した）。

## 次に効きそうな改善（一般形）

- A. 却下: 「台帳の判定を寄せたら書き換える側も全部 1 関数に寄せる」は広げすぎ（今回寄せたのは個別の record の回収だけで、登録・状態の更新・terminal の removeAll は別の経路のまま）。
  「その操作に届く入口を全部挙げて gate を通す」は既存ルール `adversarial-review-own-safeguards.md` §0-D にある。今回の手段（回収を 1 関数に寄せ、条件を満たさなければ消さない）は issue 106 に記録した
- B. 却下: 既存ルール `adversarial-review-own-safeguards.md` §5 ③ が、await のすき間で他のタスクが状態を変えうること・各順序をテストで固定すること・自作のテスト基盤への適用まで求めている。
  actor の再入はその範囲で、規則の欠落ではなく不履行（refund の直前に gate を置く直し方は issue 106 に記録した）
- C. **production に置く試験用の hook は、未設定のときに実行順を変えない形（optional chaining の呼び出し・同期の closure）にし、実装者への指示にもそう書く。**
  未設定でも suspension point や lock を作る形は、本番の interleaving を変える。
  - 切り出し先の提案: `~/.claude/skills/codex-drive/SKILL.md` の [R] の「test 専用の同期機構」の項へ追記する

## 局所的な事項（提案にしない）

- 4 は既存ルールで足りる（該当テストは直した。issue 106 に記録）
- 5 は codex-drive の既存の手順の誤り（detach を使う）
- codex が「container は同時に 1 台まで」を他人の container を数えて読み違えた 2 回目と、指示に無い CI の job を足した件は、issue 110 の C の追加の実例として書いた

## レビュー記録

- 2026-10-12: codex（sol、read-only）の反証レビューで 4 件（P2 が 3 件、P3 が 1 件）を受け、すべて採った: 4 周目の原因の説明（判定を呼んだ後に結果に従わず消していた）、
  A と B は既存ルール（§0-D、§5 ③）にあるので却下に変えた、「CI でだけ」を「CI で発覚」に直した。C と件数・周回・hook の経緯は反証されなかった
