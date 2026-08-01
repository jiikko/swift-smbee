# 079 chore: smoke marker に監査証跡がない（ログは latest 1 本のみ・marker は空 touch）

- 種別: chore / dev tooling / auditability
- 重要度: low
- 起票: 2026-08-01（issue 068/073/075 の連続 wire 変更作業中のぼやきから。当初の「最後の smoke
  しか marker に残らない」は誤りで、実装確認の上で以下に訂正済み）
- 状態: done（同日対応。対応方針の節に codex 反証レビューの訂正内容を記録）
- 関連: `bin/e2e/smoke-all`（marker 生成） / `bin/hooks/pre-push`（marker 消費） /
  `Makefile`（`make smoke` が `tmp/e2e-smoke-latest.log` へ tee）

## 事実（2026-08-01 実装確認）

- marker `tmp/e2e-verified-tree-<subtree hash>` は tree ごとに一意な filename で `touch` され、
  **蓄積される**（上書きされない。ローカルに 10 件以上残存を確認）。pre-push gate はこれで機能する。
- ただし marker は**空ファイル**で、いつ・どの commit で・どの profile 構成で smoke が走ったかの
  メタデータを持たない（mtime のみ）。
- 完全ログは `tmp/e2e-smoke-latest.log` の **1 本だけ**が毎回上書きされる。短時間に wire 変更
  commit を複数積んで smoke を回すと、過去 run の「実際に何が走って何が green だったか」の証跡が
  ローカルに残らない（marker の存在だけが残る）。

## 問題

wire 変更 commit が連続する作業（例: 2026-08-01 の issue 068 → 073 → 075）では、途中 commit の
smoke 実績を後から監査する材料が marker の存在と mtime しかない。「この tree の smoke は
どの profile を通ったか」を確認するには当時の会話ログ等の外部記録に頼ることになる。

## 対応方針（codex 反証レビュー 2026-08-01 で訂正済み）

反証レビューの指摘を反映した最終形:

1. marker はメタデータ入り（verified_at / head_commit / sources_tree / profiles）にする。
   pre-push は `-e` 存在チェックのみで本文を見ないので互換（反証できず確認済み）。
2. **marker は刈り込まない**（当初案から変更）: 直近 N 件で marker を消すと、smoke 済みの
   古い tree を再 push するとき再実行が必要になり、push gate の実質挙動が変わる（指摘 P2）。
   刈り込むのは容量を食う tree 別ログのみ。
3. tree 別ログ（`tmp/e2e-smoke-tree-<subtree hash>.log`）は smoke-agent が成功後に copy し、
   直近 N 件（SMBEE_SMOKE_RETAIN、既定 10）だけ保持。刈り込みは glob 不一致でも
   `set -o pipefail` を殺さない形にする（指摘 P1: `find -exec ls -t {} +` を使う）。
4. tree hash は smoke-all の開始時に固定し、終了時に「subtree 不変 + clean」を再検証してから
   marker を書く（指摘 P2: 実行中の commit で新旧混在の実行結果を証明しない）。
   smoke-agent のログ copy は smoke-all の出力行から tree を読む（再計算ずれ防止）。
5. 意味論の明確化（指摘 P3）: これは「**tree ごとの最新成功**」の監査であり、run/commit ごとの
   全履歴ではない。同一 tree の再実行・docs-only commit は同じ marker/log を上書きする（仕様）。
   `make smoke-verbose`（smoke-all 直叩き）は marker のみでログ copy なし（仕様）。

## 完了条件

- [x] marker に timestamp / commit / profile 一覧が記録される（pre-push gate は従来どおり動く）
- [x] tree 別ログが保存され、ログのみ直近 N 件で刈り込まれる（0 件でも pipeline が落ちない）
- [x] marker は刈り込まない（push gate 挙動を変えない）
- [x] tree の開始時固定 + 終了時不変検証
- [x] `make smoke` の表示・既存の `tmp/e2e-smoke-latest.log` 互換を維持
