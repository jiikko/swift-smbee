# 109 (retro): issue 103（path の区切りを Unicode scalar で判定する）の振り返り

起票日: 2026-10-09

## どこで踏んだか

1. **新しい E2E のテストクラスが、どの実行経路からも選ばれていなかった。**
   `bin/e2e/container-samba.sh` も `.github/workflows/e2e.yml` も、決まったクラスを `--filter` で選んで回す。
   codex が足した `SMBPathSeparatorE2ETests` は、配線するまで一度も走っていなかった（container-samba.sh は rc=0）。
   気づいたのは、出力に新しいテストの行が 1 行も無いことからだった。配線したのはローカルの container-samba.sh
   （smb311-signing-required の段）だけで、CI の e2e.yml には今も入っていない（push 前の `make smoke` で毎回走る）。
2. **build に組み込まれた lint が、変異検証の結果を「構文エラー」に変えた。**
   SwiftLint は SwiftPM の build tool plugin として `swift build` の中で走る。新しい custom rule が、Character 単位に戻した変異を
   build の段で止めた。そのため `mutate-verify` は 13 本中 12 本を rc=5（構文エラー）と判定した。
   lint の検知力の証拠にはなったが、lint に止められた 12 本については unit テストの検知力が見えなかった
   （lint の対象外の helper に当てた 1 本は build を通り、unit テストで red になった）。変異の行だけ `swiftlint:disable` で囲んで測り直した。
3. **raw packet を組む測定ハーネスが、構造体のオフセットを誤っていた（CREATE の NameOffset を 104 として読んだ）。**
   対照（通常の名前）まで STATUS_INVALID_PARAMETER になったことで気づいた。対照を置いていなければ、
   「Samba は区切り + 結合文字を拒否する」と誤って結論するところだった。

## 次に効きそうな改善（一般形）

- A. **環境で skip しうるテストを足したら、「テスト名が出た」ではなく、その実行経路で passed になり skip されていないことまで確かめる。**
  環境変数・profile が合わないと XCTSkip するテストは、テスト名・started・suite passed が出たまま何も検査しない
  （今回の Linux の unit 実行でも E2E クラスは skip で緑だった）。名指しの実行経路に足したかどうかの確認も、この判定で兼ねられる。
  - 切り出し先の提案: 既存ルール `verify-execution-not-just-exit-code.md` の表の「新規テスト」の行へ「skip を実行と数えない」を追記する
    （新規テストの実行一覧での確認・集約 target 経由の確認は既にあるので、差分はここだけ）。
    swift-smbee では CI の `bin/ci/require-xctest-passed` が既にこの判定をしている。E2E のクラス一覧と container-samba.sh / e2e.yml の filter の突き合わせは別 issue の候補
- B. **変異検証の build に静的検査（lint plugin・警告をエラーにする設定）が入っていると、その検査に止められた変異は
  テストまで届かず、テストの検知力は測れない。** 結果は「どの段階で止まったか」で帰属する（build の段で静的検査に止められた =
  静的検査の検知力、build を通ってテストで red = テストの検知力）。テストの検知力も要るなら、止められた変異だけ、その行で静的検査を外して測り直す。
  - 切り出し先の提案: 既存ルール `mutation-verify-new-tests.md` の手順 1.5（「その変異が実際にビルドできたことを確認する」）へ追記する
- C. **外部の挙動を測る自作のハーネスには、結果が既知の対照を同じ経路で 1 本混ぜる。** 対照が期待どおりでなければ、
  測定対象ではなくハーネスを疑う。
  - 切り出し先の提案: 既存ルール `verify-execution-not-just-exit-code.md` の「抽出・判定を書いたら、同じ経路を通る canary を先に置く」と
    同じ考え方なので、そこへ「外部の挙動の実測にも当てる」を 1 行足すか、既に含まれているとして却下する

## 局所的な事項（提案にしない）

- issue 103 の受け入れ条件の誤り（`a\\\u{0301}..` は受理が正しい）は issue 本文で訂正した
- DFS キャッシュの鍵の `/` と `\` の不一致（性能のみ）は issue 103 に記録した
