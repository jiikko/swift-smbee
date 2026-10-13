# 107 (retro): issue 010 M3 の入れ直しと issue 106 の Commit 1〜3

起票日: 2026-10-05

対象のセッション（2026-10-02〜10-05）の作業:
- issue 010 M3 の Linux の性能退行の調査と、M3 の入れ直し
- issue 106（未送信 request 退役 primitive）の設計の承認、Commit 1・2 の着地、Commit 3 の revert

経緯と数字は issue 010 と 106 の本文にある。ここには、踏んだことと次に効く改善だけを書く。

## 踏んだこと / 回りくどかったこと

1. **手元の計測が CI の性能 gate を予測できなかった（向きも逆だった）。**
   - M3: 手元の Linux container（arm64、Apple container）では −30〜−37%。fixture を変えた run や、host の負荷で master も動いた run が混ざるので、きれいな比較ではない。
     CI の x86 では −45.8%（issue 010）。
   - Commit 2: arm64 の container では −10.6%、CI の x86 では −0.9%。
   - Commit 3: macOS では −0.75%、CI の x86 では −22% / user CPU +46%。
   - 毎回「手元では上限の内側」と見て push し、2 回 revert した。
2. **benchmark が、変更した経路を通っていなかった（gate の偽の緑）。**
   Commit 3 の新しい送信経路は、session が認証後の状態のときだけ使われる。benchmark は認証を通らずに session を直接作っていた。
   define を付けたときだけ新しい経路を測る形で、CI の gate は define なしで走る。実装報告を読むまで気づかなかった。
3. **M3 の入れ直しが、CI の stress を運で通っていた。**
   - CI の Test の「Cancel and teardown bounded stress」step（`.github/workflows/test.yml`）は、`swift test --skip SMBeeE2ETests --filter 'KeepAlive|Cancel'` を 20 回まわしている。
   - 手元で同じ command を 20 回まわすと、M3 の入れ直しの後（a0fac80 / c4d354e）は 5 回落ちた。M3 の入れ直しの前（76d70ed）は 0 回だった（issue 010）。
   - 次の commit（Commit 2）の CI で初めて表に出て、Commit 2 の退行と誤認しかけた。
4. **敵対レビューの周回が収束しなかった。**
   Commit 2 は 2 周続けて P2 が 3 件ずつ、それぞれ別の不変条件で出た。
   範囲（設計 §5 の約束と master からの退行だけを止める。既存の穴は記録）を issue に固定してから収束した。
   範囲内の P2 は 3 → 2 → 1 → 0 件（issue 106 の Commit 2 節）。
5. **codex への指示に書かなかった規約を、codex が破った。**
   - Docker / colima を入れて回し、後で uninstall した（`~/.docker` が残った）。
   - `/tmp` に約 8 GB の build cache を残した。
   - repo の CLAUDE.md には書いてあるが、prompt に無いと codex は読まない。
6. **自分で後から足した修正が、CI の strict SwiftLint を落とした。** 手元では `make lint-analyze`（analyzer rules だけ）しか回していなかった。
7. **背景の待ちが 2 時間の上限で何度も切れた**（codex の実装の run は 3〜5 時間かかった）。
   監視の grep が、codex のログに出たテストコードの文字列（`at capacity` 等）に当たって、偽の rate limit を報告した。

## 次に効きそうな改善（一般形）

- **(1)** 性能が gate になっている変更は、push の前に gate と同じ環境（OS・CPU アーキテクチャ）で測る手段を用意してから着手する。
  手元の別の環境の数字は、向きも含めて予測にならない。
  - 切り出し先: `~/dotfiles/_claude/rules/perf-claims-need-measurement.md` の「測った経路がユーザーの実経路と同じかを、数字を書く前に確かめる」に加える。
    - 既存の文は「対象の OS」で律速が変わる変更には触れている。CPU アーキテクチャ（arm64 と x86）の差と、「push 前に CI の gate と同じ環境で測る」は書かれていない。
    - 足すのはこの 2 点だけ。
- **(2)** 新しい経路を足す変更では、gate の計測がその経路を実際に通ることを、計数（経路の起動回数など）か assert で確かめる。
  - 切り出し先: `~/dotfiles/_claude/rules/verify-execution-not-just-exit-code.md` の「実行された証拠」の表に、「性能 gate」の行を足す。
- **(3)** 並行性・後始末の経路を変えた commit は、CI の stress の step と同じ command を、push の前に手元で同じ回数まわす。
  - 切り出し先: この repo の CLAUDE.md（「smoke が要る変更」の節の近く）。
    - CLAUDE.md は今、CI の stress の step に触れていない。command の正本は `.github/workflows/test.yml` なので、そこを指す 1 行にする（command は写さない）。
- (4)〜(6) は既存の rule と memory で足りる。
  - (4) は `adversarial-review-own-safeguards.md` §8 の stopping rule そのもの。今回は守るのが遅れた。
  - (5) と (6) は今回 memory に追記した（codex の prompt に Docker 禁止と `./tmp`、push 前の strict lint）。
- (7) は局所の運用で、新しい rule にはしない。
  - codex の run の待ちは上限を長くとる。
  - ログの grep は、道具自身の出力の接頭辞（codex なら `^ERROR:`）に固定する。

## 残課題

- [x] (1) を rule に追記するか → 採用（110 A とまとめ、修正して `perf-claims-need-measurement.md` へ）
- [x] (2) を rule に追記するか → 却下（既存で足りる）
- [x] (3) を CLAUDE.md に追記するか → 却下（既存で足りる・局所）

## 決着（2026-10-13）

codex（sol-high）に、4 本の retro の提案 11 個を反証の立場で審査させ、10 項目にまとめて 6 採用・4 却下とした（ユーザーの指示: 有意義なら適用）。採用分は dotfiles の commit `docs(rules): swift-smbee の retro 107 / 109 / 110 / 111 の提案のうち、codex の審査で既存に無いと確かめた 6 点を既存ルールへ追記する`（ace43ba1）。

- (1) 採用（修正）: `perf-claims-need-measurement.md` に「性能 gate の対象経路を変えるときにも発動」「gate と同じ OS・CPU アーキテクチャで候補を比べる手段を着手前に確保し、本流への採用前に比べる」を追記。
  「別の環境の数字は向きも含めて予測にならない」は掲載値と合わない（M3・Commit 2・Commit 3 とも throughput は同じ向きに低下していた）ので、「退行の大きさや gate の合否を予測しない」に直した。
  「push の前に」は、比較の手段自体が候補の branch への push を要するので「本流への採用前に」に直した
- (2) 却下: `perf-claims-need-measurement.md` の「測った経路がユーザーの実経路と同じかを、数字を書く前に確かめる」、`verify-execution-not-just-exit-code.md` の「最適化が近道を足すなら、測る操作がその近道を通るかを数え」、
  敵対レビューのチェックリスト §1.5（gate が名指しする退行を当てて red を確かめる）で足りる
- (3) 却下: `verify-execution-not-just-exit-code.md` の「最後の編集の後に、変更したファイルを実際に検査する gate (CI と同じ lint・テスト) を回す」で足りる（反復を含む検査は反復も検査の一部）。
  repo の CLAUDE.md に CI の固有の step を書くのは局所で、20 回が他の並行性の変更にも足りる根拠も無い
