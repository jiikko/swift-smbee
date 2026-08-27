# 082 refactor: `DCERPC.responseHasLastFragment` が呼び出し元を失ったまま残っている (issue 032 で塞いだ弱い判定の再導入口)

状態: **done** (2026-08-27)
起票: 2026-08-26
種別: `refactor` (P3。現時点で呼ばれていないため実害は無いが、放置すると 032 の退行口になる)
起源: /audit の dead-code / dependency 監査

## 問題

`DCERPC.responseHasLastFragment(_:)` (`Sources/SMBee/DCERPC.swift`) は
**リポジトリ内のどこからも呼ばれていない**。

```
$ grep -rn "responseHasLastFragment" Sources Tests docs bin test
Sources/SMBee/DCERPC.swift:90:    static func responseHasLastFragment(_ bytes: [UInt8]) throws -> Bool {
```

ヒットは定義 1 件のみ (`issues/done/032-*.md` 内にも文字列が出るが、そちらは
「修正前」として引用されたコードであり実コードではない)。

呼び出し元が消えた経緯は commit `0fb16dc` ("fix: harden download, RPC, timeout, and
replacement paths"、2026-07-11。issue 032 の対応) で確定できる:

```
$ git show 0fb16dc -- Sources/SMBee/SMBClient.swift
-        while !(try DCERPC.responseHasLastFragment(output)) {
+        while !(try DCERPC.validateResponseFragments(output, expectedCallId: expectedCallId)) {
```

より厳密な `validateResponseFragments` に置き換えた際に、旧ヘルパー本体の削除だけが
漏れた。

## なぜ「掃除」以上の話か

残っているのは **issue 032 で塞いだ脆弱性そのものを持つ旧実装**である。両者の差:

| | `responseHasLastFragment` (孤児) | `validateResponseFragments` (現行) |
|---|---|---|
| 全体サイズ上限 | **無し** | `maxBytes: Int = 16 * 1024 * 1024` |
| call id の相関確認 | **無し** | `expectedCallId` で照合 |
| フラグメント数の追跡 | 無し | あり |

名前は `responseHasLastFragment` の方が素直なので、**将来 DCE/RPC を使う経路
(SRVSVC の share 列挙拡張、LSARPC の追加要求など) を足す人が名前で選んで呼ぶと、
032 で塞いだ「無制限フラグメントストリーム + 弱い相関」が静かに復活する**。
compile error にも lint error にもならない。

## 発火条件

- **現時点では発火しない** (呼び出し元ゼロ)。silent に壊れている状態ではない
- 発火するのは「新しい DCE/RPC 応答処理を書く人が `validateResponseFragments` ではなく
  こちらを呼んだとき」。そのとき悪意ある/壊れたサーバが last-fragment を立てない応答を
  返し続けると、上限チェックが無いため `output` が無制限に伸びる (032 の再現)
- 上記は**コード上の到達可能性からの推論であり、実際にそう書かれた実例は無い**
  (= 未確認リスク。断定ではない)

## 対応方針

1. `DCERPC.responseHasLastFragment(_:)` を削除する (`internal` なので外部利用者への影響なし。
   `enum DCERPC` 自体に `public` 修飾は無い)
2. 削除後に `swift build && swift test` で参照漏れが無いことを確認する
   (production の wire 挙動は変えないので E2E smoke は不要 — CLAUDE.md「smoke が要る変更 /
   要らない変更」の「要らない」側)
3. 同型の取り残しが他にもないか確認する。今回の監査では Sources の private/fileprivate 422 件・
   internal 関数 310 件・型 100 件を「定義以外の参照ゼロ」で機械走査して他に該当は無かったが、
   **これは一度きりの走査であり、継続的な検出は現状の配線では効いていない**。
   SwiftLint には `unused_declaration` / `unused_import` が**存在する**が、いずれも
   `analyzer: yes` の analyzer rule で `swiftlint analyze` (コンパイラログ必須) でしか走らず、
   本 repo の `.swiftlint.yml` は `analyzer_rules: []`、実行経路は SwiftPM build tool plugin
   (= `swiftlint lint`) のみ。継続検出の導入是非は issue 083 に分ける

## 受け入れ条件

- [ ] `DCERPC.responseHasLastFragment` が削除されている
- [ ] `swift build && swift test` が green
- [ ] 削除の commit message に「032 の弱い判定の再導入口を閉じる」意図が残っている

## 関連

- `issues/done/032-robustness-dcerpc-fragment-stream-is-unbounded-and-weakly-correlated.md`
  — 現行 `validateResponseFragments` を入れた issue。本 issue はその後片付け
- `Sources/SMBee/SMBClient.swift` — `validateResponseFragments` の唯一の呼び出し元 (pipe transceive ループ)
- commit `0fb16dc` — 呼び出し元を差し替えた commit (削除漏れの発生点)

## レビュー記録

- 2026-08-26: codex 敵対的レビューは **未実施**。codex が usage limit
  (reset 22:46) に達して 4 セッションとも最終回答前に停止したため。
  ⚠️ 本 issue の主張 (grep 1 件・commit `0fb16dc` の差し替え・両実装の防御機構の差) は
  main agent が実コマンド出力で裏取り済みだが、**反証レビューは通していない**

## 完了記録 (2026-08-27)

- `DCERPC.responseHasLastFragment(_:)` を削除。`swift build --build-tests` (macOS / Linux swift:6.2
  container) と `swift test --skip SMBeeE2ETests` (441 tests, 0 failures) が green
- 継続検出は issue 083 の `bin/ci/lint-analyze` (`swiftlint analyze` の `unused_declaration`) が担う。
  同ルールで本関数のほかに未使用宣言 6 件・未使用 import 13 件が同時に見つかり、同じ commit で掃除した
- 変異検証: 本関数を戻して `bin/ci/lint-analyze` と同じ analyze を回すと
  `DCERPC.swift:90:17: error: Unused Declaration Violation` で rc=1 (red) になることを確認
