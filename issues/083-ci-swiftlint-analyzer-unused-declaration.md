# 083 ci: 未使用 declaration / import の継続検出が無い (`swiftlint analyze` の analyzer rules 未配線)

状態: **open**
起票: 2026-08-26
種別: `ci` (P3。今回見つかった取り残しは 1 件で実害も無いため、費用対効果を測ってから判断する)
起源: /audit の dead-code / dependency 監査。issue 082 の 3 番から分離

## 問題

issue 082 の `DCERPC.responseHasLastFragment` は、呼び出し元の差し替え (commit `0fb16dc`) から
**約 6 週間、誰も気づかないまま残っていた**。現状の CI/lint 配線ではこの種の取り残しを
機械的に検出できないため。

SwiftLint 自体には対応するルールが**存在する** (バイナリ
`.build/artifacts/swiftlintplugins/.../swiftlint rules` で実測):

```
| identifier          | opt-in | correctable | enabled in your config | kind | analyzer | uses sourcekit |
| unused_declaration  | yes    | no          | no                     | lint | yes      | yes            |
| unused_import       | yes    | yes         | no                     | lint | yes      | yes            |
```

効いていない理由は 2 つとも配線側:

1. **`analyzer: yes`** = `swiftlint lint` では走らない。`swiftlint analyze --compiler-log-path`
   (ビルドのコンパイラログが必要) でしか実行されない
2. 本 repo の `.swiftlint.yml` は `analyzer_rules: []`、実行経路は SwiftPM build tool plugin
   (`SwiftLintBuildToolPlugin` = `swiftlint lint`) のみ。`enabled in your config` も `no`

## 発火条件

- 「関数・型・import を置き換えたが旧実装を消し忘れる」変更を入れたとき、**CI は緑のまま通る**
- 実例は issue 082 (1 件)。今回の一度きりの全数走査では他に該当が無かったので、
  **頻度は「6 週間で 1 件」より高いという証拠は無い**。導入判断はこの前提で行うこと

## 対応方針 (案。まずコストを測ってから採否を決める)

1. `swiftlint analyze` を回すのに必要な手順を実測する
   (`swift build` のコンパイラログ取得 → `swiftlint analyze --compiler-log-path`)。
   **所要時間を測る**。analyzer rules は sourcekit を使うため lint より大幅に遅い
2. 許容できる時間なら CI に独立 job として足す (毎 PR ではなく push / nightly でもよい)。
   GitHub Actions の runner 選択は umbrella の `.claude/rules/gha-runner.md` に従う
   (本 repo は Linux runner が基本。macOS runner は public repo でのみ無料)
3. `analyzer_rules: [unused_declaration, unused_import]` を `.swiftlint.yml` に足す
4. **導入したら必ず「issue 082 の削除を revert して CI が赤くなる」ことを確認する**
   (手元ではなく CI で。走っていない検査を「入れた」と report しないため)
5. コストが見合わなければ**入れない**と決めて、その理由を `.swiftlint.yml` の
   `analyzer_rules: []` の隣にコメントで残す (次の監査が同じ提案を再生成しないように)

## 受け入れ条件

- [ ] `swiftlint analyze` の所要時間が実測されている
- [ ] 採用する場合: CI で実行され、issue 082 の削除を revert すると **CI が赤くなる**ことを確認済み
- [ ] 不採用の場合: 理由が `.swiftlint.yml` にコメントとして残っている

## 関連

- `issues/082-refactor-dcerpc-orphaned-weak-fragment-predicate.md` — 本 issue の発生源
- `issues/064-ci-swiftlint-strict-no-warnings.md` — SwiftLint の CI 強度に関する既存 issue。
  **重複ではない** (064 は既存ルールの warning 0 化、本 issue は未配線の analyzer rules 追加)
- umbrella `.claude/rules/swiftlint-plugin.md` — SwiftLint は build tool plugin として組み込む方針
  (本 issue の analyze job はその補完であり、plugin の置き換えではない)

## レビュー記録

- 2026-08-26: codex 敵対的レビューは **未実施** (codex usage limit、reset 22:46)。
  ルールの実在・`analyzer: yes`・`analyzer_rules: []` は main agent が実バイナリと
  設定ファイルで裏取り済み。**費用対効果の見積もりは未検証**

## 実測と決定 (2026-08-27)

- **所要時間 (手元 Apple silicon)**: クリーン `swift build -v --build-tests` 34s + `swiftlint analyze` 135s。
  採用する (CI は独立 job `swiftlint-analyze`、macos-26、timeout 30 min)
- **検出力**: 082 の関数を含む unused_declaration 10 件・unused_import 17 件を報告。内訳:
  - 未使用宣言 7 件は本物 (082 の関数 / `withSession(credentialProvider:)` overload /
    `write(treeId:fileId:nextChunk:)` overload / `SMBByteReader.remaining` / `SMB2Read.bufferOffset` /
    `remoteRecursiveBatchGlobEntries(endpoint:)` / テスト側 2 件) → 削除
  - 偽陽性 2 件 (`@main` の `SMBCLIMain.main()`、`Encodable` の `BatchSummaryOutput.ok` = JSON 契約)
    → 理由付き `swiftlint:disable:next`
  - unused_import: `import Foundation` 13 件 + `Darwin`/`Glibc` ブロック 1 件は本物 (削除後に Linux
    swift:6.2 container で `swift build --build-tests` green)。`import Crypto` 3 件は macOS で
    CryptoKit に解決されるだけの偽陽性 → `always_keep_imports: [Crypto]`
- **配線**: `bin/ci/lint-analyze` (クリーン scratch build → module 名ガード → `analyze --strict`)、
  `make lint-analyze`、`test.yml` の `swiftlint-analyze` job、CLAUDE.md に入口を追記
- **安全機構の異常系**: 空ログでガードが exit 1 / no-op 増分ビルドは swiftc 行 0 件 (= クリーン
  build 必須の根拠) / 変異 (082 の関数 + `import Foundation` を戻す) で 2 violations, rc=1
- **残課題**: CI 上で「082 の削除を revert すると `swiftlint-analyze` job が赤くなる」の実証
  (受け入れ条件 2 つ目)。手元の red 確認は済み
