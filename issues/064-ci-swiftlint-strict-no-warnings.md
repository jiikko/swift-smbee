# 064: CI で SwiftLint を strict 実行し警告ゼロを担保する

- 起票: 2026-07-23
- 種別: `ci`
- 状態: open

## 背景 / 問題

SwiftLint は `SwiftLintBuildToolPlugin` として各ターゲットに組み込まれており、`swift build` /
`swift test` の一部として走る (test.yml:41 のコメント参照)。しかし plugin が出す violation は
**severity が warning のものは CI job を落とさない**。このため:

- 構造ルール (function_parameter_count / cyclomatic_complexity / function_body_length /
  type_body_length / large_tuple / file_length / trailing_comma / blanket_disable_command 等) の
  warning が **長期間放置**されていた。
- swift-smbee は他リポジトリ (例: obaket) から **SPM ソース依存**として参照されるため、consumer 側が
  ビルドすると swift-smbee の plugin も発火し、**consumer のビルドログに swift-smbee 由来の warning が
  大量に流入**していた (2026-07-23 に obaket CI ログで顕在化 → 一括整理した)。

2026-07-23 に `.swiftlint.yml` で codec に本質的な構造ルールを無効化 + 残る trailing_comma /
blanket_disable をコード側で安全修正し、現時点で `swift build` 由来の swift-smbee 警告は 0 になった。
本 issue は **この lint-clean 状態を CI で恒久的に守る** ことが目的。

## ゴール

- swift-smbee の CI に「**SwiftLint violation が 1 件でもあれば FAIL する**」job を追加する
  (warning を含め strict 扱い)。これにより:
  - PR に lint 違反が入ったら merge 前に落ちる。
  - lint-clean が維持され、consumer (obaket 等) のビルドログに warning が再流入しない。

## 対応方針 (案)

1. **専用 lint job を GitHub Actions に追加 (推奨)**
   - `.github/workflows/lint.yml` を新設し、SwiftLint を `--strict` 相当 (warning も error 扱い) で実行。
   - **Linux runner** で回す (SDK 非依存の lint は Linux で十分・高速。my-products の gha-runner 方針)。
   - 可能なら `jiikko/shared-workflows` の `.github/workflows/swiftlint.yml` を再利用する
     (バージョン固定・共通化)。strict オプションの有無を確認し、無ければ薄い job を自前で書く。
   - **注意 (swiftlint-plugin 方針)**: `brew install swiftlint` は使わない。plugin が正本であり、
     この CI job はその **補完** (PR で macOS runner を回さず strict 結果を返す) と位置づける。
     SwiftLint バージョンは plugin (`SwiftLintPlugins` `from: 0.63.0`) と揃える。

2. **代替: plugin を CI で strict 化**
   - build-tool plugin は `--strict` を素直に受け取れないため、環境変数 / config で strict を効かせる
     方法を調査する必要がある。1 案より実装が重いので、まず 1 案を優先。

## 受け入れ条件

- lint 違反 (warning 含む) を 1 件入れた PR で CI が **FAIL** する。
- 現状の master (lint-clean) で CI が **PASS** する。
- push / PR の両方で走る。
- SwiftLint バージョンが plugin (`.swiftlint.yml` を使う plugin) と一致し、ローカル `swift build` と
  CI で同じ結果になる (lint 結果の乖離が起きない)。

## 関連

- `.swiftlint.yml` (2026-07-23 に codec 向け構造ルールを無効化した設定が正本)
- `.github/workflows/test.yml` (SwiftLint plugin が build 時に走る既存経路)
- my-products `.claude/rules/gha-runner.md` (lint は Linux runner)
- my-products `.claude/rules/swiftlint-plugin.md` (plugin が正本 / brew 禁止 / shared-workflows は補完)
- obaket 側 issue 429 (consumer に warning が流入していた件の対処)
