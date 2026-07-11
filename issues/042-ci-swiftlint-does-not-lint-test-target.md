# 042 CI: SwiftLintがtest targetを実際にはlintしていない

- 種別: CI / lint coverage
- 重要度: medium-high
- 状態: open
- 関連: `Package.swift`, `.swiftlint.yml`, `.github/workflows/test.yml`

## 問題

`.swiftlint.yml`の`included`には`Tests`が入っているが、`SwiftLintBuildToolPlugin`が設定されているのは
`SMBee`と`smbcli` targetだけで、`SMBeeTests` test targetにはpluginがない。

CIは`swift build`がlintも実行すると説明しているが、このbuildで確実にlintされるのはpluginを持つ
production targetだけである。test sourceのcustom rule違反や通常rule違反はPR gateにならない。

手元でSwiftLint binaryをrepository全体へ直接実行すると、Tests内にもerror severityの既存違反が複数あり、
単純にtest targetへpluginを付けるだけではCIが即座にredになる状態でもある。

## 影響

- test helper内のtrapping cast、fire-and-forget cleanup、unsafe concurrency patternが見逃される。
- `.swiftlint.yml`の`included: Tests`が実際のCI保証より強く見え、誤解を招く。
- build target構成変更でlint対象が静かに変わっても検出できない。

## 対応方針

1. 独立した`lint` jobでSwiftLint binary/pluginをrepository全体へ明示実行する。
2. 先に既存test violationを修正するか、理由付きの局所disable/baselineを作る。
3. lint jobはwarningではなくerror件数でfailし、実行対象file一覧をlogへ出す。
4. custom rule用のpositive/negative fixture testをscript化し、regex変更による無効化を検出する。

## リグレッションテスト / CI受け入れ条件

- Testsに意図的なerror rule違反を置いたfixtureでlint jobがfailする。
- SourcesとTestsの両方がlint対象としてlogに現れる。
- `no_fire_and_forget_session_close`と`no_cancellable_cleanup_close`のpositive/negative fixtureが期待どおり判定される。
- repository全体lintがcleanになった後、warning運用中custom ruleをerrorへ段階的に昇格する。
