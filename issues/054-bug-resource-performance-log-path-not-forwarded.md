# 054 bug: resource performance のカスタムログパスをコンテナへ転送する

状態: **open**
起票: 2026-07-12
優先度: **P2**
コスト: **S**
関連: `bin/ci/run-resource-performance` / `bin/ci/write-resource-performance-artifact` / `bin/ci/publish-resource-performance-summary` / `bin/ci/test-performance-scripts` / `.github/workflows/performance.yml` / `issues/done/052-perf-calibrate-resource-metrics-and-plan-optimization.md`

## 背景

`bin/ci/run-resource-performance` は `RESOURCE_PERFORMANCE_LOG` を受け取り、ホスト側のログファイルの親ディレクトリを作成する。artifact と summary のスクリプトも同じ環境変数を読み取る。

## 問題

コンテナ内の実行処理は `.build/resource-performance.log` を固定して初期化・追記している。`RESOURCE_PERFORMANCE_LOG` にデフォルト以外のパスを指定すると、ホスト側で後続スクリプトが読むパスと、コンテナ内で実際に書き込むパスが一致しない可能性がある。カスタムパス指定時にログが見つからず、測定結果が欠落する潜在バグである。

## 対応方針

- `RESOURCE_PERFORMANCE_LOG` の相対パスをコンテナへ明示的に転送し、実行処理・初期化・後続の読み取り先を同じパスにする。
- または、デフォルトパス以外の指定を入力検証で明示的に拒否し、利用者に非ゼロ終了とエラーを返す。
- `bin/ci/test-performance-scripts` にデフォルト以外のログパスを指定して、実際にそのパスへログが出力され後続処理が読めるケースを追加する。

## 完了条件

- [ ] カスタムログパスのサポートまたは明示拒否の仕様がスクリプトに記載されている。
- [ ] サポートする場合、コンテナ内の書き込み先とホスト側の artifact/summary の読み取り先が同一入力から決まる。
- [ ] 拒否する場合、デフォルト以外の指定が非ゼロ終了し、理由が標準エラーに出る。
- [ ] `bin/ci/test-performance-scripts` にカスタムパスの回帰テストがあり、実際のファイル存在と読み取り結果を検証する。

