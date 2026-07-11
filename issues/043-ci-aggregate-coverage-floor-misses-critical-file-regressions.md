# 043 CI: package全体coverage floorではwire中核のデグレを検出できない

- 種別: CI / coverage quality
- 重要度: medium
- 状態: open
- 関連: `scripts/check-code-coverage.sh`, `.github/workflows/test.yml`

## 問題

code coverage jobはunit suiteのpackage全体line coverageが65%以上かだけをgateする。reportにはfile別値を
表示するが、file別・変更差分・重要symbolのfloorは判定しない。

そのため`SMBClient.swift`、transport、crypto、codecの未テストbranchが増えても、別fileの容易にcoverできる
code/test追加で全体比率を維持できる。E2E testはcoverage計測から明示的に除外されるため、E2Eだけが通る
public facadeや実transport経路はcoverage上0のままでも全体floorを通る。

## 影響

- cancellation、cleanup、signature verification、decoder error pathなど高risk branchのcoverage低下を見逃す。
- 新規実装に対応testがなくてもpackage全体の数値変化が小さければCIがgreenになる。
- file別tableは観測用に留まり、regression防止として機能しない。

## 対応方針

1. 変更行coverageまたは変更fileごとの最低coverageをPR jobへ追加する。
2. `SMBClient.swift`、`SMB2ReadCodecs.swift`、transport、cryptoに個別floorを設定する。
3. branch/region coverageも少なくとも観測し、error/cancellation branchの低下をratchetする。
4. E2E coverageは別artifactとして計測するか、E2E-only symbol一覧を明示してunit coverage分母から扱いを分ける。

## リグレッションテスト / CI受け入れ条件

- 未テストbranchだけをcritical fileへ追加したfixture PRでcoverage jobがfailする。
- 無関係fileのcovered lines追加ではcritical fileの低下を相殺できない。
- file別floorとdiff coverageをjob summaryへ表示する。
- thresholdは現在値から小さなmarginで開始し、改善時のみ引き上げるratchet運用にする。
