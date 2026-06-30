# 003 ci: パフォーマンス退行を環境非依存の指標で検出する

状態: **open**
起票: 2026-06-30
関連: `.github/workflows/ci.yml` / `.github/workflows/e2e.yml` / `Tests/SMBeeTests`

## 背景

`smbcli` と公開 API は最低限の SMB client として動く状態になったが、今後の改善で以下のような
パフォーマンス退行を入れても、通常の unit / E2E だけでは見落としやすい。

- 大きな file read/write が想定より細かい chunk に分割される
- directory listing が page streaming ではなく全件集約経路へ戻る
- 1 operation あたりの SMB request/response 回数が増える
- persistent session を使うべき箇所で毎回 connect/auth/treeConnect してしまう
- retry / close / flush などの補助 command が意図せず増える

ただし CI とローカルでは CPU / I/O / network / virtualization の差が大きいため、**実行時間そのものを
しきい値にするテストは不安定**になりやすい。

## 問題

「速い/遅い」を wall-clock time だけで測ると、環境差や GitHub Actions の混雑で flake する。
一方で、この実装は `InMemoryTransport` と codec unit を持っているため、環境に依存しにくい
**計算量・通信量に近い proxy 指標**を CI で固定できる。

## 方針

CI に performance-regression 用 job を追加する。計測対象は wall-clock ではなく、原則として以下のような
deterministic metric にする。

- SMB wire transaction count
  - `CREATE` / `READ` / `WRITE` / `QUERY_DIRECTORY` / `QUERY_INFO` / `CLOSE` など command 別の request 数
  - 例: N byte read が `ceil(N / negotiatedReadChunkSize)` 回の `READ` で済むこと
- chunk count / byte count
  - read/write stream が期待 chunk 数で進むこと
  - 受信/送信 byte の総量が payload size + expected protocol overhead の範囲に収まること
- allocation-prone behavior の proxy
  - directory streaming API で callback が page ごとに呼ばれ、CLI `ls` が全件配列を作らない経路を使うこと
  - large file read/write で full payload を `[UInt8]` に集約しない API が使われること
- session reuse count
  - persistent session API で複数 operation を行っても `NEGOTIATE` / `SESSION_SETUP` / `TREE_CONNECT`
    が 1 回ずつで済むこと
- algorithmic scaling
  - synthetic input size を 2 倍にしたとき、request count / callback count が O(n) の期待式に一致すること
  - O(n^2) 的な「累積 copy / 配列結合」退行を、サイズ別 counter で検出すること

wall-clock time は補助ログとして出してよいが、pass/fail の主条件にしない。

## 実装案

1. `Tests/SMBeeTests` に `SMBeePerformanceRegressionTests` 相当を追加する。
   - `InMemoryTransport` / `ControlledReceiveTransport` を使い、実 network に依存しない。
   - outbound frame を decode して command 別 request count を assert する。
   - negotiated read/write size を固定した synthetic session で chunk count を assert する。
2. 必要なら test helper を追加する。
   - `SMBCommandCounter` のような helper で outbound frames から command histogram を作る。
   - `CountingSink` / `CountingSource` で streaming callback count と byte count を記録する。
3. CI に専用 job を追加する。
   - 例: `swift test --filter SMBeePerformanceRegressionTests`
   - 通常 unit と分ける理由は、失敗時に「性能退行の contract が壊れた」と明確にするため。
4. しきい値は時間ではなく式で書く。
   - `expectedReadCount = ceil(fileSize / negotiatedReadChunkSize)`
   - `expectedQueryDirectoryRequests = pageCount + 1(noMoreFiles)`
   - `expectedSessionSetupCount = 1` for persistent session multi-operation smoke

## 完了条件

- [ ] CI に performance-regression job を追加する。
- [ ] 少なくとも read streaming / write streaming / directory streaming / persistent session reuse の
      deterministic metric test を追加する。
- [ ] pass/fail 条件に wall-clock time を使わない。
- [ ] job のログに command count / chunk count / byte count を出し、退行時に何が増えたか分かる。
- [ ] README または `docs/testing.md` に「性能テストは実時間ではなく計算量 proxy を見る」方針を追記する。

## やらないこと

- GitHub Actions 上の秒数に固定しきい値を置くこと。
- 実 Samba / macOS SMB server の実転送時間を CI gate にすること。
- micro benchmark framework 導入。必要になるまで XCTest + deterministic counter で十分。

