# 003 ci: パフォーマンス退行を環境非依存の指標で検出する

状態: **open**
起票: 2026-06-30
関連: `.github/workflows/ci.yml` / `.github/workflows/e2e.yml` / `Tests/SMBeeTests`

## 背景

`smbcli` と公開 API は最低限の SMB client として動く状態になったが、今後の改善で以下のような
パフォーマンス退行を入れても、通常の unit / E2E だけでは見落としやすい。

- 大きな file read/write が想定より細かい chunk に分割される
- directory listing が streaming 経路ではなく全件集約経路へ戻る
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
  - directory streaming API で callback が entry/page ごとに呼ばれ、CLI `ls` が streaming 経路を使うこと
  - large file read/write で full payload を `[UInt8]` に集約しない API が使われること
- session reuse count
  - persistent session API で複数 operation を行っても `NEGOTIATE` / `SESSION_SETUP` / `TREE_CONNECT`
    が 1 回ずつで済むこと
- algorithmic scaling
  - synthetic input size を 2 倍にしたとき、request count / callback count が O(n) の期待式に一致すること
  - O(n^2) 的な「累積 copy / 配列結合」退行を、サイズ別 counter で検出すること

wall-clock time は補助ログとして出してよいが、pass/fail の主条件にしない。

## スコープ分割

### Phase 1 — 最初の PR で入れる

最初から全部を固定しない。まず、退行影響が大きく、現在の API だけで測れるものを CI gate にする。

- read streaming
  - `SMBClient.withReadStream` / `SMBClientSession.withReadStream` が full payload を `[UInt8]` に集約せず、
    期待 chunk 数で `onChunk` を呼ぶこと。
  - `READ` request 数が `ceil(fileSize / effectiveReadChunkSize)` に一致すること。
- write streaming
  - local file upload / streaming write が `localWriteChunkLimit` と negotiated max write size の小さい方で分割されること。
  - `WRITE` request 数が `ceil(fileSize / effectiveWriteChunkSize)` に一致すること。
- persistent session reuse
  - `SMBClient.connect(...) -> SMBClientSession` で複数 operation を実行しても、`NEGOTIATE` / `SESSION_SETUP` /
    `TREE_CONNECT` がセッション確立時の 1 回分だけで済むこと。
- CI job
  - `ubuntu-latest` で `swift test --filter SMBeePerformanceRegressionTests` を走らせる。

### Phase 2 — Phase 1 後に追加する

- directory streaming
  - `withDirectoryStream` が entry callback 経路を通ること。
  - `QUERY_DIRECTORY` request 数が fixture の page 数 + `STATUS_NO_MORE_FILES` 終端に一致すること。
- recursive download/upload/copy scaling
  - synthetic directory tree の node 数を 2 倍にしたとき、operation count が O(n) の期待式に一致すること。
- CLI path smoke
  - `smbcli ls/cat/get/put` が streaming API 経路を使うことを、必要なら test-only hook で確認する。

### Later — 今は CI gate にしない

- 実 Samba / macOS SMBX に対する転送速度の秒数比較。
- NAS / Windows Server など実サーバ別の performance matrix。
- micro benchmark framework 導入。
- allocation byte 数そのものの厳密測定。必要になるまで counter / callback count を proxy にする。

## 計測点の注意

SMB3 の認証後 packet は signing / encryption / transform header の影響を受けるため、**暗号化後の raw outbound
frame だけを後から decode して command histogram を作る設計にしない**。command count は、以下のどちらかで取る。

1. codec / session の pre-transform 境界で、test-only instrumentation として command を記録する。
2. `InMemoryTransport` / `ControlledReceiveTransport` に流す fixture を、decode 可能な非暗号 synthetic packet に限定する。

実 wire 互換性は既存 unit / Samba E2E が見る。performance-regression test は、実時間ではなく「想定より余計な操作を
発行していないか」を固定する contract とする。

## 期待値の書き方

しきい値は時間ではなく式で書く。

### read streaming

- `effectiveReadChunkSize = min(localReadLimit, negotiatedMaxReadSize - transformOverhead)`
- `expectedReadRequests = ceil(fileSize / effectiveReadChunkSize)`
- command count:
  - `CREATE`: 1
  - `QUERY_INFO`: 1
  - `READ`: `expectedReadRequests`
  - `CLOSE`: 1
- callback count:
  - `onChunk`: `expectedReadRequests`
- byte count:
  - `sum(chunk.count) == requestedLength`

### write streaming

- `effectiveWriteChunkSize = min(localWriteLimit, negotiatedMaxWriteSize - transformOverhead)`
- `expectedWriteRequests = ceil(fileSize / effectiveWriteChunkSize)`
- command count:
  - `CREATE`: 1
  - `WRITE`: `expectedWriteRequests`
  - `FLUSH`: 1
  - `CLOSE`: 1
- byte count:
  - `sum(writtenBytes) == fileSize`

### persistent session reuse

`SMBClientSession` で `stat -> read -> list` のように複数 operation を続ける fixture を作る。

- session setup side:
  - `NEGOTIATE`: 1
  - `SESSION_SETUP`: 2 request phases までを許容。実装が single phase になった場合は contract を見直す。
  - `TREE_CONNECT`: 1
- per operation side:
  - operation ごとの `CREATE` / `QUERY_INFO` / `READ` / `QUERY_DIRECTORY` / `CLOSE` は増えてよい。
- 禁止:
  - operation ごとに `NEGOTIATE` / `SESSION_SETUP` / `TREE_CONNECT` が増えること。

### directory streaming

Phase 2 で追加する。

- `expectedQueryDirectoryRequests = pageCount + 1(noMoreFiles)`
- `onEntry` callback count = fixture entry count
- `list()` の全件配列化は互換 API として許容するが、`withDirectoryStream()` と `smbcli ls` は streaming 経路を使う。

## ログ形式

失敗時に何が増えたか分かるよう、job log に machine-readable 風の 1 行を出す。

```text
PERF_METRIC read_stream.commands.READ actual=16 expected=16
PERF_METRIC read_stream.chunks actual=16 expected=16
PERF_METRIC read_stream.bytes actual=1048576 expected=1048576
PERF_METRIC persistent_session.commands.NEGOTIATE actual=1 expected=1
```

`actual` と `expected` を両方出す。wall-clock time を出す場合も `PERF_INFO` として扱い、失敗条件にはしない。

```text
PERF_INFO read_stream.wall_clock_ms value=42
```

## 実装案

1. `Tests/SMBeeTests/SMBeePerformanceRegressionTests.swift` を追加する。
   - `InMemoryTransport` / `ControlledReceiveTransport` を使い、実 network に依存しない。
   - command count は pre-transform instrumentation か、decode 可能な synthetic frame に限定して記録する。
   - negotiated read/write size を固定した synthetic session で chunk count を assert する。
2. test helper を追加する。
   - `SMBCommandCounter`: command histogram を保持し、`PERF_METRIC` 形式で dump する。
   - `CountingSink` / `CountingSource`: streaming callback count と byte count を記録する。
   - `ceilDiv(_:_:)`: expected request 数の式をテスト内で重複させない。
3. CI に専用 job を追加する。
   - job 名: `performance-regression`
   - runner: `ubuntu-latest`
   - command: `swift test --filter SMBeePerformanceRegressionTests`
   - 通常 unit と分ける理由は、失敗時に「性能退行の contract が壊れた」と明確にするため。
4. `docs/testing.md` に「性能テストは実時間ではなく計算量 proxy を見る」方針を追記する。

## 完了条件

### Phase 1 完了条件

- [ ] `SMBeePerformanceRegressionTests` を追加する。
- [ ] CI に `performance-regression` job を追加する。
- [ ] read streaming の `READ` count / chunk count / byte count を deterministic metric で assert する。
- [ ] write streaming の `WRITE` count / chunk count / byte count を deterministic metric で assert する。
- [ ] persistent session reuse の `NEGOTIATE` / `SESSION_SETUP` / `TREE_CONNECT` count を assert する。
- [ ] pass/fail 条件に wall-clock time を使わない。
- [ ] job のログに `PERF_METRIC ... actual=... expected=...` を出す。
- [ ] `docs/testing.md` に「性能テストは実時間ではなく計算量 proxy を見る」方針を追記する。

### Phase 2 完了条件

- [ ] directory streaming の `QUERY_DIRECTORY` count / `onEntry` callback count を追加する。
- [ ] recursive download/upload/copy の O(n) scaling counter を追加する。
  - 2026-06-30: `SMBSession.copyDirectory` / `deleteRecursively` は directory page を配列集約せず、
    `queryDirectory(... onEntry:)` callback traversal で処理するよう修正済み。残る計測対象は
    one-shot `downloadDirectory` と recursive upload/download/copy の operation count proxy。
- [ ] 必要なら CLI が streaming 経路を使うことを test-only hook で確認する。

## やらないこと

- GitHub Actions 上の秒数に固定しきい値を置くこと。
- 実 Samba / macOS SMB server の実転送時間を CI gate にすること。
- micro benchmark framework 導入。必要になるまで XCTest + deterministic counter で十分。
- command count を無差別に固定すること。固定するのは「性能 contract として守りたい数」だけにする。
