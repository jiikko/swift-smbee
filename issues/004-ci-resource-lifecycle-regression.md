# 004 ci: リソースライフサイクル退行を静的lintと実行時contractで検出する

状態: **open**
起票: 2026-06-30
関連: `.github/workflows/ci.yml` / `Tests/SMBeeTests` / `Sources/SMBee/POSIXSocketTransport.swift` / `Sources/SMBee/SMBClient.swift`
GitHub Issue: https://github.com/jiikko/swift-smbee/issues/1

## 背景

`smbcli` / `SMBee` は socket fd、transport、`FileHandle`、`Task`、`CheckedContinuation` など、Swift の ARC だけでは安全性を表現しきれないリソースを扱う。

通常の unit / E2E では機能的に成功していても、以下のようなリソースライフサイクル退行を見落としやすい。

- 成功時は動くが、throw / cancellation 経路で `transport.close()` が呼ばれない
- `POSIXSocketTransport` の socket fd が失敗経路で close されない
- `FileHandle` が error 経路で close されない
- `withCheckedContinuation` / `withCheckedThrowingContinuation` の pending continuation が close / cancel 時に resume されない
- `Task.detached { ... self ... }` が想定より長く `self` / transport / session を保持する
- `SMBClientSession.close()` 後の二重 close / use-after-close が不安定になる

SwiftLint の通常 rule だけでは、こうした所有権・ライフサイクル退行を十分には検出できない。そのため、静的lintだけに寄せず、実行時 contract test と補助的な sanitizer job を組み合わせる。

## 方針

優先順位は以下。

1. 実行時 contract test
2. Semgrep custom rules
3. ASan / LSan smoke
4. TSan smoke
5. SwiftLint analyzer / custom regex rule

最初から sanitizer を CI gate にしない。まず、repo 内のリソース所有境界を deterministic に検証する。

## Phase 1 — 実行時 contract test を追加する

`Tests/SMBeeTests/SMBeeResourceLifecycleTests.swift` を追加する。

### test helper

- `CloseCountingTransport`
  - `closeCallCount`
  - `connectCallCount`
  - `sendCallCount`
  - `receiveCallCount`
  - `close()` が複数回呼ばれても安全かを検証できるようにする。
- `LeakTrackingTransport`
  - `deinit` 時に tracker へ通知する。
  - weak reference / expectation で解放可能性を確認する。
- `ContinuationTrackingTransport`
  - pending receive continuation を持つ。
  - `close()` / cancellation 時に continuation が resume されることを確認する。
- `FailingAfterConnectTransport`
  - connect 成功後、send / receive / protocol response の途中で throw する fixture 用。

### 検証対象

- success path
  - `SMBClient.list/read/stat/delete` などが成功した後、transport が close されること。
- throw path
  - connect 後の `SESSION_SETUP` / `TREE_CONNECT` / `CREATE` / `READ` / `WRITE` 失敗でも close されること。
- cancellation path
  - pending receive 中の task cancellation で continuation が resume され、transport が close されること。
- persistent session
  - `SMBClient.connect(...) -> SMBClientSession` では、operation ごとに close されないこと。
  - `SMBClientSession.close()` で close が 1 回だけ呼ばれること。
  - `close()` 後の operation が `connectionLost(operation: "SESSION")` 相当で失敗すること。
  - `close()` の二重呼び出しが idempotent であること。
- object lifetime
  - operation 完了後に transport / session を保持する不要な強参照が残らないこと。

### CI job

`.github/workflows/ci.yml` に専用 job を追加する。

```yaml
resource-lifecycle:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: swift-actions/setup-swift@v2
      with:
        swift-version: "6.0"
    - name: Resource lifecycle tests
      run: swift test --filter SMBeeResourceLifecycleTests
```

通常 unit test と分ける理由は、失敗時に「機能不具合」ではなく「リソースライフサイクル contract 破壊」と分かるようにするため。

## Phase 2 — Semgrep custom rules を追加する

SwiftLint だけでは所有権解析が弱いため、リソースリークの静的検出は Semgrep custom rules を優先する。

### rules 例

- `FileHandle(forWritingTo:)` / `FileHandle(forReadingFrom:)` を作った関数で `close()` / `defer close()` が見当たらない。
- `socket(...)` を作った後、失敗経路に `close(...)` がない。
- `withCheckedContinuation` / `withCheckedThrowingContinuation` の continuation を field に保持する型で、`close()` / `cancel()` / `deinit` に resume 経路がない。
- `Task.detached { ... self ... }` で transport / session owner を長く捕まえる。
- `SMBClient.connect(...)` の戻り値 `SMBClientSession` を捨てる、または `close()` なしで scope を抜ける疑いがある箇所。

### CI job

最初は advisory 扱いにする。

```yaml
semgrep-resource-lint:
  runs-on: ubuntu-latest
  continue-on-error: true
  steps:
    - uses: actions/checkout@v4
    - name: Run Semgrep resource lifecycle rules
      uses: semgrep/semgrep-action@v1
      with:
        config: .semgrep/resource-lifecycle.yml
```

誤検知が落ち着いたら required job 化する。

## Phase 3 — Sanitizer smoke job を追加する

ASan / LSan は native memory / C interoperability / fd 周辺の補助検出として使う。

### ASan / LSan

最初は `workflow_dispatch` または `continue-on-error: true` にする。

```yaml
sanitizer-smoke:
  runs-on: ubuntu-latest
  continue-on-error: true
  steps:
    - uses: actions/checkout@v4
    - uses: swift-actions/setup-swift@v2
      with:
        swift-version: "6.0"
    - name: Address sanitizer smoke
      run: swift test --sanitize=address
      env:
        ASAN_OPTIONS: detect_leaks=1
```

### TSan

ThreadSanitizer は重いため、PR必須jobではなく手動/定期実行から始める。

```yaml
thread-sanitizer-smoke:
  runs-on: ubuntu-latest
  if: github.event_name == 'workflow_dispatch'
  steps:
    - uses: actions/checkout@v4
    - uses: swift-actions/setup-swift@v2
      with:
        swift-version: "6.0"
    - name: Thread sanitizer smoke
      run: swift test --sanitize=thread
```

## 完了条件

### Phase 1 完了条件

- [ ] `SMBeeResourceLifecycleTests.swift` を追加する。
- [ ] `CloseCountingTransport` を追加する。
- [ ] success path で `transport.close()` が呼ばれることを assert する。
- [ ] throw path で `transport.close()` が呼ばれることを assert する。
- [ ] cancellation path で pending continuation が resume されることを assert する。
- [ ] `SMBClientSession.close()` が idempotent であることを assert する。
- [ ] `SMBClientSession.close()` 後の operation が明示的に失敗することを assert する。
- [ ] CI に `resource-lifecycle` job を追加する。

### Phase 2 完了条件

- [ ] `.semgrep/resource-lifecycle.yml` を追加する。
- [ ] `FileHandle` / `socket` / `CheckedContinuation` / `Task.detached` の custom rule を追加する。
- [ ] CI に `semgrep-resource-lint` job を advisory として追加する。
- [ ] 誤検知を整理し、required job 化するか判断する。

### Phase 3 完了条件

- [ ] `sanitizer-smoke` job を追加する。
- [ ] `ASAN_OPTIONS=detect_leaks=1` で実行する。
- [ ] SwiftPM / runner / dependency の都合で安定しない場合は `workflow_dispatch` に落とす。
- [ ] TSan は手動/定期実行にするか判断する。

## やらないこと

- SwiftLint 通常 rule だけでリソースリーク検出を完結させること。
- wall-clock time やRSSの固定値を leak 判定に使うこと。
- sanitizer smoke を最初から required job にすること。
- Semgrep custom rule の初回導入時から誤検知ゼロを要求すること。

## 注意点

- ASan / LSan は Swift ARC の論理的な循環参照をすべて検出できるわけではない。
- Semgrep custom rule は所有権移譲を完全には理解できないため、誤検知を前提にする。
- 実行時 contract test はテストした経路しか保証しない。
- それでも、この repo では socket fd / transport / continuation / session close の境界が明確なので、まず contract test を入れる費用対効果が高い。
