# 077 bug疑い: closeTransport 後に開始した operation の pending が resume されない経路

- 種別: bug / resource leak / cleanup liveness
- 重要度: medium（P2。codex 反証レビュー 2026-08-01 で「反証できず、症状は記述より悪い」と確認済み）
- 起票: 2026-08-01（issue 069 再現テスト作成時の敵対レビューで検出）
- 関連: `Sources/SMBee/SMBClient.swift`（`demuxedWireTransaction` / `reserveCredit` / `closeTransport`）
- 関連issue: `issues/069-bug-cleanup-failure-kills-shared-session.md`

## 症状（静的指摘・未再現）

`closeTransport` 完了後に `demuxedWireTransaction` へ入った operation は、次の順で無期限 pending に
なり得る:

1. `closeTransport` が `failWire` で既存の `pendingResponses` を全消去・resume する。
2. その後に開始した operation が新しい pending continuation を `pendingResponses` へ登録する
   （登録は credit reserve / send より先）。
3. `reserveCredit` は `wireFailure` が設定済みなのでそれを throw する。
4. send 失敗経路が `closeTransport` を再度呼ぶ。
5. `closeTransport` は `transportClosed` guard で即 return し、手順 2 で登録された新規 pending を
   resume しない。

## codex 反証レビューの結論（2026-08-01・反証できず）

手順 1-5 は現コードと一致。さらに当初記述の「外側の Task は reserve の throw で終了する可能性が高い」は
**誤り**で、実際はより悪い:

- reserve の例外は内側の unstructured send `Task` の catch で捕捉・消費される
  （`failPendingResponse` が呼ばれるのは `CancellationError` の場合のみ）。
- 外側の operation は `withCheckedThrowingContinuation` の resume を待ち続けるため、
  cancel 等の別の終端イベントがなければ **pending エントリ残留 + continuation 未 resume +
  operation の無期限待ち** が通常の帰結になる。

到達可能性:

- `SMBClientSession.close()` 後の公開 API は `ensureOpen` で弾かれるため対象外。
- しかし send/receive/cleanup 失敗による `closeTransport` は `SMBClientSession.isClosed` を
  更新しないため、**cleanup timeout 後の persistent session への `echo` / `read` 等は
  `ensureOpen` を通過し、実運用経路で到達可能**。
- 既存 `testRequestAfterReceiveLoopFailureFailsWithoutCreditWait` は `transportClosed == false` の
  「最初の後続 request」を固定しているだけで、その次の request（本 issue）はカバーしていない。

## 検証方法（先にやること）

- `closeTransport` 済みの `SMBSession` に対して低レベル operation（`readChunk` 等）を開始し、
  operation が有限時間で throw すること・`pendingCountForTesting() == 0` に戻ることを unit で確認する。
- 再現しなければ「reserve throw → catch 経路で pending が除去される」実装根拠を特定し、本 issue を
  false positive としてクローズする（結論をこのファイルに残す）。

## 対応方針（再現した場合）

- `demuxedWireTransaction` の pending 登録前に `wireFailure` を検査して即 throw する、または
  send/reserve 失敗の catch 経路で自分の pending エントリを必ず除去・resume する
  （「continuation を登録する箇所は全終端経路で resume される」不変条件、issue 010 §B と同じ）。

## 対応結果（2026-08-01）

- `demuxedWireTransaction` の pending 登録前に `wireFailure` / `transportClosed` を検査して即 throw。
  `wireFailure` のみ（transport 未 teardown）の窓では `closeTransport(cause: request_after_wire_failure)`
  で従来の teardown を維持してから throw する。
- send Task の失敗経路は error 型に関わらず `failPendingResponse` で自 transaction を必ず終端してから
  （非 cancellation の場合のみ）`closeTransport` する。closeTransport の冪等 guard に continuation 解放を
  依存しない。
- 回帰テスト: `testOperationsAfterClosedTransportFailWithExistingWireFailureWithoutPendingResponse` /
  `testRequestAfterWireFailureTearsDownTransportBeforeThrowing`。完全 revert のミューテーションで
  検知確認済み（2 つのサブ修正は同一シナリオに対して冗長な defense-in-depth）。
