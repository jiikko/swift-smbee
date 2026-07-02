# credit window / demux の follow-up（orphan 蓄積・会計 drift・head-of-line）

- 種別: bug (低頻度) + design followup
- 発見: 2026-07-03 サブエージェントレビュー → main agent で妥当性確認済み。codex レビューは usage limit のため未実施 (要: 後日 codex-review)
- 前提: messageId が CreditCharge 分進まないバグは 2026-07-03 に修正済み
  (`SMBSession.nextMessageId(charge:)`)。本 issue はその残件。

## 対応 (2026-07-03 完了)

1. orphan queue に上限 64 を追加。超過時は最古 messageId を drop して debug log。
2. `reserveCredit` は decode 失敗時に fallback せず throw（自作 packet の decode 失敗 = 内部バグ）。
3. FIFO head-of-line は「大 request の飢餓防止のため意図的」と rationale コメントを
   `SMB2CreditWindow.resumeReadyWaiters` に明記。
併せて issues/013 の残件だった `reserve` の cancellation 対応
(withTaskCancellationHandler + waiter 除去) も実装。unit coverage あり。

## 1. `orphanResponses` の無制限蓄積

`SMBSession.dispatchReceivedPacket` は pending に無い messageId の packet を
`orphanResponses` に無期限に保持する（`markRequestSent` の一致 or 全 fail でしか消えない）。
server の重複/spurious response が来ると long-lived session でメモリが漏れる。
oplock break / messageId=UInt64.max は 2026-07-03 に drop 済みだが、一般の未知 id は残る。

対応案: エントリ数上限（例: 64）+ 超過時は最古を drop して debug log。

## 2. `reserveCredit` の decode 失敗 fallback による会計 drift

`guard let header = try? SMB2Header.decode(packet) else { return 1 }` — decode 失敗時に
charge=1 で reserve するが packet はそのまま送られる。実際の CreditCharge と window の
帳簿がずれ、window が徐々に痩せる。自作 packet が decode 不能な時点で内部バグなので、
fallback せず throw する方が安全。

## 3. `SMB2CreditWindow.resumeReadyWaiters` の head-of-line blocking

FIFO 先頭 waiter の charge が available を超えている間、後続の小さい waiter も全て待つ。
大 request の飢餓を防ぐ意図なら妥当（コメントで明示する）。スループット優先なら
first-fit に変える。方針を決めて rationale をコードに残す。

## 関連

- todo2 P1-3 (credit accounting / multi-credit IO)。local chunk cap が 64KiB
  (`SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, ...)`) のため
  multi-credit request は現状発生しない。cap を上げる時に本 issue を再評価すること。
