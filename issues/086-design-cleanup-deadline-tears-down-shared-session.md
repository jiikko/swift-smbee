# 086 design: cleanup wire 操作の deadline 超過が共有セッション全体を落とす policy を再検討する

- 種別: design (既存 policy の再検討)
- 起票: 2026-09-08
- 状態: **open / 設計検討**
- 関連: [`done/065`](done/065-leak-cleanup-wire-operations-have-no-deadline.md) (この policy を**意図的に**入れた issue) /
  [`080`](done/080-bug-ci-multiflight-connection-closed.md) (発見の経緯) /
  [`075`](075-perf-linux-aes-ccm-pure-swift-throughput.md) (CI で顕在化させた throughput) /
  [`done/062`](done/062-design-cancel-tears-down-shared-session.md) (同族の症状と tombstone drain 設計) /
  `Sources/SMBee/SMBClient.swift` の `defaultCleanupTimeout` / `closeCreatedHandle` /
  `bestEffortClose` / `bestEffortTreeDisconnect` / `disconnect`

## これは新規バグではない — 065 で意図的に入れた policy の再検討

issue 065「cleanup wire operation に deadline が無い」の対応結果として、次が入っている。

- cleanup 専用 deadline を `SMBSession` に追加し、production default を **5 秒**にした
  (`SMBClient.swift:4005`)。
- **cleanup failure / timeout 時は transport を閉じ、pending response と credit waiter を drain する。**
- 理由はコードにも書かれている: CLOSE が失敗すると FileId の寿命が不明になり session を再利用できない
  (`SMBClient.swift:5316-5318`)、scoped tree も同様 (`5358-5359`)。

本 issue はこの policy を否定するものではなく、**「遅いだけ」と「壊れている」を deadline が
区別できない**点を再検討する。

## 何が起きるか

`closeTransport` → `failWire` → `failAllPendingResponses` は
`pendingResponses` / `sentResponseMessageIds` / `orphanResponses` を全消去する
(`SMBClient.swift:6116-6148`)。
つまり **1 つの handle の後始末が deadline に間に合わなかっただけで、保持セッション上の
無関係な in-flight 操作が全部 `connectionClosed` になる。**

同じ 5 秒 deadline を使う経路: `closeCreatedHandle` (`5320-5324`) /
`bestEffortClose` (`5335-5344`) / `bestEffortTreeDisconnect` (`5364-5368`) /
`disconnect` の TREE_DISCONNECT + LOGOFF (各 5 秒、`5404-5415`)。

## 観測 (issue 080 の調査から)

CI E2E run 31650773027 (`f725bd6`) の multi-flight テストが 12.4 秒で `connectionClosed` になった。
1 MiB の暗号化 response の前後に 18〜26 秒の実時間ギャップがあり、
receive loop が塞がっている間に cleanup の CLOSE 応答が 5 秒以内に届く余地は無い。

🚨 **未確定**: `SMBEE_PERF` が無効だったため `close_transport cause=` がログに残っておらず、
上記のどの経路が発火したかは確定していない。`SMBOperationDeadline` は hard deadline ではなく
cancel 後に task 完了を待つため、5 秒ちょうどで閉じるとも限らない。
**着手時にまず `SMBEE_PERF=1` の 1 run で cause と timer 発火時刻を確定させること。**

## なぜ CI 固有と言い切れないか

receive loop が塞がる原因は「Linux の pure-Swift CCM が遅い」(issue 075) だけではない。
遅い / 混んでいる実 NAS、大きな read の復号、モバイル回線・VPN 越しでも
「cleanup の CLOSE が 5 秒に間に合わない」は起こりうる。
obaket の共有セッション (動画先読み) では **「SMB がたまに切れる」**として現れる。
issue 062 が扱った「read cancel が session を壊す」と同じ**症状**で、発動点が違う。

## 設計上の論点

1. **「遅い」と「壊れている」を区別できるか。** deadline 超過はどちらでも同じ顔で出る。
   receive loop が生きていて他の response が届いているなら wire は壊れていない。
2. **065 が守りたかったもの**は「FileId / tree の寿命が不明なまま session を再利用しない」こと。
   *応答が遅い*だけのケースでも同じ強度が要るか。
3. **穴を残さずに session を生かす道はあるか。** 062 の tombstone + quarantine 機構が近い。

## 対応案 (どれも未検証)

| 案 | 内容 | 前提・懸念 |
|---|---|---|
| A. tombstone drain + bounded quarantine | deadline 超過時に transport を閉じず、その CLOSE を tombstone として残して drain する | **drop-in 再利用では足りない**: `bestEffortClose` は detached task の完了を await しており (`5332-5347`) tombstone 化だけでは await を解除できない。CLOSE の最終応答 / `STATUS_CANCELLED` / handle state unknown の扱い / tombstone 上限 / quarantine 中の新規操作の可否をすべて定義する必要がある (062 の sendStarted・wireSent 規則と drain timeout quarantine を含む形なら有効) |
| B. soft deadline + session quarantine | deadline 超過で即 close せず、session を quarantine 状態にして新規 admission を止める | 状態が 1 つ増える。quarantine から復帰する条件が要る |
| C. cleanup の直列化 / 新規 operation の admission 停止 | cleanup 中は新規操作を受けない | 保持 session の応答性が落ちる |
| D. handle 生成時点から専用 session を使う | cleanup が共有 wire を巻き込まない | session 数が増える。credit / 認証コストが増える |
| E. cleanup を別 actor / worker へ隔離 | 復号の負荷と cleanup の deadline を分離する | 実装が大きい |
| F. deadline を伸ばす / 適応的にする | 5 秒 → 30 秒等、または直近の response 間隔から算出 | 閾値の付け替えであって構造の是正ではない。A〜E が固まるまでの緩和にはなる |
| G. 現状維持 | 065 の判断を維持し、理由を再確認してコメントを補強して close | 遅い実 NAS で「たまに切れる」が残る。**選ぶなら「なぜ気づけると言えるか」を書くこと** |

CI 側の話 (転送量削減 / release build / 決定論的 mock) は本 issue のスコープ外で、issue 080 が扱う。

## 完了条件

以下のいずれか。

- `SMBEE_PERF=1` の CI run で cause を確定させたうえで案 A〜F のいずれかを実装し、
  **「receive loop が塞がっている間に cleanup CLOSE が deadline を超えても、
  同じ session の他の in-flight 操作が失敗しない」**ことを回帰テストで固定する。
  テストは fake clock か遅い transport の seam で決定論的に作る (壁時計に依存させない)。
  併せて 065 の「cleanup failure で transport を閉じる」不変条件が**どう変わったか**を
  065 の本文か API contract へ追記する。
- または案 G を選び、**なぜ閉じる必要があるか**と**どうなれば変更可能か**を
  `bestEffortClose` / `closeCreatedHandle` の直近コメントに残して close する。

## 残タスク

- [ ] `SMBEE_PERF=1` の CI run で `close_transport cause=` と timer 発火時刻を確定 (issue 080 の残タスク)
- [ ] 案の選定 (外部レビューを通す)
- [ ] 実装 + 決定論的な回帰テスト
