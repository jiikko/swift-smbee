# 102 (task): 全体の構成・設計レビュー（2026-10-01）の指摘と裏取り

起票日: 2026-10-01

## 概要

codex（gpt-6-luna、effort max）に、HEAD `ae4c92d` のスナップショットで全体の構成・設計をレビューさせた。
観点は 6 本（レイヤーとモジュール境界 / 並行性 / 公開 API とエラー / テストと CI / セキュリティ / transport と性能）で、
merger が 23 件を 21 件に統合した（全数採用、脱落 0）。各レビュワーには `docs/architecture.md` と `docs/api-stability.md` を先に読ませ、
文書に理由のある設計を行数だけで作り替えないよう指示した。

この issue は指摘の一覧と裏取りの結果を残すためのもの。**個々の対応は、着手するときに別 issue に切り出す**（この issue では直さない）。

## 裏取り済み（Claude が実コードで確認）

| # | 重要度 | 指摘 | 確認した事実 |
|---|---|---|---|
| 1 | P1 | SMB 3.0.x で、中間者が NEGOTIATE 応答の「署名必須」ビットを消すと、署名なしの応答を受け入れる（downgrade） | `FSCTL_VALIDATE_NEGOTIATE_INFO` の実装が無い（`grep` で 0 件）。[`done/021`](done/021-security-signed-session-accepts-unsigned-responses.md) の主題は「署名した session が署名なし応答を受け入れる」で、NEGOTIATE の段階の改ざんは別の経路（なお 021 は done/ にあるが本文の状態表記は open のまま）。SMB 3.1.1 は preauth integrity で守られる |
| 10 | P2 | profile 別の E2E が、filter の空振りや XCTSkip でも緑になる | `.github/workflows/e2e.yml` で `required_test`（`bin/ci/require-xctest-passed`）を持つのは smb302-encrypted-required だけ。smb311-signing / smb311-encrypted / guest / msdfs / smb422-reparse の 5 profile は終了コードだけを見る |
| 11 | P2 | `SMBClient.connect(..., credential:)` が平文の credential を保持し続ける | `SMBClient.swift` の overload が `credentialProvider: { credential }` で値を closure に閉じ込め、`ReconnectInfo` に残る。[`done/037`](done/037-security-session-retains-plaintext-credentials-after-authentication.md)（done/ にあるが本文の状態表記は open のまま）の対象は下位の `SMBSession` 側で、この closure は残る |
| 7 | P2 | auto-reconnect が `close()` の後に session を開き直せる | `reconnect()` は `connect()` / `treeConnect()` を await した後に `session` を差し替え、その間に `isClosed` が立ったかを見直さない |
| 8 | P3 | `STATUS_CANCELLED` が経路によって別の型で返る | 一般の経路は `SMBErrorMapper.throwIfFailure`（`CancellationError`）、SESSION_SETUP#1 だけが `SMBErrorMapper.map`（`SMBError.cancelled`）を直接呼ぶ。レビュワーが挙げた IOCTL は、許可外の status を `SMB2ReadCodecs` で `throwIfFailure` に渡しており該当しない（反証レビューで訂正） |
| 12 | P2 | ACL の `AceCount`（最大 65,535）で、中身の検証前に容量を確保する | `SMB2ReadCodecs.swift` の `decodeACL` が `aclSize` の検証の後、`entries.reserveCapacity(aceCount)` を ACE を読む前に行う。[`done/027`](done/027-robustness-ndr-count-validation-allows-inconsistent-arrays.md) は NDR 配列が対象で、この経路は含まない |
| 13 | P3 | SMB 署名の比較が constant-time でない | `verifyResponseSignature` が `expected == header.signature`（`Array ==`）。CCM の tag は `constantTimeEqual`。遠隔からの測定可能性は未確認 |
| 16 | P2 | POSIX の部分受信のたびに、残りの全量を確保してゼロ初期化する | `POSIXSocketTransport.receiveBlocking(maxLength:)` が毎回、`maxLength` 個のゼロで初期化した配列を作る。小さい部分読みが続くと確保と初期化が残量に比例して繰り返される（効果の大きさは未実測） |

## 未検証（レビュワーの静的な主張のまま。着手前に裏を取る）

| # | 重要度 | 指摘 | 既存 issue |
|---|---|---|---|
| 2 | P2 | `docs/api-stability.md` が「actor が呼び出し全体を直列化する」と読める（actor は await をまたいで排他しない） | — |
| 3 | P2 | handle の cleanup 失敗が共有 session の全操作を終わらせる | [069](069-bug-cleanup-failure-kills-shared-session.md)（対応中） |
| 4 | P2 | 公開の入口（`SMBee` と `SMBClient`）と安定性契約が揃っていない（custom transport は `SMBClient.connect` からしか渡せない） | — |
| 5 | P2 | credit waiter が永久に待つ順序がある（CreditCharge 未満の grant を返すサーバの存在は未確認） | [010](010-bug-linux-unit-suite-hang-multiflight-demux.md) |
| 6 | P2 | 送信後に cancel した request の tombstone に終端の期限が無い | [010](010-bug-linux-unit-suite-hang-multiflight-demux.md) |
| 9 | P2 | `withTree` が TREE_DISCONNECT の失敗（transport を閉じる）を結果に反映しない | 069 で後回しにした TREE_DISCONNECT の経路と関係（069 本文の「M2」） |
| 14 | P2 | READ streaming が 1 request ずつ応答を待つ（RTT のある経路で帯域を使い切れない。未実測） | — |
| 15 | P2 | WRITE も 1 chunk ずつ応答を待つ（未実測） | [done/015](done/015-perf-upload-write-chunk-and-pipeline.md)（本文の 64 KiB の上限の記述が今の実装と食い違う、とレビュワー） |
| 17 | P3 | 並行に呼んだ 2 回目の `close()` が、1 回目の後始末の完了を待たない | — |
| 18 | P3 | 転送 API の間で、全体の deadline の指定方法が揃っていない | — |
| 19 | P3 | `SMBEE_TRACE_WIRE_FULL=1` で、暗号化 session でも平文のファイル内容が stderr に出る | — |
| 20 | P3 | NWConnection の segment 送信が frame 全体を連結する | — |
| 21 | P3 | NWConnection 経路の TCP_NODELAY が未設定・実効値が未確認 | — |

## 「変えない方がよい」とされた点（再提起を防ぐために残す）

- `SMBClient.swift`（6,448 行）の大規模なファイル分割は勧めない。8 つの機能群に分けられるが、`SMBSession` の command 処理と wire 処理は session ID・鍵・credit・
  pending response を共有するので、ファイル移動では依存も状態の共有も減らない。責務を本当に減らすには wire lifecycle の所有者を別の collaborator にする必要があり、
  それは 010 / 069 に関係する中規模以上の変更になる（観点 1）
- `SMBSession` が具体的な transport でなく `SMBTransport` に依存していること、Direct-TCP framing を transport の外に置いていること、codec と crypto が専用ファイルに分かれていること

## 出典

レビューの原文と digest は `tmp/arch/out/`（ローカルの一時領域。消える前提で、結論はこの issue に移した）。

## 付随して見つかったこと

- `done/021`・`done/037`・`done/027` は done/ に置かれているが、本文冒頭の状態表記が open のまま（位置と表記が食い違う）

## 次の一手

裏取り済みのうち、着手する価値が高いのは #1（security、P1）と #10（CI の素通り）。どれを別 issue に切り出すかはユーザーの判断。

## 進捗

- **#1（対応済み、2026-10-02）**: SMB 3.0 / 3.0.2 で、匿名でない session は TREE_CONNECT が成功するたびに `FSCTL_VALIDATE_NEGOTIATE_INFO` を送り、
  NEGOTIATE の 4 値を照合する。応答は暗号化か署名を必須（`signingRequired` を見ない）。失敗・非対応はすべて接続の失敗（fail-closed。ユーザーの判断）。
  匿名の資格情報は検証を省く（SMBee のポリシーの例外）。資格情報を渡したのに guest / null にされた 3.0.x 接続は失敗。
  commit `security(negotiate): SMB 3.0.x で TREE_CONNECT ごとに FSCTL_VALIDATE_NEGOTIATE_INFO を送り、NEGOTIATE の downgrade を検出する (issue 102 #1)`。
  手順と方針の正本は `docs/smb-protocol.md`。実機（macOS SMBX・Windows・NAS）での確認は未実施（Tier 3）。非対応の機器には 3.0.x で接続できなくなる可能性がある
- 設計レビューの途中で見つけた既存バグも直した: 共有の暗号化必須の判定が Capabilities の `0x8`（`SMB2_SHARE_CAP_DFS`）も見ていた。
  commit `fix(tree): 共有の暗号化必須の判定から Capabilities 0x8 (SMB2_SHARE_CAP_DFS) を外す`
- **#10（対応済み、2026-10-01）**: `e2e.yml` の 6 profile と `samba-compat.yml` の 7 profile すべてで、その profile のための test が 1 回 pass したことを必須にした。
  commit `ci: profile 別の E2E は、その profile のための test が 1 回 pass したことを必須にする (issue 102 #10)`。e2e.yml は CI のログで 6 profile 分の `passed once` を確認。
  samba-compat.yml は週次の定期 run で確認する（手動起動は費用のため見送り）
- 残り: 裏取り済みの #7（close 後の再接続）・#8・#11（credential の保持）・#12（ACL の過大確保）・#13・#16 と、未検証の 13 件
