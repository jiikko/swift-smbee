# 078 bug: async header を意味的に decode せず、STATUS_PENDING 後の CANCEL が規範形式にならない

- 種別: bug / protocol compliance / interoperability
- 重要度: medium（根拠は下記「影響」の response correlation。CANCEL 形式単体なら low）
- 起票: 2026-08-01（issue 010 §修正方針 3 の敵対的設計レビューで検出、codex 反証レビューで範囲を訂正）
- 関連: `Sources/SMBee/SMB2Header.swift`（`SMB2Header`）/
  `Sources/SMBee/SMB2ReadCodecs.swift`（`SMB2Cancel.encodeRequest`）/
  `Sources/SMBee/SMBClient.swift`（`SMBPendingResponse` / response correlation / cancellation 経路）

## 事実（codex 反証レビュー 2026-08-01 で「反証できず・事実」と確認済み）

- `SMB2Header` は `SMB2_FLAGS_ASYNC_COMMAND` による union 分岐を持たず、async header の
  bytes 32–39（8-byte AsyncId、MS-SMB2 §2.2.1.1）を常に「4 byte skip + TreeId」として decode する。
- `SMBPendingResponse` は interim response（STATUS_PENDING）の AsyncId を保存しない
  （MS-SMB2 §3.2.5.1.5 は保存を MUST とする）。
- `SMB2Cancel.encodeRequest` は常に同期 header で、AsyncId + `SMB2_FLAGS_ASYNC_COMMAND` の
  async 形式（interim 処理後の CANCEL に対する §2.2.1 / §3.2.4.24 の MUST）を組めない。
- 同期 CANCEL の TreeId に元 request の TreeId をコピーしている（§2.2.1.2 では SHOULD 0）。

## 影響

1. **response correlation（medium の根拠・最も直接的）**: async response の AsyncId 上位 32bit が
   非 zero の server では、正当な STATUS_PENDING / final async response を `treeId mismatch` として
   接続障害にし得る（bytes 36–39 を treeId として照合しているため）。
2. **CANCEL の client-side 仕様違反**: interim 処理後の CANCEL が規範形式にならない。ただし
   「準拠 server が必ず無視する」は仕様から導けず未立証（server-side §3.3.5.16 は async flag なしなら
   MessageId 検索を規定しており、Samba もこの分岐を実装している）。
3. 既存の cancel E2E は「caller が期限内に失敗し session correlation が壊れない」ことしか確認して
   おらず、STATUS_PENDING 経由・CANCEL の wire 形式・server 側解放は未検証。

## 対応方針

1. `SMB2Header` に async header の意味的 decode（AsyncId）を追加し、**async response では TreeId
   correlation を行わない**。interim で保存した AsyncId と final async response の一致を検証する。
2. interim response 受信時に `SMBPendingResponse` へ AsyncId を保存する（cancellation と interim
   受信の競合は actor 内で原子的に判定する）。
3. `SMB2Cancel.encodeRequest` に async 形式を追加し、AsyncId 保持 pending への CANCEL は async 形式、
   interim 前は sync 形式（TreeId は 0 に修正）で送る。MessageId は仕様上再利用可だが Windows client は
   AsyncId 使用時 0 にする product behavior があるため、wire test でどちらかを明示的に固定する。
4. unit fixture は wire 上有効な async header になっているが、値を `treeId` と呼んで decode/assert して
   いる。AsyncId として decode・assert し、STATUS_PENDING fixture に SMB2 ERROR response body を付ける。
5. 実測（Tier 3 手動 smoke）: Windows Server / macOS SMBX に対する CHANGE_NOTIFY → STATUS_PENDING →
   cancel で CANCEL の効果（server 側 watch 解放）を確認する。
