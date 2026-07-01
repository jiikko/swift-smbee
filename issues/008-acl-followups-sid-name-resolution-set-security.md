# 008 feat: ACL follow-ups — SID 名前解決 と SET_SECURITY (write)

状態: **open** (backlog)
起票: 2026-07-01
関連: [todo.md](../todo.md) 「ACL / owner / SID metadata」/ `Sources/SMBee/SMB2ReadCodecs.swift`
(`decodeSecurityDescriptor` / `decodeSID`) / `Sources/smbcli/SMBCLI.swift` (`acl` サブコマンド)

## 背景

todo 319 で **QUERY_SECURITY (read)** を実装した (commit `e3d51ae`)。owner/group SID + DACL ACE を
`SMBSecurityInfo` として取得し `smbcli acl` で表示、実 Samba E2E green。その際に出た follow-up を記録する。

## A. SID → アカウント名の解決 (LSA LsarLookupSids)

`smbcli acl` は SID を数値文字列のまま表示する (例: `S-1-5-21-...-1001`)。実運用では
SID → 人間可読なアカウント名 (`DOMAIN\user`) の解決が欲しくなる。

- 解決には **別プロトコル (MS-LSAT `LsarLookupSids` over `\lsarpc` named pipe)** が必要で、
  現在の SMB2 codec とは独立した DCE/RPC 実装 (`\srvsvc` の share enum と同系統) になる。
- スコープが大きいので独立タスク。まず「よく知られた SID (well-known: `S-1-5-32-544`=Administrators,
  `S-1-1-0`=Everyone 等)」の静的テーブルだけ持つ軽量版から始める案もある (RPC 不要で ACE 表示が読みやすくなる)。

## B. SET_SECURITY (write)

todo 319 では **書き込みを意図的に defer** した。理由:

- 自分のアクセス権をロックアウトしうる **破壊操作**。
- self-relative SECURITY_DESCRIPTOR の **構築 (encode)** が read の parse より複雑
  (owner/group/DACL の offset 再計算、ACL/ACE の pack)。

着手する場合の設計メモ:

- **read-modify-write** を基本にする (既存 SD を `securityInfo` で取得 → ACE を足し引き → 書き戻し)。
  ゼロから SD を組ませない。
- **自ロックアウト防止**: 書き戻す DACL に現在の認証ユーザーの ACCESS_ALLOWED が残ることを確認する
  guard を入れる (`--force` で明示解除)。
- SET_INFO InfoType=0x03 SECURITY + AdditionalInformation で書き込む。SACL は特権が要るため対象外のまま。
- E2E は「ACE を 1 件足して read で往復一致」を Samba で確認。破壊確認のため bounded / 専用 share で。

## C. SID の 6-byte authority を UInt64 48bit 扱い (対応不要見込み)

`decodeSID` は IdentifierAuthority (6 byte BE) を `UInt64` に畳んでいる。既知の authority は小さい値
(`S-1-5-...`) のみで実害はなく、コメント済み。48bit を超える authority を返すサーバは事実上存在しないため、
現状維持でよい (本項は記録のみ)。

## 優先度

- A/B とも管理系 smbclient 向けで、browse/GUI (obaket) の MVP には不要。
- B (write) の需要が出た時に read-modify-write + 自ロックアウト guard の設計から着手する。
- A は well-known SID 静的テーブルの軽量版だけ先行する余地あり (低コスト)。
