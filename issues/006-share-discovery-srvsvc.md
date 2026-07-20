# 006 feature: share discovery を SRVSVC over IPC$ で実装する

状態: **実装済み。macOS SMBX 手動 smoke 待ち**
起票: 2026-06-30
関連: `todo2.md` / `Sources/SMBee/SMBClient.swift` / `Sources/smbcli/SMBCLI.swift`

## 背景

`smbcli shares smb://host` / `SMBee.listShares(...)` 相当の API が欲しい。現状は share 名を既知として
`TREE_CONNECT` する前提で、サーバ上の共有一覧を取得できない。

SMB2/3 の通常 command set だけでは share enumeration はできない。現実的な実装経路は
`IPC$` へ `TREE_CONNECT` し、`srvsvc` named pipe に対して DCE/RPC を流し、
SRVSVC `NetrShareEnum` の response を NDR decode する形になる。

## 必要な実装単位

- `IPC$` tree connect と named pipe open (`\\srvsvc`)。
- named pipe 向け READ/WRITE または IOCTL 経路の fixture。
- DCE/RPC bind PDU / request PDU / response PDU codec。
- SRVSVC interface UUID / version / opnum `NetrShareEnum`。
- `SHARE_INFO_1` または `SHARE_INFO_502` の NDR decode。
- macOS SMBX / Samba / Windows Server での packet fixture と互換性確認。
- 公開 API:
  - `SMBee.listShares(host:port:credential:)`
  - `SMBClient.listShares(...)`
  - `smbcli shares smb://user@host[:port]`

## リスク

- macOS SMBX と Samba で SRVSVC の対応範囲や guest/anonymous 挙動が異なる可能性がある。
- `IPC$` 接続後の signing/encryption policy が通常 share と異なる可能性がある。
- share name だけでなく type/comment/hidden share (`$`) をどう返すか API 設計が必要。
- DCE/RPC/NDR codec は今の SMB2 codec より scope が大きいため、fixture なしで実装すると退行検出が弱い。

## 完了条件

- [x] `SMBee.listShares` / `SMBClient.listShares` / `smbcli shares` がある。
- [x] Samba E2E で `public` share が列挙できる。
- [ ] macOS SMBX 手動 smoke で少なくともユーザーの home share が列挙できる。
- [x] DCE/RPC bind と `NetrShareEnum` response の unit fixture がある。
- [x] guest/anonymous を許すか、認証必須にするかの policy が docs に記録されている。

## 実装メモ (2026-06-30)

API / CLI の入口は追加済み。ただし本体の SRVSVC は未実装のため、
`SMBError.unsupported(status: 0, operation: "SHARE_DISCOVERY_SRVsvc")` を返す。
次は DCE/RPC bind と SRVSVC `NetrShareEnum` の fixture を用意してから実 wire path を実装する。

## 実装メモ (2026-06-30 追記)

- `IPC$` へ TREE_CONNECT し、`srvsvc` named pipe を CREATE。
- DCE/RPC unauthenticated bind で SRVSVC interface
  (`4b324fc8-1670-01d3-1278-5a47bf6ee188`, v3.0) + NDR v2.0 を negotiate。
- `NetrShareEnum` opnum 15、Level 1 (`SHARE_INFO_1`) を要求し、`name/type/comment` を
  `SMBShareInfo` として decode。
- API/CLI は既存の `SMBCredential` を必須とする。guest/anonymous share discovery は現時点では
  未サポートで、認証 backend 拡張時に別途扱う。
- Unit fixture: DCE/RPC bind PDU、bind_ack parse、NetrShareEnum request、SHARE_INFO_1 response decode。
- Samba E2E: `SMBee.listShares` で `public` を assert。CLI smoke は
  `smbcli shares smb://smbee@host:port | grep -Fx public`。
