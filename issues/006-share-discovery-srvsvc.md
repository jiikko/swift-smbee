# 006 feature: share discovery を SRVSVC over IPC$ で実装する

状態: **open**
起票: 2026-06-30
関連: `todo.md` / `Sources/SMBee/SMBClient.swift` / `Sources/smbcli/SMBCLI.swift`

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

- [ ] `SMBee.listShares` / `SMBClient.listShares` / `smbcli shares` がある。
- [ ] Samba E2E で `public` share が列挙できる。
- [ ] macOS SMBX 手動 smoke で少なくともユーザーの home share が列挙できる。
- [ ] DCE/RPC bind と `NetrShareEnum` response の unit fixture がある。
- [ ] guest/anonymous を許すか、認証必須にするかの policy が docs に記録されている。
