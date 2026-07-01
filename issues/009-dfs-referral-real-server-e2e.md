# 009 test: DFS referral を実 msdfs サーバで E2E 検証する

状態: **open** (backlog)
起票: 2026-07-01
関連: `Sources/SMBee/SMB2DfsReferral.swift` / `Sources/SMBee/SMBClient.swift` (`dfsReferral`) /
`bin/e2e/container-samba.sh` / `test/e2e/smb/` / [todo.md](../todo.md) 「symlink / reparse point / DFS referral」

## 背景

`FSCTL_DFS_GET_REFERRALS` による DFS referral 取得を実装した (commit `3e21a34`)。REQ_GET_DFS_REFERRAL
encode + RESP_GET_DFS_REFERRAL (V3/V4) decode + `SMBee.dfsReferral` / `smbcli dfs`。

**ただし実 msdfs サーバが手元に無く、検証は MS-DFSC 準拠の unit fixture + parser 精読のみ**で、
**実サーバの wire response では未検証**。他の protocol 実装 (T309 volume info / T319 QUERY_SECURITY) は
実 Samba で wire を確認済みなのに対し、DFS だけ「実サーバ未検証」で残っている。

codex-drive の既知弱点「循環テスト green でも実サーバが拒否する」を DFS では潰せていないため、
実サーバ E2E で裏取りしたい。

## やること

1. **Samba msdfs profile を追加** (`test/e2e/smb/smb-msdfs.conf` 等):
   - `[global]` に `host msdfs = yes`、共有に `msdfs root = yes`。
   - 共有内に msdfs link を作る: `ln -s "msdfs:<targetserver>\\<targetshare>" <linkname>`
     (Samba は symlink の値で referral target を表現する)。
   - `bin/e2e/container-samba.sh` がこの profile と link を用意できるよう拡張
     (既存 profile と同様に container 内 Samba 起動 + 共有準備)。
2. **E2E test を追加** (`Tests/SMBeeTests/SMBeeE2ETests.swift`, SMBEE_E2E gate):
   - `SMBee.dfsReferral(path: "\\<host>\<msdfsroot>\<link>")` を呼び、
     `referrals` が 1 件以上 / `networkAddress` が用意した target を指す、を assert。
   - msdfs 未設定 profile では skip 可能な形にする (他 profile を壊さない)。
3. parser が実 Samba の V3/V4 (または Samba が返す version) を正しく解釈するか確認し、
   ズレがあれば `SMB2DfsReferral.decodeResponse` を修正。

## 補足 / 未検証で残っているその他

- **symlink target 解決** (`FSCTL_GET_REPARSE_POINT`): reparse tag (種別) は取得できるが、symlink の
  実際の target path は未取得。DFS E2E とは別だが、reparse 系の「実サーバ検証」として併せて検討余地あり。
- **NameListReferral (DC referral) format**: 現状 best-effort で string parse を skip している。
  DC referral を返す構成での挙動は未確認。

## 優先度

- DFS は管理系 / エンタープライズ機能で、browse/GUI (obaket) の MVP には不要。
- ただし「実 wire 未検証」は本ライブラリで DFS だけの状態なので、Samba を触る機会に msdfs profile を
  足して E2E を通し、他項目と同水準 (実サーバ検証済み) に揃えるのが望ましい。
