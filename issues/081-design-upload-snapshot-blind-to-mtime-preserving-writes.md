# 081 design: upload の SMBLocalFileSnapshot 照合は mtime 保存書き込みを検出できない (既知の限界の明文化 + ctime 追加の評価)

状態: **open**
起票: 2026-08-21
種別: `design` (P3。既知の限界の明文化が主。検出強化は評価してから)
起源: obaket issue 542 (upload ソース同一性設計) の敵対的レビューで、参照実装として
SMBee を精査した際に見つかった盲点の横展開

## 問題

`SMBClientSession.upload(path:fileURL:)` は `SMBLocalFileSnapshot` (`SMBClient.swift:17-40`,
fstat の `st_dev` / `st_ino` / `st_size` / `st_mtimespec`) を転送前後で照合し、転送中の
ソース書き換えを `local source file changed during upload` で loud に検出する — この設計自体は
正しい (obaket 542 が参照実装として採用)。ただし以下は**素通り**する:

1. **mtime 復元書き込み**: 内容を書き換えた後 `utimes` / `touch -r` で mtime を戻すツール
   (rsync `-t --inplace`、backup 復元系)。size 同一 + mtime 復元で 4 フィールド全一致
2. **mmap(MAP_SHARED) 経由の書き換え**: POSIX 上 mtime 更新は「write reference 〜次の
   msync のどこか」としか規定されず、msync まで遅延しうる (macOS での遅延幅は実測未確認)
3. **mtime 粒度の粗い FS 上のソース**: exFAT/FAT (2 秒) 等では同粒度窓内の再保存が同値になる

また同一 handle への再 fstat では **dev/ino は恒真** (fd は vnode に固定される) なので、
検出シグナルの実体は size + mtime の 2 つだけ。dev/ino をフィールドに持つこと自体は無害だが、
「replacement を検出している」わけではない (replacement は fd 保持自体が旧 inode を読み続ける
ことで無害化している)。

## 対応方針 (案)

1. **まず限界をコードコメントに明文化する** (最低限。`SMBLocalFileSnapshot` の docstring に
   「検出は best-effort。mtime 保存書き込み / mmap / 粗粒度 FS は素通りする」を残す)
2. **`st_ctime` の追加を評価する**: ctime はユーザーが `utimes` で復元できない
   (utimes 自体が ctime を進める) ため 1 の mtime 復元を潰せる。**トレードオフ**: ctime は
   chmod / xattr 変更 (Finder タグ、quarantine 属性) でも進むため、転送中の無害なメタデータ
   操作が spurious fail になる。upload の所要時間内に Finder が xattr を触る頻度を見てから
   採否を決める (blind に足さない)
3. 完全に塞ぐには content checksum が要るが、SMB upload の性能特性に直結するので
   本 issue のスコープ外 (必要になったら別 issue)

## 受け入れ条件

- [ ] `SMBLocalFileSnapshot` の docstring に検出限界が明記されている
- [ ] ctime 追加の採否が評価され、採用時は「xattr/chmod で spurious fail する」ことを
      テストで pin、不採用時は理由をコメントで残す

## 関連

- `Sources/SMBee/SMBClient.swift` — `SMBLocalFileSnapshot` / `upload` の照合点 (`:1429`, `:1433`)
- obaket `issues/542-design-upload-source-integrity-and-file-lock.md` — 本盲点の発見元。
  obaket 側は同じ token 設計を採るため同じ限界を「既知の限界」節に記載済み

## レビュー記録

- 2026-08-21: codex は usage limit のため未レビュー (解除後に反証レビューを通す)。
  file:line は obaket セッションの main agent が実コードで裏取り済み
