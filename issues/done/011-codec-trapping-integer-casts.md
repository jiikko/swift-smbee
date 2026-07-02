# codec の trapping integer cast（長大入力で fatalError クラッシュ）

- 種別: bug (robustness / crash surface)
- 発見: 2026-07-03 サブエージェントレビュー → main agent で code 裏取り済み。codex レビューは usage limit のため未実施 (要: 後日 codex-review)

## 症状

encoder が `Int` 長を `UInt16(...)` の trapping initializer で直接 cast している。
上限超過時に `SMBCodecError` を throw せず **プロセスが fatalError で落ちる**。

確認済み箇所（`Sources/SMBee/SMB2ReadCodecs.swift`）:

- `SMB2TreeConnect` 系: `UInt16(pathBytes.count)`
- `SMB2Create.encodeRequest`: `UInt16(nameBytes.count)` — 32K 文字超の remote path 名
  （巨大 share の traversal で他者が作った名前を再 encode する経路）で到達しうる
- SET_INFO security: `UInt16(aclSize)` — ACE 数が多い DACL の read-modify-write

`Sources/SMBee/DCERPC.swift` にも同類の `UInt16(16 + body.count)` があるが、
現用途 (share enum) では 64KB 超 stub に到達しにくい。

## 対応 (2026-07-03 完了)

- `SMBByteWriter.writeUInt16LE(count:of:)` (range-checked, `SMBCodecError.invalidValue` を throw)
  を追加し、可変長 count の全 call site (CREATE name / TREE_CONNECT path / SESSION_SETUP blob /
  ACL・ACE / DCE/RPC fragment / NTLM security buffer / NEGOTIATE dialect・salt・context /
  LOCK element) を置換。
- SwiftLint custom rule `no_trapping_uint16_length_cast` (error) を追加し再発を build 時に阻止。
- 回帰 unit: `testEncoderRejectsOversizedVariableLengthFieldsInsteadOfTrapping`
  (>32K 文字 path の CREATE encode が throw する)。

## 対応方針（案・当初）

- 共通ヘルパー（例: `SMBByteWriter.writeUInt16LE(checked: Int) throws`）を導入し、
  範囲超過は `SMBCodecError.invalidValue` として throw する。
- SMBPath validation 側で path 長上限（UTF-16 バイト長 ≤ 65535、実質はもっと小さい
  server 制限）を先に弾くのも可。
- 再発防止: SwiftLint custom rule で `writeUInt16LE(UInt16(` パターンを警告できないか検討。

## メモ

decoder 側の offset 演算は境界検証済み（既存レビューで確認）。問題は encoder 側の cast のみ。
