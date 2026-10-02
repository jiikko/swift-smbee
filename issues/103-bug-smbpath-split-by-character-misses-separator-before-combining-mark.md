# 103 (bug): `SMBPath.normalize` が `/` と `\` を Character 単位で探すので、結合文字が続く区切りを見落とし、`..` の拒否をすり抜ける

起票日: 2026-10-02

出典: obaket issue 1022 (path の `/` の分割が Character 単位で、結合文字が続く `/` を見落とす) の調査 (codex gpt-6.1-sol / medium、2026-10-02)。

## 問題

`SMBPath.normalize` (`Sources/SMBee/SMBPath.swift`) は `split(whereSeparator: { $0 == "/" || $0 == "\\" })` で Character を比べる。
Swift では `/` や `\` の直後に結合文字 (U+0301 など) が来ると、区切りとその結合文字が 1 つの Character になり、区切りとして見えない。
そのため `../\u{0301}y` は 1 つの component `../́y` として扱われ、`. / ..` の拒否を通る。

obaket で 2026-10-02 に実測した事実 (Swift。`SMBPath` そのものではなく同じ書き方で):
- `"x/../\u{0301}y".split(separator: "/")` は `["x", "../́y"]`。`unicodeScalars` で分けると `["x", "..", "́y"]`
- `/` の前の Prepend (U+0600) でも同じく区切りが消える

## 未確認

- この `SMBPath` を通した名前を、SMB サーバ (Samba / Windows) がどう扱うか。`/` を区切りとして受けるのか、名前に使えない文字として拒否するのか (`STATUS_OBJECT_NAME_INVALID` 等)。**まずここを実測する**
- `\` の直後に結合文字が来る場合も同じか

## 対応方針

- 区切りを Unicode scalar (`unicodeScalars`) で探す形にする。分けた後の component は String に戻し、比較は今のまま
- obaket 側の helper (issue 1022 の `PathSeparator`) と同じ考え方に揃える

## 受け入れ条件

- [ ] `../\u{0301}y` / `a\\\u{0301}..` 相当の入力が `SMBPath` で拒否される unit test
- [ ] サーバの扱いの実測を本文に書く
