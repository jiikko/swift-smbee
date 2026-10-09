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

- [x] `../\u{0301}y` などの入力が `SMBPath` で拒否される unit test（`SMBPathSeparatorTests`。`a\\\u{0301}..` は下の訂正のとおり受理が正しい）
- [x] サーバの扱いの実測を本文に書く（下の「実測」）

## 実測（2026-10-09、container の Samba = `ubuntu:24.04` の distro 版、smb311-signing-required）

`SMBPathSeparatorE2ETests` が raw の CREATE（FILE_CREATE、署名つき）で名前をそのまま送って測った。`bin/e2e/container-samba.sh` の
smb311-signing-required でだけ走る（暗号化の profile では raw packet を送る既存の経路 `validateNegotiateWireTransactionForTesting` が使えない）。

| 送った名前（probe の下） | status | できた場所 |
|---|---|---|
| `x\plain`（対照） | 0 | `x` の中 |
| `x/\u{0301}y` | 0 | `x` の中に `\u{0301}y`（`/` は結合文字の直前でも区切り） |
| `x\\\u{0301}z` | 0 | `x` の中に `\u{0301}z` |
| `x\\../\u{0301}w`（旧 normalize が素通しした形） | 0 | **probe の直下に `\u{0301}w`**（隠れた `..` が share の中で 1 つ上へ解決した） |
| share root で `../\u{0301}…`（share の外へ） | 0xC000003B（STATUS_OBJECT_PATH_SYNTAX_BAD） | 作られない |

影響: 旧実装では、結合文字で隠した `..` で share の中を遡れた（copy の「コピー先がコピー元の中か」の判定や、ディレクトリに閉じた再帰操作の前提が崩れる）。
share の外へは Samba が拒否する。Windows / macOS SMBX は未実測。

## 訂正

- 受け入れ条件の `a\\\u{0301}..` は、scalar で分けると `a` と `\u{0301}..` になり、後者は `..` ではない正当な名前なので**受理が正しい**。
  拒否すべき例は `a\\..\\\u{0301}b` / `x\u{0600}/..` / `a\u{0600}\\..`
- `/` の隠蔽は SMBPath だけでなく、`SMBShareName`・entry 名の検査・URL の path component・copy の内側判定・DFS・TREE_CONNECT・
  `directoryEntry(matching:)`・smbcli の相対パスと親ディレクトリの作成にもあった（`hasPrefix` も書記素境界で判定するので同じ穴）

## 進捗

- 2026-10-09: commit `fix(path): issue 103 — path の区切りを Unicode scalar で判定し、結合文字で隠れた `..` を拒否する`
  - 区切りの判定を `SMBPathSeparator`（scalar 単位）に一本化し、上の全箇所を寄せた。smbcli へは `package` 可視性の転送メソッドで出す
  - SwiftLint の custom rule `no_character_based_smb_path_separator`（error）で Character 単位の判定を止める。検出しない形は `.swiftlint.yml` のヘッダ
  - 検証: macOS の unit 711 件・Linux container（swift:6.2）の unit 718 件が green、strict lint / lint-analyze 0 件、signing profile の E2E が green
- 範囲外として記録（直していない）: DFS の直接入口 `SMBSession.dfsReferral(share:path:)` と `resolveDFS` の解決結果には `.` / `..` の検査そのものが無い
  （区切りの隠蔽ではなく既存の穴。設計の敵対レビューの指摘）
- 残り: 実装後のレビュー（回帰・壊す・素通り）、smbcli の変更箇所（相対パス・親ディレクトリの作成・glob の切り出し）のテスト、変異検証、smoke、push
  - 2026-10-09 10:10: レビューの 3 本が codex の 5h 枠切れで出力の途中に止まった。12:37 のリセット後に再開する
