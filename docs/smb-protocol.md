# SMB protocol — implementation references for SMBee

SMBee が実装する SMB の wire 仕様と、その一次ソースをまとめる。実装者（人間 / AI）は
本書ではなく **一次ソース（下記）を正本**とすること。本書は地図であり、値・構造体の
正確な定義は必ず spec で確認する。**ⓥ = 実装前に spec で要確認**。

## SMB は RFC か？

いいえ。SMB は Microsoft のプロトコルで、正本は公開された **Microsoft Open
Specifications**。周辺の暗号・交渉メカニズムの一部だけが IETF RFC / NIST にある。

### 一次ソース（Microsoft Open Specifications）

すべて公開・無償。`https://learn.microsoft.com/en-us/openspecs/windows_protocols/<id>/`。

| ID | 内容 | SMBee での用途 |
|----|------|----------------|
| **MS-SMB2** | SMB 2/3 プロトコル本体（メッセージ構文・交渉・署名・暗号化・key derivation） | 中核。NEGOTIATE / SESSION_SETUP / TREE_CONNECT / CREATE / READ / WRITE / QUERY_DIRECTORY / QUERY_INFO / SET_INFO / CLOSE、3.1.1 の preauth integrity・signing・encryption |
| **MS-NLMP** | NTLM 認証（NTLMv2 応答計算・AV pair・MIC） | SESSION_SETUP の認証 |
| **MS-SPNG** | SPNEGO（GSS-API 交渉）の Microsoft 拡張 | SESSION_SETUP の security buffer 包装 |
| **MS-DTYP** | Windows データ型（FILETIME・GUID・SID 等） | 構造体のフィールド型 |
| **MS-ERREF** | Windows エラーコード（NTSTATUS） | error mapping |
| MS-SMB / MS-CIFS | SMB1 / CIFS（レガシー） | **スコープ外**（SMB1 は提示しない） |
| MS-FSCC | File System Control Codes / FileInformation クラス | QUERY_INFO / SET_INFO / QUERY_DIRECTORY の information class |

### 周辺標準（IETF / NIST）

| 仕様 | 内容 | 用途 |
|------|------|------|
| RFC 4178 | SPNEGO（GSS-API negotiation） | SESSION_SETUP |
| RFC 1320 | MD4 | NT hash（swift-crypto に無いので自前 / micro-lib） |
| RFC 2104 | HMAC | HMAC-MD5（NTLMv2）/ HMAC-SHA256（KDF） |
| NIST SP 800-108 | KDF（counter mode） | SMB 3.x の鍵導出 |
| NIST SP 800-38D | GCM / GMAC | 3.1.1 の encryption(GCM)・signing(GMAC) |
| RFC 4493 / RFC 3610 / NIST SP 800-38C | AES-CMAC / AES-CCM | 3.0.2 の signing(CMAC)・encryption(CCM)。in-repo pure-Swift 実装で扱う |
| RFC 1001 / 1002 | NetBIOS | direct TCP 445 の 4 byte length header はこれ由来（445 では name service は使わない） |

## MVP スコープ（SMBee）

- **transport**: direct TCP、**port 445**、各 SMB2 メッセージの前に **4 byte の big-endian length**（最上位 byte は 0）。NetBIOS session service は使わない。
- **dialect**: **SMB 3.0.2 と SMB 3.1.1 の両対応**。macOS SMBX の実上限は 3.0.2
  （macOS 26.5.1 でも 0x0302 が上限）、Samba 等は 3.1.1 を想定。
- **auth**: **NTLMv2**（SPNEGO 包装）。**Kerberos は対象外**。
- **signing / encryption**: negotiated dialect 依存。
  - **3.1.1**: AES-128-GMAC / AES-128-GCM（swift-crypto）。
  - **3.0.2**: AES-CMAC / AES-128-CCM（in-repo pure-Swift 実装）。Linux ビルド維持が条件。
- **対象サーバ**: **macOS の SMB サーバ（SMBX、実上限 3.0.2）**。Samba は E2E / 互換確認対象。

## 接続ライフサイクルと実装する command

```
TCP connect :445
 └ NEGOTIATE        … dialect 3.0.2 / 3.1.1 を提示（3.1.1 用 negotiate contexts 付き）
     └ SESSION_SETUP … SPNEGO+NTLMv2 (type1 → CHALLENGE(type2) → type3)。複数往復
         └ TREE_CONNECT … \\host\share へ接続 (share = namespace)
             └ CREATE → {READ | WRITE | QUERY_DIRECTORY | QUERY_INFO | SET_INFO} → CLOSE
```

実装順（issue/Phase は obaket 側 tracker 管理。本 repo では下記の通り）:

1. **probe**: TCP + NEGOTIATE + 応答 parse → 交渉された dialect / signing / cipher / preauth hash を表示
2. **read**: SESSION_SETUP(NTLMv2) → TREE_CONNECT → CREATE → QUERY_DIRECTORY(list) / QUERY_INFO(stat) / READ(range)
3. **write**: CREATE(disposition) + WRITE / mkdir(CREATE dir) / rename(SET_INFO FileRenameInformation) / delete(SET_INFO FileDispositionInformation)

### SMB URL / path handling

公開 API の `path` は share ルートからの相対 SMB path とし、区切りは `\` を使う。CLI の
`smb://user[:password]@host[:port]/share/path` 入力では URL path の `/` を SMB path 区切りへ変換する。

- share 名と path component は URL component ごとに percent decode する。
- `.` / `..` component は受け付けない。SMB サーバ上の正規化に依存して share root 外へ出る解釈を避ける。
- decoded component に `/` または `\` が含まれる場合は受け付けない。区切り文字は URL の `/` だけを構造として扱う。
- user / password も percent decode する。secret は debug log に出さない。

Unicode normalization はサーバ実装差があり得るため、現時点では入力文字列を追加正規化せずそのまま
UTF-16LE encode する。macOS SMBX / Samba での NFC/NFD 実測は compatibility matrix 側で扱う。

### NEGOTIATE（3.1.1）の negotiate contexts ⓥ

3.1.1 では NEGOTIATE に **negotiate context** を付ける（MS-SMB2 の NEGOTIATE 節）:

- **SMB2_PREAUTH_INTEGRITY_CAPABILITIES**: hash algorithm = **SHA-512**、salt
- **SMB2_ENCRYPTION_CAPABILITIES**: ciphers（**AES-128-GCM** / AES-256-GCM / AES-128-CCM の優先順）
- **SMB2_SIGNING_CAPABILITIES**: signing algorithms（**AES-GMAC** / AES-CMAC）

応答で server が選んだ hash / cipher / signing algo を読み、3.1.1 では SHA-512 + GCM + GMAC を検証する。
3.0.2 では negotiate contexts は返らず、signing/encryption は CMAC/CCM 系として扱う。

### SMB2 メッセージ構文 ⓥ

- **SMB2 packet header（sync）= 64 byte**。`ProtocolId(0xFE 'S' 'M' 'B')` / `StructureSize=64` /
  `Command` / `MessageId` / `SessionId` / `TreeId` / `Signature(16B)` / flags など。正確な
  オフセットは MS-SMB2 の packet header 節を参照。
- 各 command の request/response 構造（`StructureSize` 先頭、可変長 buffer の offset/length 方式）も
  MS-SMB2 のメッセージ構文節を参照。**buffer の offset は SMB2 header 先頭からの byte**。

### NTLMv2（MS-NLMP）ⓥ

- 3 メッセージ: NEGOTIATE_MESSAGE(type1) → CHALLENGE_MESSAGE(type2) → AUTHENTICATE_MESSAGE(type3)。
- 文字列は **UTF-16LE**。
- 鍵計算（概略。正確な手順は MS-NLMP）:
  - `NTOWFv2 = HMAC-MD5( MD4(UTF16LE(password)), UTF16LE( Uppercase(user) + domain ) )`
  - `NTProofStr = HMAC-MD5( NTOWFv2, serverChallenge + temp )`、temp に timestamp / clientChallenge / **AV pair(target info)** を含む
  - **MIC**（type3 全体の HMAC-MD5）を AV pair に応じて埋める
- session base key から SMB3 の key derivation に渡す。

### SMB 3.1.1 の crypto framing（MS-SMB2）ⓥ

ここが自作の難所。swift-crypto は **primitive（GCM/HMAC/SHA）**を提供するが、**どう適用するか
（framing）は SMB 固有**で自作する:

- **preauth integrity**: NEGOTIATE と SESSION_SETUP の全メッセージを順に **SHA-512 で running hash**
  した transcript（PreauthIntegrityHashValue）。途中で 1 byte でも取り違えると以降の鍵が全部壊れる。
- **key derivation（SP 800-108 counter mode, HMAC-SHA256）**: 3.1.1 の label / context ⓥ
  （MS-SMB2 で確認。代表値: label `"SMBSigningKey"` / `"SMBC2SCipherKey"` / `"SMBS2CCipherKey"` /
  `"SMBAppKey"`、context = preauth integrity hash）。3.0/3.0.2 とは label が違う。
- **signing = AES-128-GMAC**: メッセージに対する GMAC。swift-crypto の AES-GCM を「平文 0・AAD=メッセージ」
  の MAC として使えるか要検証。
- **encryption = TRANSFORM_HEADER + AES-128-GCM**: transform header（nonce / original message size /
  flags / signature(tag)）の後に GCM 暗号文。nonce 長・AAD 範囲・tag の置き場は SMB 固有 ⓥ。

### NTSTATUS（MS-ERREF）— error mapping の主要コード ⓥ

代表値（**正本は MS-ERREF。実装時に値を確認**）:

| NTSTATUS | 値（要確認） | 意味 / 扱い |
|----------|------|------|
| STATUS_SUCCESS | 0x00000000 | 成功 |
| STATUS_PENDING | 0x00000103 | 非同期継続（エラーではない） |
| STATUS_MORE_PROCESSING_REQUIRED | 0xC0000016 | SESSION_SETUP 継続（type2 待ち） |
| STATUS_NO_MORE_FILES | 0x80000006 | QUERY_DIRECTORY 終端 |
| STATUS_LOGON_FAILURE | 0xC000006D | 認証失敗 |
| STATUS_ACCESS_DENIED | 0xC0000022 | 権限なし |
| STATUS_OBJECT_NAME_NOT_FOUND | 0xC0000034 | not found |
| STATUS_OBJECT_PATH_NOT_FOUND | 0xC000003A | path not found |
| STATUS_OBJECT_NAME_COLLISION | 0xC0000035 | FILE_CREATE で既存 |
| STATUS_SHARING_VIOLATION | 0xC0000043 | open handle 競合 |
| STATUS_DIRECTORY_NOT_EMPTY | 0xC0000101 | 非空 dir 削除 |
| STATUS_FILE_IS_A_DIRECTORY | 0xC00000BA | type mismatch |
| STATUS_NOT_A_DIRECTORY | 0xC0000103 | type mismatch |
| STATUS_DISK_FULL | 0xC000007F | 容量不足 |
| STATUS_NETWORK_NAME_DELETED | 0xC00000C9 | share 消失 / セッション切れ |

## 実装と検証の指針

- **test vector を並行で書く**: NTLMv2（MS-NLMP / RFC のベクタ）/ MD4（RFC1320）/ GMAC・GCM（NIST）/
  KDF / preauth transcript / SMB2 packet round-trip。primitive が通っても **SMB framing が正しいとは
  限らない**ので packet-level fixture（pcap or 既存実装由来）も用意する。
- **probe で交渉結果を先に観測**してから auth/crypto を実装すると、macOS SMBX の 3.0.2 上限や
  Samba の 3.1.1 挙動を早期に確定できる。
- secret（password / NT hash / session key）は log に出さない。
