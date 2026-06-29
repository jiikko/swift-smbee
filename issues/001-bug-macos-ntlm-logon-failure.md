# 001 bug: 実 macOS SMBX サーバへ NTLMv2 接続すると STATUS_LOGON_FAILURE

状態: **解決済み (2026-06-30)。実 macOS SMBX へ NTLMv2 認証成功・ls 再現性あり**

## 解決サマリ (サーバ側 smbd/digest-service ログを oracle にして確定)

サーバ側で SMB 共有を有効化 (NT ハッシュ provision) した後、**NTLMv2 実装の 3 バグ**が判明。
いずれも「Samba は許容するが実 macOS/Heimdal は厳格に検証する」ため Samba E2E では露見しなかった。
サーバログで段階的に確定: `verify ntlm2 hash failed` → (1)(2)修正で `kdc: ok` →
`GSS_S_DEFECTIVE_TOKEN` → (3)修正で認証成功。

1. **NTLMv2 blob ヘッダのバイト順** (`NTLM.swift`): `writeUInt32LE(0x0101_0000)` が wire 上 `00 00 01 01`
   になっていた。正しくは `01 01 00 00` (RespType=1/HiRespType=1)。`writeBytes([0x01,0x01,0x00,0x00])` に修正。
2. **AvPairs (EOL 込み) の後の trailing Z(4) 欠落**: EOL の 0 と混同して条件スキップしていた。常に付与。
   → (1)(2) で Heimdal の NTLMv2 proof 検証 (`verify ntlm2 hash`) が通過。
3. **SPNEGO mechListMIC の欠落 + checksum 未シール**: negTokenResp に `[3] mechListMIC` を付与し、
   さらに `NTLMSSP_NEGOTIATE_KEY_EXCH` 時は checksum を **sealing key の RC4 stream で暗号化**する
   (平文 HMAC だと `GSS_S_DEFECTIVE_TOKEN`)。→ 認証成功。

付随修正 (smbutil の wire と一致させた、いずれも MS-NLMP 準拠): EPA AV pair (id6 MsvAvFlags / id9
MsvAvTargetName=`cifs/<host>` / id10 ChannelBindings)、timestamp 有り時の LmChallengeResponse=Z(24)、
blob TimeStamp にサーバ MsvAvTimestamp を使用、type3 flags の SEAL クリア、ClientSigningKey/SealingKey 導出。

検証: 実 macOS server (169.254.69.111 / 127.0.0.1) へ `smbcli ls` 成功 (再現性あり)。unit 59 tests green
(flaky な transport cancellation test も deterministic 化)。NTLM ベクタは独立計算で裏取り。

---

## 以下は調査経緯 (参考・解決前の記録)

発生: 2026-06-29
対象サーバ: macOS SMBX (`ms.local`, link-local `169.254.69.111`, bridge0 経由)
再現: `SMB_PASSWORD=koji swift run smbcli ls smb://koji@169.254.69.111/koji`
→ `Error: logonFailure(status: 3221225581 = 0xC000006D STATUS_LOGON_FAILURE, operation: "SESSION_SETUP")`

## 症状

SMBee (`smbcli`) が実 macOS サーバへ NTLMv2 認証すると SESSION_SETUP で `STATUS_LOGON_FAILURE`。
一方 Samba 相手の E2E は署名(CMAC)+暗号(CCM)込みで全 green。

## 調査で確定した 2 つの独立した原因

### 原因 1 (サーバ側): macOS ローカルアカウントは既定で SMB NT ハッシュを持たない

macOS は GUI ログインユーザーを **LKDC Kerberos** で認証するため、ローカルアカウントの
**SMB(NTLM) 用 NT ハッシュが provision されていない**ことがある。この状態では:

- 通常の Finder 接続は成功する（GUI セッションが持つ LKDC チケット経由。**パスワード認証ではない**）。
- ゲスト/匿名アクセスも有効（`smbutil -G/-N` で共有一覧が出る）。
- しかし **NTLM パスワード認証は拒否**される（Apple 純正 `smbutil` を sudo=keychain/Kerberos なしで
  動かしても、SMBee と同じく `Authentication error`）。

#### 観測による切り分け（重要: 安易な「Finder で繋がる=NTLM が通る」を否定した）

| 観測 | 結論 |
|---|---|
| `smbutil` がユーザー文脈で**間違ったパスワードでも成功**、Kerberos チケットも新規に立たない | 成功は LKDC/キャッシュセッション経由で NTLM ではない |
| `klist` に `cifs/…@LKDC:SHA1…` チケット | GUI ユーザーは Kerberos で認証 |
| `kdestroy -A` 後の新規 mount_smbfs は**ユーザー文脈でも** `Authentication error` (wire: NTLM type1/2/3, AP-REQ=0) | チケットが無いと NTLM に転落し拒否される＝NTLM パスワードは通らない |
| 同条件の Apple smbutil(root) も SMBee も拒否 | クライアントのバグではなくサーバ側条件 |

#### 対処

サーバ `ms.local` で **System Settings → 一般 → 共有 → ファイル共有 → ⓘ → オプション →
「SMB を使用して共有」を ON にし、対象アカウント(koji)にチェック＋パスワード再入力**。
これで NT ハッシュが保存され NTLM 認証が有効になる。
（有効化後、Apple smbutil(root, genuine NTLM) が `koji:koji` で認証成功することを確認済み。）

### 原因 2 (クライアント側): type3 に EPA AV pair が欠落していると macOS は MIC を検証できず拒否

サーバ側 NTLM を有効化した後も SMBee は拒否されたため、**受理される Apple smbutil の type3 と
SMBee の type3 を wire でフィールド比較**した結果、欠落フィールドが判明:

| field | 受理 (smbutil) | 拒否 (SMBee HEAD) |
|---|---|---|
| AV `id=6` MsvAvFlags (MIC present=0x02) | あり | **欠落** |
| AV `id=9` MsvAvTargetName (`cifs/<host>`) | あり | **欠落** |
| AV `id=10` MsvAvChannelBindings (16 zero) | あり | **欠落** |
| MIC フィールド | あり (検証される) | あり (だが id=6 未設定で**検証されない/必須未充足**) |
| domain / workstation | `MS` / `AIR5` | 空 / 空 |

HEAD は MIC フィールドを書くのに `MsvAvFlags(0x2)` を立てておらず、macOS が MIC を検証できない
（あるいは EPA で channel binding を必須としている）。

#### 修正方針

`NTLM.makeType3` に `serverName`(=接続先 host) を渡し、MIC 経路で NTLMv2 blob の TargetInfo EOL 直前に
`id=6 (0x02)` / `id=9 (UTF16LE "cifs/"+host)` / `id=10 (16 zero)` を挿入。NTProofStr と MIC は
拡張後の blob/message 全体で計算する。type3 の user 欄は username をそのまま（NTOWFv2 計算のみ uppercase）。

→ 実装済み (codex) + 後続で下記 2 件も修正。ただし**いずれも単独では LOGON_FAILURE が続いた**。

### 原因 2 の内訳 (wire 差分で 1 つずつ確定)

NTLM 有効化後、受理される smbutil type3 と SMBee type3 を wire 比較しながら 1 項目ずつ潰した:

| # | 差分 | 状態 | 根拠 |
|---|---|---|---|
| 2a | EPA AV pair (id=6/9/10) 欠落 | 修正済 | smbutil は送る |
| 2b | **LmChallengeResponse が非0** | 修正済 | MS-NLMP 3.1.5.1.2: timestamp 有り時は Z(24)。smbutil は 24 byte 0 |
| 2c | **blob TimeStamp に currentNTTime() を使用** | 修正済 | server の MsvAvTimestamp を使うべき。offline 照合で smbutil は server 値を使用 |
| 2d | type3 domain が空 | 要 `--domain MS` | offline proof 照合で本アカウントの NTOWFv2 domain は **MS** (NetBIOS domain)。空だと proof 不一致 |
| **2e** | **SPNEGO mechListMIC ([3]) 欠落** | **← 真の決定打 (実装中)** | 下記 |

### 2e: SPNEGO mechListMIC が真の root cause

offline 照合で **NTProofStr は完全に正しい** (smbutil と同じ NTOWFv2(user=koji, domain=MS) で proof
一致) と確定。にもかかわらず拒否されたため type3 fields 以外を疑い、**SESSION_SETUP#2 の SPNEGO
negTokenResp 構造**を wire 比較した:

- 受理 (smbutil): NTLM type3 の直後に **`a3 12 04 10 | 01000000 7e1eee9546d510a1 00000000`**
  = ASN.1 `[3] mechListMIC` (OCTET STRING 16 byte = NTLMSSP signature: version `01000000` +
  checksum 8 byte + seqnum `00000000`)。
- 拒否 (SMBee): type3 の後に **何もない** (mechListMIC 欠落)。

**macOS SMBX は SPNEGO mechListMIC を必須にし、Samba は要求しない** → Samba E2E は通り実 macOS のみ落ちる
症状の正体。mechListMIC = NTLM の GSS MakeSignature (extended session security, seqnum 0) を
**初回 negTokenInit で送った MechTypeList の DER バイト列**に対して計算したもの。

#### 実装方針 (2e)

- `ClientSigningKey = MD5(ExportedSessionKey ++ "session key to client-to-server signing key magic constant\0")`
- SEAL 無効 (smbutil の type3 flags は SEAL=0x20 を立てない) なので RC4 シールせず:
  `mechListMIC = 01 00 00 00 ++ HMAC_MD5(ClientSigningKey, seqnum(0,4LE) ++ mechList)[0..8] ++ 00 00 00 00`
  (mechList = 初回 negTokenInit の `[0]` 内 MechTypeList DER = 現状 `derSequence(ntlmOID)`)
- `wrapNegTokenResp` に mechListMIC を渡し `derContext(3, derOctetString(mechListMIC))` を付加。
- あわせて type3 flags の **SEAL(0x20) を落とす** (smbutil 準拠 + 上式が RC4 不要になる前提と一致)。
- 検証 oracle: live macOS server への `smbcli ls` 成功 (Claude が実行)。

## 検証手順 (再現環境メモ)

- NTLM 経路を強制して観測するには `kdestroy -A` で LKDC チケットを消してから試す
  (消さないと Finder/smbutil が Kerberos で成功してしまい NTLM の可否が見えない)。
- genuine NTLM リファレンス = `sudo smbutil view -A "//koji:koji@169.254.69.111"`
  (root は keychain/セッションを持たないため必ず NTLM に落ちる)。
- wire 比較は tcpdump (bridge0, port 445) → NTLMSSP type3 の AV pair / proof / MIC を抽出。

## 関連

- `Sources/SMBee/NTLM.swift` (`makeType3` / NTLMv2 blob / MIC)
- `Sources/SMBee/SMBClient.swift` (SESSION_SETUP 経路, `serverName` 受け渡し)
- git 履歴: NTLM-MIC fix の連続 revert (`d8ae7aa`/`f724f1c`/`dba5c79`/`1b4c89e`) は本 issue と同根の
  「サーバ側 Kerberos-only が真因と気づかず client を blind fix」した痕跡。
- todo.md「実 macOS (3.0.2) 手動 smoke」の具体的失敗ケース。
