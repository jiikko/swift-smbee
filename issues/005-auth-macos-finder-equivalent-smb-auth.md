# 005 auth: macOS Finder相当のSMB認証をobaket/SMBeeで実現できるか調査する

状態: **open**（SMBee core の NTLM/credential 土台は完了。残りは Finder 相当認証の実測と macOS 依存方針）
起票: 2026-06-30
関連: `Sources/SMBee/NTLM.swift` / `Sources/SMBee/SMBClient.swift` / `Sources/smbcli/SMBCLI.swift` / `issues/001-bug-macos-ntlm-logon-failure.md`

## 進捗 (2026-07-01)

SMBee 側で本 issue に関連する auth 基盤を実装した（commit c8172c3 / 17b897d、
[todo.md](../todo.md) の authentication options 参照）。

- **guest / anonymous NTLM** を実装（`SMBCredential.anonymous`、CLI `--anonymous`/`--guest`、
  NTLM anonymous Type3、signing 不可時の unsigned フォールバック）。実 Samba guest で ls/cat/stat 成功。
  → 「現状の仮説」の **3. guest / local account fallback** はクライアント側で検証可能になった。
- **password provider callback**（`SMBCredentialProvider` = lazy async closure）を persistent `connect` と
  one-shot API 全体（`listShares` / `list` / `stat` / `read` / stream / download / upload /
  copy / metadata / rename / delete）に追加。
  → Keychain 等から遅延取得した credential を SMBee に渡す配線点ができた（Keychain lookup 自体は下記のとおり consumer 責務）。
- **SMB 3.1.1 の auth 後 crypto** は GMAC signing-only / GCM encrypted session とも Samba E2E green。
  つまり NTLM で session key material が得られる経路については、3.0.2/3.1.1 とも
  `TREE_CONNECT` 以降の signing/encryption が実サーバで確認済み。

本 issue の残りは **SMBee ライブラリ core の外**にある macOS システム依存部分に絞られる:

- **Keychain 連携**: macOS `Security.framework` 依存。SMBee は cross-platform（Linux ビルド維持）で
  credential-agnostic を保つ方針のため、Keychain lookup は **consumer (obaket / smbcli) 側**で行い、
  結果を `SMBCredentialProvider` で SMBee に渡す。SMBee core には入れない。
- **Kerberos / GSS / SPNEGO(Kerberos mech)**: MVP scope 外。SMBee の NTLM 経路は壊さない（「やらないこと」参照）。
- **macOS mount delegation / NetFS SSO**: obaket 側の統合方針の問題。

→ 従って本 issue は、現時点では「SMBee の NTLM auth 実装課題」ではなく
「**obaket がどの方式を採用するかの意思決定 + macOS 依存部分**」の調査として残る。
SMBee が提供する土台（password / ntHash / provider / anonymous / SMB3 signing+encryption）は出揃った。

## 背景

obaket から、別の macOS の「ファイル共有」で公開されている SMB share に接続したい。

現在の SMBee は、`SMBCredential(username/password/ntHash/domain)` または
`SMBCredentialProvider` から得た credential を使い、NTLMv2 token を自前で生成し、SPNEGO wrapper に包んで
`SESSION_SETUP` へ送っている。anonymous/guest も NTLM anonymous Type3 として扱う。
これは password / NT hash / provider 前提の認証経路であり、Finder が macOS-to-macOS SMB 接続時に
使っている可能性のある「ログイン済み資格情報」「Keychain」「Kerberos / GSS / SPNEGO」
「macOS SMB stack 内部のSSO」とは別物である。

この issue では、いきなり Kerberos 実装に入らない。まず、Finder が macOS クライアントから macOS ファイル共有サーバへ接続するとき、本当に Kerberos 相当の認証を使っているのかを実測で確認する。そのうえで、obaket / SMBee でどこまで再現するかを判断する。

## 現状の仮説

Finder 相当認証の正体は複数あり得る。

1. Kerberos / GSS / SPNEGO
   - `cifs/<server-hostname>` の service ticket を取得している。
   - `klist` で接続前後の ticket cache 差分に現れる可能性がある。
2. Keychain 保存済み password + NTLM
   - Finder が password prompt を出さないだけで、実体は Keychain から password を読み出した NTLM かもしれない。
3. guest / local account fallback
   - guest access や同名ローカルユーザーにより、Kerberosではない経路で成功している可能性がある。
4. macOS 標準 SMB stack 内部の非公開挙動
   - NetFS / smbfs / Finder / Keychain / GSS の組み合わせで、アプリから同じ粒度では扱えない可能性がある。

このため、「Finderでパスワードなしに繋がった」だけでは Kerberos と断定しない。

## 成功条件の定義

### obaket としての成功

- ユーザーが Finder と同程度の体験で macOS file sharing の SMB share に接続できる。
- password を obaket に直接入力させずに済む経路がある。
- 進捗表示、再試行、ファイル一覧、アップロード/ダウンロードなど、obaket 側のUXを破壊しない。

### SMBee としての成功

- NTLM 経路は完了済み: password / NT hash / provider / anonymous を扱え、認証後の
  SMB signing / encryption に必要な session key material を使って 3.0.2/3.1.1 の実 Samba E2E が通る。
- Finder 相当認証を SMBee core で扱う場合は、SMB2/3 `SESSION_SETUP` の security blob に
  Kerberos / GSS / SPNEGO token を載せられる。
- GSS 認証後、`TREE_CONNECT` 以降の SMB signing / encryption に必要な session key material を取得できる。
- NTLM 経路を壊さず、auth backend として NTLM / GSS を切り替えられる。

### 撤退条件

- Finder は Kerberos ではなく Keychain + NTLM を使っていた。
- macOS GSS API で token exchange はできるが、SMB signing/encryption に必要な session key material を取得できない。
- macOS 標準 SMB stack にしか入れない非公開挙動が必要で、SMBee 自前実装では再現できない。
- GSS/Kerberos 対応のために、SMBee の単純さやクロスプラットフォーム性を大きく損なう。

撤退条件に当たる場合は、SMBee 自体に Kerberos を実装するのではなく、obaket で macOS 標準 SMB mount に委譲する経路を優先する。

## Phase 0 — 現行SMBee認証経路の確認

目的: SMBee が何をしていて、どこを差し替える必要があるかを明確にする。

確認すること:

- `SMBCredential` は password / NT hash / domain / anonymous を表現する。
- `SMBCredentialProvider` は lazy async closure として persistent `connect` と one-shot API 全体で利用できる。
- `SMBSession.connect()` は現在も `NTLM.makeType1` → `SESSION_SETUP#1` → `NTLM.makeType3` →
  `SESSION_SETUP#2` の NTLM 経路を直書きしている。
- `SPNEGO` は NTLM OID だけを広告している。Kerberos mech は未実装。
- `smbcli` は `--domain` / `--nt-hash` / `--password-stdin` / `--anonymous` / `--guest` /
  `SMB_PASSWORD` / `SMB_NT_HASH` 前提である。

成果物:

- [x] 現行 NTLM 認証経路の短いメモ（本節 + `todo.md` authentication options）。
- [x] provider 入口は実装済み。Keychain など consumer 依存 credential source は provider に閉じ込める。
- [ ] `SMBAuthenticator` のような抽象化が必要な差し替え点リスト（GSS を実装する場合のみ必要）。

## Phase 1 — Finder が本当にKerberos相当か実測する

目的: macOS client → macOS file sharing server の Finder 接続で、Kerberos / GSS が実際に使われているかを確認する。

### 環境

- Mac A: obaket / SMBee を動かすクライアントMac
- Mac B: macOS の「ファイル共有」をONにしたSMBサーバMac
- 両方のmacOSバージョン、ホスト名、Bonjour名、IPアドレスを記録する。
- Apple ID / iCloud / ローカルユーザー / 同名ユーザー / Keychain保存状態の影響を切り分ける。

### 実測手順

1. Mac A の既存資格情報を確認する。

```sh
klist
security find-internet-password -s '<Mac B hostname>' 2>/dev/null || true
security find-internet-password -s '<Mac B .local hostname>' 2>/dev/null || true
```

2. Finder から `smb://<Mac B hostname>/<share>` に接続する。

3. 接続後に ticket cache を再確認する。

```sh
klist
```

4. `cifs/<host>` / `cifs/<host>@REALM` / `host/<host>` のような service ticket が増えたか確認する。

5. Keychain item が増えたか確認する。

```sh
security find-internet-password -s '<Mac B hostname>' 2>/dev/null || true
security find-internet-password -s '<Mac B .local hostname>' 2>/dev/null || true
```

6. Console.app / unified logging で SMB / Kerberos / GSS / NetFS 関連ログを確認する。

```sh
log stream --style compact --predicate 'process == "NetAuthSysAgent" OR process == "Finder" OR process == "mount_smbfs" OR process == "smbd" OR eventMessage CONTAINS[c] "Kerberos" OR eventMessage CONTAINS[c] "GSS" OR eventMessage CONTAINS[c] "NTLM" OR eventMessage CONTAINS[c] "SPNEGO"'
```

7. Finder ではなく CLI でも同じ挙動か確認する。

```sh
mount_smbfs //'<user>'@'<host>'/'<share>' /tmp/smb-test
```

または password なし・Keychainなし・hostname/IP/Bonjour名のパターンを切り替える。

### 判定

- `klist` に `cifs/<Mac B>` 相当の ticket が増える
  - Kerberos / GSS 経路の可能性が高い。
  - Phase 2 へ進む。
- ticket は増えず、Keychain item が使われている
  - Finder の「パスワードなし」は Keychain + NTLM の可能性が高い。
  - obaket は Keychain 統合または macOS mount 委譲を優先する。
- ticket も Keychain も明確でない
  - packet capture / log を追加して判定する。

## Phase 2 — macOS GSS PoC

目的: SMBee 本体に入れる前に、macOS 上で `cifs/<host>` 向けの GSS token を作れるか確認する。

### PoC コマンド

`smbcli` とは別に、最初は小さい debug command でよい。

```sh
swift run smbee-gss-poc --service cifs/<host> --hostname <host>
```

または `smbcli probe-auth --kerberos smb://<host>/<share>` のような command を追加する。

### 確認すること

- default credential で GSS credential を取得できるか。
- `cifs/<host>` service principal で GSS security context を開始できるか。
- 初回 output token が生成されるか。
- Finder 実測で得られた hostname / Bonjour名 / FQDN / realm と一致するか。
- password をアプリに渡さずに token が作れるか。

### 失敗時の切り分け

- service principal が違う
  - `cifs/<fqdn>` / `cifs/<hostname>` / `host/<hostname>` / `.local` を比較する。
- TGT がない
  - `klist` / `kinit` / Platform SSO / Kerberos SSO Extension の有無を確認する。
- local-only macOS file sharing では KDC / realm が存在しない
  - Kerberosではなく Keychain + NTLM だった可能性を再評価する。

成果物:

- `docs/auth-macos-finder-equivalent.md` に実測結果を記録する。
- GSS token を生成できる最小コード。

## Phase 3 — SMB SESSION_SETUP へのGSS token投入PoC

目的: GSS token を SMB2 `SESSION_SETUP` の security blob に載せて、macOS SMB server が受け入れるか確認する。

### 実装方針

- 既存の NTLM 直書き経路を壊さない。
- `SMBAuthenticator` 相当の protocol を内部に追加する。
- まずは macOS-only の `GSSAuthenticator` として切る。

```swift
protocol SMBAuthenticator: Sendable {
    mutating func makeInitialSecurityBlob(host: String) async throws -> [UInt8]
    mutating func processSecurityBlob(_ blob: [UInt8]) async throws -> SMBAuthStep
}

enum SMBAuthStep: Sendable {
    case continueWithBlob([UInt8])
    case completed(sessionKey: [UInt8])
}
```

注意: `sessionKey` を本当に取得できるかは未確定。ここが最大の不確実性。

### 確認すること

- `SESSION_SETUP#1` で GSS/SPNEGO token を送れるか。
- server response の security blob を GSS に戻して continue できるか。
- server が `STATUS_MORE_PROCESSING_REQUIRED` → success に進むか。
- 認証後の SMB signing/encryption 用 key material を取り出せるか。
- `TREE_CONNECT` 以降の signed request が通るか。

### 重要な分岐

- GSS context から SMB signing/encryption に必要な session key material を取得できる
  - SMBee 自前 Kerberos 実装を進める価値がある。
- token exchange は成功するが session key material が取得できない
  - SMBee 自前実装は撤退候補。
  - obaket では macOS mount delegation を優先する。

## Phase 4 — SMBee API設計

目的: NTLMとGSS/Kerberosを共存させる。

### 現在の実装済みAPI

NTLM 系は `SMBCredential` と `SMBCredentialProvider` で扱う。

```swift
public struct SMBCredential: Sendable {
    public init(username: String, password: String, domain: String = "")
    public init(username: String, ntHash: [UInt8], domain: String = "") throws
    public static var anonymous: SMBCredential { get }
}

public typealias SMBCredentialProvider = @Sendable () async throws -> SMBCredential
```

既存の `credential: SMBCredential` API は維持しつつ、one-shot API 全体に
`credentialProvider: SMBCredentialProvider` overload を追加済み。これにより Keychain lookup、
UI prompt、consumer 側 secret store は SMBee core に持ち込まずに接続直前へ遅延できる。

### API案

GSS/Kerberos を SMBee core に入れる場合は、credential provider とは別の auth backend が必要。

```swift
public enum SMBAuthentication: Sendable {
    case ntlm(SMBCredential)
    case ntlmProvider(SMBCredentialProvider)
    case macOSDefaultGSS(servicePrincipal: String? = nil)
}
```

既存API互換のため、当面は `credential: SMBCredential` を残す。

```swift
public static func list(
    host: String,
    port: UInt16 = 445,
    share: String,
    path: String = "",
    credential: SMBCredential,
    makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
) async throws -> [SMBDirectoryEntry]
```

新APIを追加する。

```swift
public static func list(
    host: String,
    port: UInt16 = 445,
    share: String,
    path: String = "",
    authentication: SMBAuthentication,
    makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
) async throws -> [SMBDirectoryEntry]
```

ただし、Finder 実測の結果が Keychain + NTLM で足りる場合は、
`SMBAuthentication` を追加せず `SMBCredentialProvider` のまま進める方が単純。
`SMBAuthentication` は **GSS/Kerberos を実装すると決めた時点**で導入する。

### CLI案

```sh
smbcli ls --auth ntlm smb://user@host/share/path
smbcli ls --auth kerberos smb://host/share/path
smbcli ls --auth macos-default smb://host/share/path
```

`--auth macos-default` では username/password を要求しない。
Keychain + NTLM 案では `--auth macos-default` ではなく、consumer/smbcli 側で Keychain から
password を取得して `SMBCredentialProvider` に渡す実装になる。

## Phase 5 — obaket統合方針

目的: ユーザー体験として Finder 相当認証を成立させる。

### Option A: SMBee 自前GSS経路

- obaket は SMBee の `authentication: .macOSDefaultGSS` を使う。
- ファイル一覧、進捗、再試行、アップロード/ダウンロードをすべて obaket / SMBee が制御できる。
- ただし GSS session key 問題が解けることが前提。

### Option B: macOS標準SMB mount委譲

- obaket は NetFS / `open smb://...` / `mount_smbfs` 相当で macOS に接続を任せる。
- 認証、Keychain、Kerberos、Finder相当挙動は OS に任せる。
- obaket は `/Volumes/...` または mount point を通常ファイルシステムとして扱う。

メリット:

- Finder と最も近い認証体験にしやすい。
- Kerberos / Keychain / NTLM fallback の詳細を obaket が抱えなくて済む。

デメリット:

- mount lifecycle 管理が必要。
- SMB protocol level の進捗や再試行制御は弱くなる。
- obaket の自前SMB clientとしての一貫性は下がる。

### Option C: Keychain + NTLM

Finder実測の結果が Keychain + NTLM だった場合の現実解。

- obaket が Keychain から SMB password を読む/保存する。
- SMBee は既存 NTLM 経路を使う。実装上は `SMBCredentialProvider` で Keychain lookup を遅延実行し、
  `SMBCredential(username:password:domain:)` または `SMBCredential(username:ntHash:domain:)` を返す。
- ユーザーには「Finder相当」ではなく「Keychain保存済み資格情報で接続」と説明する。

現状ではこの Option C が最小追加実装で済む。SMBee core 側は対応済みで、残る作業は
obaket/smbcli の macOS-only Keychain adapter と UX。

## テスト計画

### 実機テスト

- macOS client → macOS server
- hostname / FQDN / Bonjour `.local` / IP address
- Keychainあり/なし
- 同名ユーザーあり/なし
- password promptあり/なし
- File Sharing guest accessあり/なし
- Open Directory / AD / Platform SSO 環境あり/なし。用意できない場合は明記する。

### SMBee unit / integration

- NTLM auth backend が既存挙動を維持する。
- GSS auth backend は macOS 以外では明示的に unsupported にする。
- `SESSION_SETUP` の複数round-tripを扱える。
- GSS失敗時に NTLM fallback するか、明示エラーにするかを選べる。

### obaket E2E

- password 未入力で接続できるケース。
- password が必要なケースでは明示的に prompt / Keychain 保存へ誘導する。
- mount delegation の場合、mount/unmount/既存mount再利用を検証する。

## 完了条件

### Phase 1 完了条件

- [ ] Finder接続前後の `klist` 差分を記録する。
- [ ] Finder接続前後の Keychain 差分を記録する。
- [ ] hostname / `.local` / IP address で認証方式が変わるか記録する。
- [ ] Finder が Kerberos 相当だったか、Keychain + NTLM だったか、判定不能だったかを明記する。

### Phase 2 完了条件

- [ ] macOS GSS API で `cifs/<host>` 向け token を生成するPoCを作る。
- [ ] password をアプリに渡さず token を作れるか確認する。
- [ ] 失敗時の原因を TGTなし / service principal不一致 / realmなし / API制限 に分類する。

### Phase 3 完了条件

- [ ] GSS token を SMB2 `SESSION_SETUP` security blob に載せるPoCを作る。
- [ ] macOS SMB server から success response を得られるか確認する。
- [ ] SMB signing/encryption 用 session key material を取得できるか確認する。
- [ ] `TREE_CONNECT` 以降まで通るか確認する。

### Phase 4 完了条件

- [x] 既存 `SMBCredential` APIを壊さず、`SMBCredentialProvider` overload を全 one-shot API に追加済み。
- [x] Keychain + NTLM 方針の場合の API は確定: consumer が provider 内で Keychain lookup する。
- [ ] GSS/Kerberos を SMBee core に入れる場合の `SMBAuthenticator` / `SMBAuthentication` API案を固める。
- [ ] `smbcli --auth macos-default` 相当のCLI UXを決める。

### Phase 5 完了条件

- [ ] obaketで SMBee 自前GSS、macOS mount delegation、Keychain + NTLM のどれを採用するか決める。
- [ ] 採用しない方式の理由を記録する。
- [ ] ユーザー向け説明文言を決める。

## やらないこと

- FinderがKerberosを使っていると決め打ちして実装すること。
- AD / Windows Server Kerberos 対応を最初のゴールにすること。
- SMBee の NTLM 経路を壊して GSS に置き換えること。
- GSS token exchange だけ成功した段階で「Kerberos対応完了」と見なすこと。
- session key material が取れないまま `TREE_CONNECT` 以降に進めること。

## 参考

- MS-SMB2: SMB2 SESSION_SETUP request / response security buffer
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f
- RFC 4178: SPNEGO
  - https://www.rfc-editor.org/rfc/rfc4178
- RFC 2743: GSS-API v2
  - https://www.rfc-editor.org/rfc/rfc2743
- RFC 4121: Kerberos V5 GSS-API mechanism
  - https://www.rfc-editor.org/rfc/rfc4121
