# 098 ci: samba-compat の guest job が、追加されてから一度も通っていない

起票日: 2026-09-30
親: [done/095](done/095-ci-samba-compatibility-matrix.md)（Samba compatibility matrix）/ guest job を足したのは [done/044](done/044-ci-guest-anonymous-profile-is-not-covered.md)
関連: `.github/workflows/samba-compat.yml`（matrix の `profile: guest`）/ `test/e2e/smb/guest.conf` /
`Tests/SMBeeTests/SMBeeE2ETests.swift`（`SMBEE_E2E_PROFILE` の分岐）

## 概要

`samba-compat.yml` の scheduled run は、毎週 **run 全体が failure** になっている。落ちているのは
`ubuntu:24.04 / guest / Swift 6.2` の job だけで、他の 5 job は success。そのため「毎週赤い」ことが
常態化していて、他の profile が退行して赤くなっても気づけない。

## 実測（2026-09-30）

- `gh run list --workflow samba-compat.yml --limit 12` の結果: 2026-07-13 から 2026-09-28 までの
  scheduled run 12 回がすべて failure。各 run で success 以外の job を列挙すると、どの回も
  `ubuntu:24.04 / guest` の 1 job だけだった。
- guest job は a7161ea（2026-07-11、`fix: harden transfer integrity and session cleanup (issues 035-044)`）で
  matrix に入った。これより前で最後に success した run は 28815731127（2026-07-06）で、guest job はまだ無かった。
  つまり guest job は **追加されてから 1 回も通っていない**。
- run 36497070303 の guest job（job 109179009595）のログ（`gh run view --job 109179009595 --log-failed`）:
  - `swift test --filter SMBeeE2ETests` の結果は `Executed 15 tests, with 1 test skipped and 12 failures`。
  - 通ったのは `testGuestAnonymousSmoke` と `testProbeNegotiatesExpectedProfile` の 2 本。
  - 落ちた 12 本は、username/password の credential を使う認証ありのテスト
    （`testAuthenticatedFastSmoke` / `testAuthenticatedWriteOperations` / `testShareDiscoveryListsPublicShare` ほか）。
    エラーは `connectionLost(operation: "ECHO" / "LIST" / "MKDIR" / "UPLOAD" / "STAT")` か `connectionClosed` で、
    どれも 0.13〜0.26 秒で落ちている。
  - workflow では次の段に `swift test --filter SMBOperationalCoverageE2ETests` がある。このログには
    その結果が 1 行も出ていないので、前の段の失敗で止まり、走っていない可能性が高い（止まる仕組みは未確認）。
- 同じログの Samba 側（container の smbd ログ）:
  - 認証ありのテストの接続はどれも `Auth: ... user []\[smbee] ... with [NTLMv2] status [NT_STATUS_OK]` で、
    **`smbee` として認証に成功している**（guest に落とされてはいない）。
  - その直後に smbd が `Server exit (NT_STATUS_INVALID_PARAMETER)` で接続を終えている（ログ中 15 回）。
    ほかに `Server exit (NT_STATUS_END_OF_FILE)` が 4 回ある。
  - smbd の実効設定の dump には `server signing = if_required` と出ている（`guest.conf` の記述は `auto`）。

## 原因の候補（未確定）

- `guest.conf` は global に `map to guest = Bad User` / `server signing = auto` / `smb encrypt = disabled` を、
  `[public]` に `guest ok = yes` / `guest only = yes` / `force user = smbee` を置いている。
- 認証ありのテストは `SMBEE_E2E_PROFILE` を見ずに `SMBCredential(username:password:)` を作る。workflow も
  profile で filter を変えずに `SMBeeE2ETests` 全体を流す。そのため、guest profile でも認証ありのテストが走る。
- 認証の後で smbd が `INVALID_PARAMETER` を出して終了しているので、「server が credential を拒否した」ではない。
  **認証の後に SMBee が送った request を smbd が不正とみなしている**。候補は 3 つ:
  1. **テスト側の選別漏れ**: 認証ありのテストを guest profile で流すこと自体が想定外。
     → 直し方: guest profile では認証ありのテストを skip する。あるいは workflow の filter を、guest では
     guest 向けのテストだけに絞る。ただし、候補 2 / 3 の bug をこの直し方で隠さないこと。
  2. **SMBee の不具合**: 署名・暗号を必須にしない server（signing auto / encrypt disabled）に、認証ありで繋いだときの
     SMBee の request が不正になっている（例: 暗号化しない server に transform header 付きで送る、など。推測）。
     Finder は同じ server に user でも guest でも繋げるので、実運用でも起きうる組み合わせ。
  3. **fixture 側の問題**: `guest only` / `force user` と認証あり session の組み合わせで、Samba 側が異常終了している。

## 切り分けの結果（2026-09-30、手元の Apple container + guest.conf で再現）

**候補 2（SMBee の不具合）で確定。** SMB 3.0.x では、server が暗号化に非対応でも SMBee は認証後の request を全部暗号化
（transform header 付き）で送る。暗号化を無効にした smbd はこれを受けて `INVALID_PARAMETER` で接続を切る。

- 原因のコード: `Sources/SMBee/SMBClient.swift` の SESSION_SETUP 完了処理。dialect 3.1.1 は `result.cipher` が決まったときだけ
  `encryptionKey` を作るのに対し、3.0.x の分岐は NEGOTIATE の Capabilities も SESSION_SETUP の SessionFlags も見ずに、
  `smb302EncryptionKey` / `smb302DecryptionKey` を無条件に設定している。`sendSigned` は `encryptionKey != nil` なら暗号化して送る。
- wire の実測（`SMBEE_TRACE_WIRE_FULL=1`）:
  - NEGOTIATE 応答: SecurityMode=0x0001（signing 有効・非必須）、dialect 0x0302、Capabilities=0x00000007
    （DFS / LEASING / LARGE_MTU。`SMB2_GLOBAL_CAP_ENCRYPTION` 0x40 は無い）
  - SESSION_SETUP#2 応答: header Flags=0x09（署名付き）、SessionFlags=0x0000（guest ではなく、`ENCRYPT_DATA` も無い）
  - 注意: trace の "TREE_CONNECT request" は `treeConnect` の `debugDump` が採った**署名・暗号化前**の bytes で、
    実際の送信内容ではない（Flags=0 に見えるのはそのため）
- A/B 実験: 3.0.x の分岐で `encryptionKey` / `decryptionKey` を作らない一時的な変更（実験後に戻した）を当てると、
  同じ container で `SMBeeE2ETests` 全体が `Executed 15 tests, with 1 test skipped and 0 failures`。
  変更前は認証ありの 12 本が落ちる（CI と同じ形）。
- smbd のログからは、どの検査で `INVALID_PARAMETER` になったかまでは出ない（`container-init.sh` が
  `--debuglevel=3` 固定で起動するため。`smbcontrol smbd debug 10` も、認証後に設定を読み直す子プロセスには効かなかった）。
- 候補 1（テスト選別）: guest profile で認証ありテストを流すのは、結果として「暗号化非対応の server に認証ありで繋ぐ」
  唯一の E2E になっていた。外すと製品の bug を隠すので採らない。候補 3（fixture）: 修正後の実験で全部通るので否定。

## 対応方針

- まず候補 1〜3 を切り分ける。手元で `SAMBA_CONFIG=test/e2e/smb/guest.conf SMBEE_E2E_PROFILE=guest bin/e2e/container-samba.sh` を
  実行し、wire log で「認証の後に最初に送った request（command・flags・transform header の有無）」と、
  smbd の `INVALID_PARAMETER` がどの request に対するものかを見る。
- 切り分けの結果（どの候補だったか・根拠のログ）をこの issue に書いてから直す。

## 対応方針

- まず 1 か 2 かを切り分ける。手元で `SAMBA_CONFIG=test/e2e/smb/guest.conf SMBEE_E2E_PROFILE=guest bin/e2e/container-samba.sh` を
  実行し、wire log で最初に落ちる request と、そのときの status を見る。
- 切り分けの結果（どちらだったか・根拠のログ）をこの issue に書いてから直す。

## 受け入れ条件

- [x] 失敗の原因が候補 1〜3 のどれかを、wire log を根拠に確定してこの issue に書いている（候補 2。上の節）
- [ ] `samba-compat.yml` の guest job が success になっている（run id を記録する）
- [ ] 候補 2 だった場合、署名・暗号を必須にしない server へ認証ありで繋ぐ組み合わせを守る E2E が残っている

## 進捗

- 2026-09-30: issue-sync の中で起票（095 を done へ移したときに検出した）。codex の反証レビューで
  「2 択では足りない（smbd が認証成功の後に INVALID_PARAMETER で終了している）」と指摘され、ログで裏を取って候補を 3 つに直した。
- 2026-09-30: 手元で再現し、wire の実測と A/B 実験で候補 2 に確定（「切り分けの結果」節）。修正方針は codex がリード中。
