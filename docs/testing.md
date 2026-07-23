# SMBee — テスト戦略

SMBee のテストは 3 tier。**ⓥ = 実装/運用前に要確認**。

## Tier 1: unit（primitive / framing vector）— CI 必須・サーバ不要

純粋ロジックを既知ベクタで固める。実 SMB サーバに依存しない。

- **crypto primitive**: MD4（RFC1320）/ HMAC-MD5・HMAC-SHA256（RFC2104）/ NIST GCM・GMAC / SHA-512
- **NTLMv2**: MS-NLMP / RFC の既知ベクタ（NTOWFv2 / NTProofStr / MIC）
- **SMB framing**: SMB2 packet header・各 command 構造の encode/decode round-trip /
  3.1.1 preauth integrity transcript fixture / SP800-108 KDF vector /
  TRANSFORM_HEADER round-trip / signed packet 検証 /
  **packet-level fixture**（pcap or 既存実装由来。primitive が通っても framing が正しいとは限らない）

性能退行テストは wall-clock time を pass/fail 条件にしない。CI やローカル環境の負荷差で揺れやすいため、
`InMemoryTransport` と synthetic SMB2 frame を使い、command count / streaming callback count / byte count を
計算量 proxy として固定する。ログは `PERF_METRIC <name> actual=.. expected=..` 形式にし、時間を出す場合も
補助情報 `PERF_INFO` に留める。

## Tier 2: E2E（コンテナ上の SMB サーバ）— 本 repo のテスト範囲の主役

SMB サーバ（Samba）をコンテナで起動し、SMBee/`smbcli` でゴールデンパスを通す。
**「手動で macOS ファイル共有を立てる」依存を排し、E2E を再現可能にする。**

- **ローカル**: Apple container（macOS 26 の `container` CLI / Containerization framework, Apple silicon）
- **CI**: Docker（**Linux runner**。GHA: `.github/workflows/e2e.yml`、public repo で無料）

test code は共通（Samba を起動 → golden path）で、**起動手段だけ差し替える**。

> ⚠️ **CI(Docker/Linux) の前提**: Docker は Linux で動かす（macOS hosted runner では Docker 不可）。
> よって **SMBee が Linux でビルド/実行できる**必要がある。→ **決定: transport を抽象化**し
> macOS=NWConnection / Linux=POSIXSocketTransport を差し替える（[architecture.md](architecture.md)）。
> `Network.framework` 依存は `NWConnectionTransport` 内に `#if canImport(Network)` で閉じ込める。

ゴールデンパス（probe → 認証 → 操作）:

```
probe   : NEGOTIATE 結果 (dialect/signing/contexts) が想定 (macOS mirror: 3.0.2 / signing required / contexts なし) か
shares  : IPC$ + SRVSVC NetrShareEnum で public share が列挙できるか（既存 SMBCredential による認証必須。
          guest/anonymous share discovery は未サポート）
ls      : QUERY_DIRECTORY
stat    : QUERY_INFO
cat     : READ（full / range）。download sha256 を期待値と照合
put     : WRITE（streaming、large file >4GiB 含む）
mkdir / rename / rm : SET_INFO / CREATE / disposition
```

E2E ハーネスの流れ（XCTest から driver 経由 ⓥ）:

1. `container run` で Samba イメージを起動（445 を expose、share + ユーザを用意）
2. 445 が listen するまで wait（probe で疎通確認）
3. ゴールデンパスを実行して assert
4. `container stop` / `rm` で確実に後始末（テスト失敗時も）

### ⚠️ サーバ実装差（重要・要確認 ⓥ）

- 対象サーバには **macOS SMBX / Windows SMB Server / Samba** を含めるが、自動 E2E は **Samba（Linux）**。各実装は別物。
- **signing/cipher の交渉差**: macOS SMBX は macOS 26.5.1 でも negotiated dialect が
  **0x0302 (SMB 3.0.2)** で上限。SMB 3.0.2 は 3.1.1 negotiate contexts を返さず、
  signing/encryption は CMAC/CCM 系になる。
- PR 必須 E2E は Samba を **SMB3_02 上限 + signing required + encryption required** に固定し、実 macOS の
  3.0.2 上限をミラーする。3.0.2 用 AES-CMAC / AES-128-CCM は in-repo pure-Swift 実装で扱う。
- Samba の **SMB 3.1.1 + AES-128-GMAC + AES-128-GCM** は `.github/workflows/samba-compat.yml` の
  互換 matrix で確認する。3.1.1 は Samba 互換対象であり、macOS SMBX の前提 dialect ではない。
- したがって E2E（Samba）green ≠ macOS SMBX / Windows SMB Server 動作保証。**実サーバへの手動 smoke（Tier 3）を併用**する。

### CI 実行 — Docker / Linux runner

- CI は **`ubuntu-latest` + Docker で Samba を起動**して E2E（`.github/workflows/e2e.yml`、Swift 6.2）。
  ローカルは Apple container、CI は Docker、と起動手段を分ける。
- **前提（再掲）**: Linux で動かす以上、SMBee が Linux ビルド可能であること（上の transport 制約）。
- E2E テストは env gate（`SMBEE_E2E=1` + 接続情報 env）。未満足ならローカルの通常 `swift test` では skip。
- `.github/workflows/e2e.yml` は PR / push 用の代表 smoke。profile は
  `test/e2e/smb/smb302-encrypted-required.conf` を使い、macOS SMBX mirror として
  SMB 3.0.2 + signing mandatory + encryption required を維持する。
- `.github/workflows/e2e.yml` の API E2E matrix は `smb302-encrypted-required` を full scope で回し、
  `smb311-signing-required` は authenticated fast smoke、`smb311-encrypted-required` は
  ECHO/list を含む 2MiB 超の encrypted large-I/O smoke で回す。これにより PR / push でも
  3.1.1 の GMAC signing-only path と GCM encrypted path を最低 1 本ずつ通す。
- API E2E と compatibility matrix は `SMBOperationalCoverageE2ETests` も実行し、実サーバの
  allocation size と単一 read deadline を検証する。PR / push の primary profile はさらに
  `SMBUnicodePathE2ETests` と `SMBeeSharedSessionRangedReadE2ETests` を実行し、Unicode path と
  cancel 後の同一 session 再利用を回帰検証する。lock CLI は CLI smoke で検証する。
- `.github/workflows/samba-compat.yml` は重い互換性 matrix。`workflow_dispatch` と週次 schedule で、
  distro-provided Samba、Swift 6.2、`test/e2e/smb/*.conf` profile の代表組み合わせを回す。

### ローカル実行 — Apple container / macOS

macOS で CI の E2E に近い条件を再現する場合は Apple の `container` CLI を使う。
この repo では `bin/e2e/container-samba.sh` が次をまとめて実行する。

1. `ubuntu:24.04` コンテナを起動し、`apt-get install samba` で CI と同じ distro Samba を入れる。
2. `test/e2e/smb/smb302-encrypted-required.conf` を `/etc/samba/smb.conf` に配置する。
3. `127.0.0.1:1445 -> container:445` で Samba を公開する。
4. CI と同じ順序で `smbcli probe`、primary API suite、operational / Unicode / shared-session
   cancellation suite、`smbcli` smoke を実行する。
5. 成功/失敗にかかわらずコンテナを削除する。

初回だけ `container system start` が kernel download / setup の確認を出すことがある。
対話セットアップを終えた後、以下を実行する。

```sh
bin/e2e/container-samba.sh
```

主な環境変数:

```sh
SMBEE_E2E_PORT=1446 bin/e2e/container-samba.sh
SMBEE_E2E_KEEP_CONTAINER=1 bin/e2e/container-samba.sh
SAMBA_CONFIG=test/e2e/smb/smb311-encrypted-required.conf bin/e2e/container-samba.sh
```

SMB 3.1.1 の NEGOTIATE だけをローカルで確認する場合:

```sh
SAMBA_CONFIG=test/e2e/smb/smb311-encrypted-required.conf \
SMBEE_E2E_PROFILE=smb311-encrypted-required \
SMBEE_E2E_TEST_FILTER=SMBeeE2ETests.testProbeNegotiatesExpectedProfile \
SMBEE_E2E_SKIP_EXTRA_API_TESTS=1 \
SMBEE_E2E_SKIP_CLI_SMOKE=1 \
bin/e2e/container-samba.sh
```

SMB 3.1.1 の authenticated fast smoke をローカルで確認する場合:

```sh
SAMBA_CONFIG=test/e2e/smb/smb311-encrypted-required.conf \
SMBEE_E2E_PROFILE=smb311-encrypted-required \
SMBEE_E2E_TEST_FILTER=SMBeeE2ETests.testAuthenticatedFastSmoke \
SMBEE_E2E_SKIP_CLI_SMOKE=1 \
bin/e2e/container-samba.sh
```

`SMBEE_E2E_KEEP_CONTAINER=1` を使った場合の後始末:

```sh
container rm -f smbee-samba-container-e2e
```

wire を細かく見る場合:

```sh
SMBEE_TRACE_WIRE=1 SMBEE_TRACE_WIRE_FULL=1 \
  SMB_PASSWORD=smbee .build/debug/smbcli shares smb://smbee@127.0.0.1:1445
```

### GitHub Actions での container CLI

GitHub Actions の E2E は引き続き `ubuntu-latest` + Docker を使う。
Apple `container` CLI は macOS 上で Linux container を動かす仕組みだが、GitHub-hosted macOS runner で
常に使える CI 前提にはしていない。

- runner image に `container` CLI がプリインストールされている保証がない。
- `brew install container` できても、初回の `container system start` は kernel download / system service setup を伴う。
- GitHub-hosted macOS runner は仮想化された環境で、Linux container 用 runtime を安定して動かす前提にしにくい。
- public repo では Samba E2E は Linux runner + Docker のほうが速く、安定し、ログも取りやすい。

そのため Apple container はローカル再現用、CI は Docker/Linux runner という分担にする。

Samba profile:

- `smb302-encrypted-required`: PR 必須代表。SMB 3.0.2 / signing mandatory / encryption required。
- `smb311-signing-required`: SMB 3.1.1 / signing mandatory / encryption off。GMAC signing-only 経路の検証用。
- `smb311-encrypted-required`: SMB 3.1.1 / signing mandatory / encryption required。GCM transform 経路の検証用。

## Tier 3: 手動 smoke（実サーバ）— リリース前

**macOS のファイル共有（SMBX）** と **Windows SMB Server** に対し `smbcli probe` + ゴールデンパスを
手動で 1 周。Tier 2 の Samba では拾えない実サーバ固有挙動（交渉値・quirk）を確認する。
「自発実行はビルドまで、実行はユーザー」運用に乗せる。

共通の手動 smoke は `bin/e2e/smoke-real-server.sh` を使う。

```sh
swift build --product smbcli
SMB_PASSWORD='...' bin/e2e/smoke-real-server.sh smb://user@host/share
```

結果は [compatibility-matrix.md](compatibility-matrix.md) に記録する。smoke は基本的な
file operation に加えて、authenticated ECHO、byte-range lock、CHANGE_NOTIFY で作成した
ファイル名が10秒以内に通知されることも確認する。`SMBEE_SMOKE_REPORT` を指定すると、
成功・失敗、終了コード、最終step、client/server metadata、NEGOTIATE JSONをMarkdownへ
保存できる。passwordはreportへ保存しない。
GitHub Actions の `windows-latest` は将来 Windows SMB Server host として使える候補だが、
現状の SMBee client は POSIX/Darwin/Linux transport 前提なので、Windows runner 上で直接 client E2E を
回すには Windows transport 対応を先に入れる。

## Push 後の performance regression 確認

`Performance` workflow は同一 Release build から完全な benchmark invocation を10回収集し、中央値と
MAD / min-maxをjob summaryへ出す。masterへのpushでは、直前のsuccessful masterも同じjob・同じrunner上で
10回測定し、次の大幅な退行をjob failureにする。current/referenceを同一CPU上で測るため、hosted runner間の
CPU世代差をperformance差として誤検出しない。

- read/write throughput: 15%超の低下
- user CPU: 25%超の増加
- process max RSS: 20%超の増加
- system CPU: hosted-runnerでの揺れが大きいためobserve-only

Swift image、runner OS/arch、CPU model/count、workloadが一致しない場合は誤判定を避けるためgateをskipし、
summaryに理由を表示する。この場合、performance-sensitiveな修正は比較可能なrunを取り直すまで改善確認済みと
扱わない。まとまった修正やtransport / codec / crypto / read-write pathの変更では、push後にworkflowの完了、
job summary、10回中央値、spreadを確認し、run URLとbefore/afterを作業結果へ記録する。

## まとめ

| Tier | 対象 | CI | 役割 |
|------|------|----|----|
| 1 unit | なし（vector/fixture） | ✅ 必須 | ロジック・framing の正しさ |
| 2 E2E | Samba コンテナ（ローカル=Apple container / CI=Docker on Linux） | ✅（e2e.yml。足場は手動、整い次第 push/PR） | 再現可能なゴールデンパス回帰 |
| 3 smoke | 実 macOS SMBX / Windows SMB Server | 手動 | 実サーバの最終確認 |
