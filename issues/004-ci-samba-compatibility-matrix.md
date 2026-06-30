# 004 ci: Samba compatibility matrix を導入する

状態: **open**
起票: 2026-06-30
関連: `.github/workflows/e2e.yml` / `test/e2e/smb.conf` / `Tests/SMBeeTests/SMBeeE2ETests.swift`

## 背景

現在の E2E は、GitHub Actions の `ubuntu-latest` 上で `ubuntu:24.04` container を起動し、container 内で
`apt-get install samba` した Samba 1 系統だけを対象にしている。

また、`test/e2e/smb.conf` は macOS SMBX mirror 寄りの 1 profile だけを使っている。

```ini
server min protocol = SMB3_00
server max protocol = SMB3_02
server signing = mandatory
smb encrypt = required
```

この構成は MVP の代表 smoke としては有効だが、SMB client の互換性テストとしては一点観測になっている。
Samba の distro/version 差や smb.conf profile 差で、dialect negotiation、signing、encryption、session setup、
large read/write、directory listing の挙動が変わる可能性がある。

## 問題

1. Samba server が 1 系統だけなので、Samba 実装差による互換性退行を拾いにくい。
2. smb.conf profile が 1 種類だけなので、SMB 3.0.2 / 3.1.1、signing、encryption の組み合わせ差を拾いにくい。
3. PR ごとにすべての互換性 matrix を走らせると、CI 時間と flake 率が上がる。
4. matrix job の設計を誤ると、複数 Samba container が同一 runner / 同一 port 445 を奪い合う。

## 方針

PR の必須 E2E は代表 1 ケースに留め、重い compatibility matrix は `workflow_dispatch` / `schedule` へ分離する。

優先順位は以下。

1. smb.conf profile matrix
2. distro-provided Samba matrix
3. 必要なら version-pinned Samba image
4. macOS SMBX 実サーバ smoke

最初から Samba version を厳密 pin しない。まずは `ubuntu:22.04` / `ubuntu:24.04` / `debian:12` など、
distro が配る Samba の差分を使って互換性の幅を広げる。

## CI構成

### PR E2E

PR では、現在の代表ケースを維持する。

- runner: `ubuntu-latest`
- Samba base image: `ubuntu:24.04`
- config profile: `smb302-encrypted-required`
- test target:
  - `swift test --filter SMBeeE2ETests`
  - `smbcli` command smoke

目的は、通常開発の feedback loop を遅くしすぎないこと。

### Compatibility matrix

`workflow_dispatch` と `schedule` で matrix E2E を走らせる。

- `workflow_dispatch`: 任意実行。protocol / crypto / transport を触ったときに手動で確認する。
- `schedule`: nightly または週次。CI コストと flake 状況を見て決める。

初期 matrix 案:

```yaml
strategy:
  fail-fast: false
  matrix:
    include:
      - samba_base: ubuntu:24.04
        profile: smb302-encrypted-required
      - samba_base: ubuntu:24.04
        profile: smb311-signing-required
      - samba_base: ubuntu:24.04
        profile: smb311-encrypted-required
      - samba_base: ubuntu:22.04
        profile: smb302-encrypted-required
      - samba_base: debian:12
        profile: smb302-encrypted-required
```

まずは全組み合わせの直積にしない。代表 profile × 複数 distro と、代表 distro × 複数 profile を組み合わせる。
直積 matrix は CI 時間とノイズが増えるため、必要になってから増やす。

## smb.conf profile 案

### smb302-encrypted-required

現在の macOS SMBX mirror profile。

```ini
server min protocol = SMB3_00
server max protocol = SMB3_02
server signing = mandatory
smb encrypt = required
```

狙い:

- SMB 3.0.2 上限
- signing mandatory
- encryption required
- macOS SMBX mirror に近い挙動

### smb311-signing-required

SMB 3.1.1 negotiation / preauth hash 寄りの profile。

```ini
server min protocol = SMB3_11
server max protocol = SMB3_11
server signing = mandatory
smb encrypt = off
```

狙い:

- SMB 3.1.1 dialect
- preauth integrity negotiate contexts
- encryption なしの signing path

### smb311-encrypted-required

SMB 3.1.1 + encryption path を確認する profile。

```ini
server min protocol = SMB3_11
server max protocol = SMB3_11
server signing = mandatory
smb encrypt = required
```

狙い:

- SMB 3.1.1 dialect
- preauth integrity negotiate contexts
- encryption required
- transform header / decrypt path

## 並列実行への配慮

matrix job は並列実行される前提で設計する。

- 1 job = 1 runner = 1 Samba container とする。
- 同一 job 内で複数 Samba container を同時起動しない。
- container 名は matrix ごとに一意にする。
  - 例: `smbee-samba-${{ matrix.profile }}-${{ strategy.job-index }}`
- share root は job ごとに一意の path にする。
  - 例: `/srv/smbee/${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${{ strategy.job-index }}/public`
- test root は既存と同じく `GITHUB_RUN_ID` / `GITHUB_RUN_ATTEMPT` / matrix profile を含める。
- host port 445 は、matrix job が別 runner で動く限り衝突しない。
- 将来、同一 runner 内で複数 Samba container を並列起動する場合は、host network port 445 固定をやめる。
  - 例: container network alias 経由で接続する。
  - あるいは `-p 0:445` で割り当て port を取得し、`SMBEE_E2E_PORT` に渡す。

`concurrency` は workflow 全体を潰さないように注意する。

- PR 用 E2E は従来通り `e2e-${{ github.ref }}` で古い run を cancel してよい。
- compatibility matrix は長時間 run になりやすいので、別 workflow に分ける。
- compatibility matrix の concurrency group は `samba-compat-${{ github.ref }}` のように PR E2E と分ける。
- `cancel-in-progress` は manual / nightly の用途に応じて決める。
  - PR branch 上の manual run は cancel してよい。
  - nightly は前日の結果を残したい場合があるため、最初は `false` でもよい。

## 実装案

1. `test/e2e/smb.conf` を profile 化する。
   - 例: `test/e2e/smb/smb302-encrypted-required.conf`
   - 例: `test/e2e/smb/smb311-signing-required.conf`
   - 例: `test/e2e/smb/smb311-encrypted-required.conf`
2. 現在の `.github/workflows/e2e.yml` は PR 用代表 smoke として維持する。
3. `.github/workflows/samba-compat.yml` を追加する。
   - trigger: `workflow_dispatch` / `schedule`
   - runner: `ubuntu-latest`
   - `strategy.fail-fast: false`
   - `matrix.include` で代表組み合わせを列挙する。
4. E2E logs に Samba version と profile を出す。
   - `smbd --version`
   - `testparm -s`
   - `echo "SAMBA_COMPAT_PROFILE=${{ matrix.profile }}"`
5. E2E test に profile 名を渡す。
   - `SMBEE_E2E_PROFILE=${{ matrix.profile }}`
   - 必要なら dialect / encryption 期待値を profile ごとに切り替える。

## 完了条件

- [ ] PR 用 E2E は代表 1 ケースとして維持されている。
- [ ] `workflow_dispatch` / `schedule` 用の Samba compatibility workflow が追加されている。
- [ ] compatibility workflow は matrix job として並列実行される。
- [ ] matrix job は `fail-fast: false` で、1 ケース失敗しても他ケースが最後まで実行される。
- [ ] matrix の各 job で Samba container 名、share root、test root が衝突しない。
- [ ] profile ごとの smb.conf が分離されている。
- [ ] job log に Samba version / base image / profile / negotiated dialect / signing / encryption が出る。
- [ ] `smb302-encrypted-required` が現在の macOS SMBX mirror profile として維持されている。
- [ ] `smb311-signing-required` と `smb311-encrypted-required` が追加されている。
- [ ] `docs/testing.md` に PR E2E と compatibility matrix の使い分けを追記する。

## やらないこと

- PR ごとに全 Samba compatibility matrix を必須実行すること。
- 初期実装で全 distro × 全 profile の直積 matrix にすること。
- GitHub Actions 上の転送速度秒数を compatibility gate にすること。
- Samba version pin image を最初から自前管理すること。必要になるまで distro-provided Samba で始める。
- macOS SMBX 実サーバ smoke をこの issue に含めること。これは別 issue で扱う。
