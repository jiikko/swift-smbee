# Compatibility Matrix

This matrix records real-server behavior. Automated Samba coverage lives in
`.github/workflows/e2e.yml` and `.github/workflows/samba-compat.yml`; this file is
for the server implementations that are not equivalent to container Samba.

Use `bin/e2e/smoke-real-server.sh` for manual smoke:

```sh
swift build --product smbcli
SMB_PASSWORD='...' bin/e2e/smoke-real-server.sh smb://user@host/share
```

To save a reviewable record, set the report path and server metadata:

```sh
SMB_PASSWORD='...' \
SMBEE_SMOKE_REPORT=smoke-report.md \
SMBEE_SMOKE_SERVER='Windows Server' \
SMBEE_SMOKE_VERSION='Windows Server 2025, build ...' \
SMBEE_SMOKE_AUTH='NTLMv2 password' \
bin/e2e/smoke-real-server.sh smb://user@host/share
```

The script exercises `probe`, `shares`, `ls`, `stat`, `cat`, `get`, `put`,
`mkdir`, `cp`, `mv`, `rm`, `df`, `acl`, `ping`, byte-range `lock`, and
`watch` against a temporary directory. The watch check creates a file after
subscribing and requires the matching change event within 10 seconds. The
optional Markdown report records pass/fail, the failing step and exit code,
client/server metadata, and the machine-readable NEGOTIATE result. It never
records `SMB_PASSWORD`.

## Results

| Client OS | Server | Server version | Dialect | Signing | Encryption | Auth | Smoke | Notes |
|---|---|---|---|---|---|---|---|---|
| Linux | Samba container | Ubuntu 24.04 profile `smb302-encrypted-required` | 3.0.2 | required / CMAC | required / CCM | NTLMv2 password | automated PR/push full E2E | macOS SMBX mirror profile. |
| Linux | Samba container | Ubuntu 24.04 profile `smb311-signing-required` | 3.1.1 | required / GMAC | off | NTLMv2 password | automated PR/push fast smoke, compat full E2E | Covers authenticated signing-only path. |
| Linux | Samba container | Ubuntu 24.04 profile `smb311-encrypted-required` | 3.1.1 | required / GMAC | required / GCM | NTLMv2 password | automated PR/push fast smoke, compat full E2E | Covers authenticated transform path. |
| macOS 26.5 / arm64 | Samba 4.19.5 in Apple Container | Ubuntu 24.04 profile `smb302-encrypted-required` | 3.0.2 | required / CMAC | required / CCM | NTLMv2 password | local full API E2E + supplemental API suites + CLI smoke passed (2026-07-21) | `/opt/homebrew/bin/container`; primary API 12 passed / 2 profile-or-large-stream gated, operational 2 passed, Unicode 1 passed, shared-session ranged-read/cancel 2 passed; CLI recursive/JSON/lock/ACL/watch smoke passed. |
| macOS | macOS SMBX | macOS 26.5.1 observed | 3.0.2 | required / CMAC | CCM | NTLMv2 password | manual basic smoke passed | `rm <dir>` now auto-retries directory delete. Re-run with `smoke-real-server.sh` before release. |
| Linux or macOS | Windows SMB Server | TBD | TBD | TBD | TBD | TBD | not run | Candidate for next Tier 3 smoke. GitHub `windows-latest` can host an SMB server, but SMBee currently has POSIX/Darwin/Linux transport assumptions and is not a Windows Swift client yet. |
| Linux or macOS | Synology/QNAP/NAS | TBD | TBD | TBD | TBD | TBD | not run | Record firmware, SMB dialect policy, signing/encryption settings, and ACL behavior. |

## Data To Record

For every manual run, capture:

- client OS and architecture
- server product, OS/firmware version, and SMB configuration
- negotiated dialect
- signing required and algorithm
- encryption required and cipher
- auth mode: password, NT hash, anonymous/guest, or future Kerberos
- command failures and exact `smbcli` exit code
- path encoding or Unicode normalization differences
- ACL/security descriptor behavior, especially mask normalization

## Known Gaps

- Windows SMB Server has no checked-in smoke result yet.
- NAS devices have no checked-in smoke result yet.
- GitHub Actions `windows-latest` is useful as a future Windows SMB Server host,
  but using it as the SMBee client runner needs Windows transport support first.
- DFS referral metadata and multi-hop auto-follow have Samba msdfs E2E coverage; Windows DFS remains pending.
