# SMBee Coverage Matrix

This document is the compact source for what SMBee implements, how it is tested,
and what remains unsupported or underverified. It complements `todo.md`, which is
a chronological implementation log.

Status labels:

- `covered`: implemented with unit and/or E2E evidence.
- `underverified`: implemented, but missing one or more real-server smoke paths.
- `partial`: usable subset exists, with explicit limitations.
- `unsupported`: intentionally not implemented yet.

## Protocol Surface

| Feature | Spec | Implementation | Unit | Samba E2E | macOS SMBX | Windows/NAS | Status | Limitations |
|---|---|---|---|---|---|---|---|---|
| Direct TCP framing | MS-SMB2 2.1 | `DirectTCPFraming.swift`, `SMBTransport.swift` | yes | yes | smoke | no | covered | Port 445 only. NetBIOS port 139 is out of scope. |
| NEGOTIATE probe | MS-SMB2 3.2.4.2 | `SMBNegotiate.swift`, `SMBProbe.swift` | yes | yes | smoke | no | covered | Probe advertises SMB 2.0.2/2.1/3.x, but authenticated connect is SMB 3.x only. |
| Authenticated dialect policy | MS-SMB2 3.2.4.2 | `SMBNegotiateCodec.authenticatedDialects` | yes | yes | smoke | no | covered | SMB 3.x only. SMB 2.0.2/2.1 are probe-only and authenticated connect returns a diagnostic `protocolError`. |
| SMB 3.0.2 signing/encryption | MS-SMB2, RFC4493, SP800-38C | `SMBSessionCrypto.swift`, `AESCMAC.swift`, `AESCCM.swift` | yes | yes | smoke | no | covered | Uses AES-CMAC signing and AES-128-CCM encryption. |
| SMB 3.1.1 signing/encryption | MS-SMB2 3.1.4.1, 3.1.4.2 | `SMBSessionCrypto.swift`, `SMB3TransformHeader.swift`, `SMBCrypto.swift` | yes | yes | no | no | underverified | Samba is covered; Windows/NAS SMB 3.1.1 smoke is still missing. |
| NTLMv2 + SPNEGO | MS-NLMP, MS-SPNG | `NTLM.swift`, `SMBClient.swift` | yes | yes | smoke | no | covered | Kerberos/GSS is unsupported. |
| Anonymous/guest NTLM | MS-NLMP | `NTLM.swift`, `SMBClient.swift`, `smbcli` | yes | yes | no | no | underverified | Samba guest path covered only. |
| SESSION_SETUP / TREE_CONNECT | MS-SMB2 3.2.4.3, 3.2.4.4 | `SMBClient.swift`, `SMBClientSession.withTree` | yes | yes | smoke | no | covered | Primary `SMBClientSession` remains one-tree oriented, with scoped additional tree access via `withTree`. Full server/tree session split is future work. |
| ECHO | MS-SMB2 3.2.4.25 | `SMB2ReadCodecs.swift`, `SMBClient.echo`, `smbcli ping` | yes | no | no | no | partial | Manual authenticated ECHO is implemented. Automatic periodic keepalive and real-server smoke are missing. |
| TREE_DISCONNECT / LOGOFF | MS-SMB2 3.2.4.23, 3.2.4.24 | `SMBClient.swift` | yes | yes | no | no | covered | Best-effort on clean close. |

## File Operations

| Feature | Spec | Implementation | Unit | Samba E2E | macOS SMBX | Windows/NAS | Status | Limitations |
|---|---|---|---|---|---|---|---|---|
| CREATE / CLOSE / FLUSH | MS-SMB2 3.2.4.5, 3.2.4.17, 3.2.4.7 | `SMBClient.swift`, `SMB2ReadCodecs.swift` | yes | yes | smoke | no | covered | Durable handles, leases, and oplocks are unsupported. |
| QUERY_DIRECTORY streaming | MS-SMB2 3.2.4.18 | `SMBClient.swift`, `SMBee.withDirectoryStream` | yes | yes | smoke | no | covered | Existing `list` collector remains for compatibility. |
| QUERY_INFO stat | MS-SMB2, MS-FSCC | `SMB2ReadCodecs.swift`, `SMBClient.swift` | yes | yes | smoke | no | covered | Reparse target data is not decoded. |
| READ full/range/streaming | MS-SMB2 3.2.4.6 | `SMBClient.swift`, `SMBee.withReadStream` | yes | yes | smoke | no | covered | >4GiB E2E is gated/manual. |
| WRITE upload/streaming | MS-SMB2 3.2.4.8 | `SMBClient.swift` | yes | yes | smoke | no | covered | Single-file byte-level resume is unsupported. |
| CreditCharge / CreditRequest | MS-SMB2 3.2.4.1 | `SMB2Credit`, `SMB2Read`, `SMB2Write`, `SMBSession`, `SMBTransferLimits` | yes | no | no | no | partial | READ/WRITE charge, response grant tracking, and credit-capped chunk planning are implemented. Credit-window blocking and multi-flight allocator are not implemented. |
| mkdir / rename / delete | MS-SMB2 CREATE, SET_INFO | `SMBClient.swift` | yes | yes | smoke | no | covered | Mutation retry is intentionally conservative. |
| recursive get/put/cp/rm | MS-SMB2 composed operations | `SMBRecursiveOperation.swift`, `SMBClient.swift` | yes | yes | no | no | covered | No true transactional directory atomicity; partial-file byte resume and checksum verify are unsupported. |
| server-side copychunk | MS-FSCC FSCTL_SRV_COPYCHUNK | `SMBClient.swift` | yes | fallback observed | no | no | underverified | Samba test FS returns unsupported and exercises fallback; offload-capable server smoke is missing. |
| change notify | MS-SMB2 CHANGE_NOTIFY | `SMBClient.swift`, `SMBee.withChangeNotifications` | yes | yes | no | no | underverified | Reconnect/resubscribe and CLI JSON output are not implemented. |

## Metadata And Admin Operations

| Feature | Spec | Implementation | Unit | Samba E2E | macOS SMBX | Windows/NAS | Status | Limitations |
|---|---|---|---|---|---|---|---|---|
| share discovery | MS-SRVS, MS-RPCE | `DCERPC.swift`, `SMBClient.listShares` | yes | yes | no | no | covered | Guest/anonymous share discovery policy is limited. |
| filesystem/volume info | MS-FSCC FileFs*Information | `SMB2ReadCodecs.swift`, `SMBClient.volumeInfo` | yes | yes | no | no | underverified | macOS SMBX, Windows, and NAS smoke missing. |
| attributes/timestamps read/write | MS-FSCC FileBasicInformation | `SMB2ReadCodecs.swift`, `SMBClient.updateMetadata` | yes | yes | no | no | covered | chmod/POSIX mode mapping is not provided. |
| security descriptor read | MS-SMB2 QUERY_INFO security, MS-DTYP | `SMB2ReadCodecs.swift`, `SMBClient.securityInfo` | yes | yes | no | no | covered | Unknown/object ACEs are preserved at mask level only. |
| DACL write | MS-SMB2 SET_INFO security, MS-DTYP | `SMBClient.setSecurityInfo` | yes | yes | no | no | partial | Owner/group/SACL write is unsupported. Samba may normalize masks. |
| SID name resolution | MS-DTYP well-known SIDs, MS-LSAT | `SMBWellKnownSID`, `smbcli acl --resolve-sids` | yes | no | no | no | partial | Well-known SID table is implemented. Domain SID lookup via LSARPC is future work. |
| DFS referral metadata | MS-DFSC, MS-FSCC FSCTL_DFS_GET_REFERRALS | `SMB2DfsReferral.swift`, `SMBClient.dfsReferral` | yes | no | no | no | underverified | Real msdfs server E2E and auto-follow are missing. |
| reparse point metadata / target | MS-FSCC FileAttributeTagInformation, FSCTL_GET_REPARSE_POINT | `SMB2ReadCodecs.swift`, `SMBFileStat`, `SMBee.readlink`, `smbcli readlink` | yes | yes | no | no | partial | Tag metadata is covered by Samba E2E. Target decode has unit coverage; real-server readlink smoke and DFS reparse-data decode are missing. |

## CLI And Operational Coverage

| Feature | Spec | Implementation | Unit | Samba E2E | macOS SMBX | Windows/NAS | Status | Limitations |
|---|---|---|---|---|---|---|---|---|
| `smbcli` core commands | CLI | `Sources/smbcli` | yes | yes | smoke | no | covered | Interactive shell is out of scope. |
| JSON output | CLI | `SMBCLIOutput.swift`, `smbcli` | yes | partial | no | no | partial | Not every command has JSON output, including `watch`. |
| exit codes | CLI | `SMBCLI.swift`, `docs/smbcli-exit-codes.md` | yes | yes | no | no | covered | Keep exhaustive mapping as `SMBError` evolves. |
| debug redaction | operational | `SMBDebug.swift`, `smbcli --debug/--trace-wire` | yes | yes | no | no | covered | Raw wire trace remains explicitly opt-in. |
| timeout/progress/cancellation | operational | `SMBTransport.swift`, `SMBTransferProgress.swift` | yes | yes | no | no | partial | Socket-level timeout only; full operation deadline is future work. |

## Release Blockers

- Add and run real-server smoke for Windows SMB Server and at least one NAS class target.
- Keep PR/push E2E gating on SMB 3.0.2 encrypted plus SMB 3.1.1 authenticated signing/encrypted smoke.
- Decide and document whether SMB 2.1 authenticated fallback remains unsupported or becomes opt-in.
- Stabilize public API names, `Sendable` annotations, error taxonomy, and credential surface before SemVer commitment.
