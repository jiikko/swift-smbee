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
| ECHO | MS-SMB2 3.2.4.25 | `SMB2ReadCodecs.swift`, `SMBClient.echo`, `SMBClientSession.startKeepAlive`, `smbcli ping` | yes | yes | no | no | partial | Manual authenticated ECHO has Samba smoke coverage. Persistent-session keepalive is opt-in and closes the transport on ECHO failure; reconnect policy is future work. |
| TREE_DISCONNECT / LOGOFF | MS-SMB2 3.2.4.23, 3.2.4.24 | `SMBClient.swift` | yes | yes | no | no | covered | Best-effort on clean close. |

## File Operations

| Feature | Spec | Implementation | Unit | Samba E2E | macOS SMBX | Windows/NAS | Status | Limitations |
|---|---|---|---|---|---|---|---|---|
| CREATE / CLOSE / FLUSH | MS-SMB2 3.2.4.5, 3.2.4.17, 3.2.4.7 | `SMBClient.swift`, `SMB2ReadCodecs.swift` | yes | yes | smoke | no | covered | Durable handles, leases, and oplocks are unsupported by policy: CREATE always requests oplock level NONE, and unsolicited server break notifications are dropped by the response demux. |
| QUERY_DIRECTORY streaming | MS-SMB2 3.2.4.18 | `SMBClient.swift`, `SMBee.withDirectoryStream` | yes | yes | smoke | no | covered | Existing `list` collector remains for compatibility. |
| QUERY_INFO stat | MS-SMB2, MS-FSCC | `SMB2ReadCodecs.swift`, `SMBClient.swift` | yes | yes | smoke | no | covered | Reparse target data is not decoded. |
| READ full/range/streaming | MS-SMB2 3.2.4.6 | `SMBClient.swift`, `SMBee.withReadStream` | yes | yes | smoke | no | covered | CLI size verification exists for single-file and recursive get. >4GiB E2E is gated/manual. |
| WRITE upload/streaming | MS-SMB2 3.2.4.8 | `SMBClient.swift` | yes | yes | smoke | no | covered | Single-file upload byte-level resume and CLI size verification are implemented. SHA-256 verification is available via `--verify hash` (full content read-back). Sparse file preservation is unsupported. |
| CreditCharge / CreditRequest | MS-SMB2 3.2.4.1 | `SMB2Credit`, `SMB2CreditWindow`, `SMB2Read`, `SMB2Write`, `SMBSession`, `SMBTransferLimits` | yes | no | no | no | partial | READ/WRITE charge, response grant tracking, credit-capped chunk planning, credit-window blocking reserve/grant, and messageId-based multi-flight response demux are implemented. Large encrypted transfer E2E coverage remains gated/manual. |
| byte-range lock | MS-SMB2 LOCK 2.2.26, 3.2.4.19 | `SMB2Lock`, `SMBClientSession.withFileLock`, `smbcli lock` | yes | yes | no | no | covered | Scoped lock/unlock on a dedicated open handle. Lock sequence tracking (resilient/durable reconnect) is unsupported. |
| sparse file | MS-FSCC FSCTL_SET_SPARSE / SET_ZERO_DATA / QUERY_ALLOCATED_RANGES | `SMB2SparseFile`, `SMBClientSession.setSparse/zeroRange/allocatedRanges`, `smbcli sparse`, `SMBFileStat.allocationSize` | yes | yes | no | no | covered | Filesystem-dependent; servers may return STATUS_INVALID_DEVICE_REQUEST. Transfer hole preservation is unsupported. |
| mkdir / rename / delete | MS-SMB2 CREATE, SET_INFO | `SMBClient.swift` | yes | yes | smoke | no | covered | Mutation retry is intentionally conservative. |
| recursive get/put/cp/rm | MS-SMB2 composed operations | `SMBRecursiveOperation.swift`, `SMBClient.swift` | yes | yes | no | no | covered | `get -r` / `put -r` / `cp -r` support include/exclude globs and per-file timeout. Single-file `get` / `put` support `--create-dirs`. No true transactional directory atomicity; directory resume is size-based skip; `--verify hash` performs SHA-256 read-back per transferred file. |
| server-side copychunk | MS-FSCC FSCTL_SRV_COPYCHUNK | `SMBClient.swift` | yes | fallback observed | no | no | underverified | Samba test FS returns unsupported and exercises fallback; offload-capable server smoke is missing. |
| change notify | MS-SMB2 CHANGE_NOTIFY | `SMBClient.swift`, `SMBee.withChangeNotifications`, `SMBClientSession.withChangeNotifications(autoReconnect:)`, `smbcli watch --json --reconnect` | yes | yes | no | no | covered | Opt-in reconnect resubscribes and emits an overflow for the gap. Real-server reconnect smoke is missing. |
| cancel | MS-SMB2 CANCEL | `SMB2Cancel`, `SMBSession.sendCancel`, signed transaction cancellation | yes | no | no | no | partial | CHANGE_NOTIFY and regular signed transactions (including READ/IOCTL paths) send SMB2 CANCEL without closing the transport. `STATUS_CANCELLED` maps to cancellation. General outstanding request tracking is future work. |

## Metadata And Admin Operations

| Feature | Spec | Implementation | Unit | Samba E2E | macOS SMBX | Windows/NAS | Status | Limitations |
|---|---|---|---|---|---|---|---|---|
| share discovery | MS-SRVS, MS-RPCE | `DCERPC.swift`, `SMBClient.listShares` | yes | yes | no | no | covered | Guest/anonymous share discovery policy is limited. |
| filesystem/volume info | MS-FSCC FileFs*Information | `SMB2ReadCodecs.swift`, `SMBClient.volumeInfo` | yes | yes | no | no | underverified | macOS SMBX, Windows, and NAS smoke missing. |
| attributes/timestamps read/write | MS-FSCC FileBasicInformation | `SMB2ReadCodecs.swift`, `SMBClient.updateMetadata` | yes | yes | no | no | covered | chmod/POSIX mode mapping is not provided. |
| security descriptor read | MS-SMB2 QUERY_INFO security, MS-DTYP | `SMB2ReadCodecs.swift`, `SMBClient.securityInfo` | yes | yes | no | no | covered | Unknown/object ACEs are preserved at mask level only. |
| security descriptor write | MS-SMB2 SET_INFO security, MS-DTYP | `SMBClient.setSecurityInfo` (owner/group/DACL components) | yes | yes | no | no | partial | DACL, owner, and group writes are supported (`smbcli setacl --owner/--group`). POSIX-backed servers (Samba) may deny owner/group changes for unprivileged users (chown semantics); arbitrary owners need server-side privilege. SACL write is unsupported (requires SeSecurityPrivilege). Samba may normalize masks. |
| SID name resolution | MS-DTYP well-known SIDs, MS-LSAT LsarLookupSids | `SMBWellKnownSID`, `LSARPC.swift`, `SMBee.lookupSIDs`, `smbcli acl --resolve-sids` | yes | yes | no | no | covered | Well-known table plus LSARPC lookup over IPC$/lsarpc; unresolved SIDs degrade to plain SIDs. AD domain-controller smoke is missing. |
| DFS referral metadata | MS-DFSC, MS-FSCC FSCTL_DFS_GET_REFERRALS | `SMB2DfsReferral.swift`, `SMBClient.dfsReferral` | yes | no | no | no | underverified | Real msdfs server E2E and auto-follow are missing. |
| reparse point metadata / target | MS-FSCC FileAttributeTagInformation, FSCTL_GET_REPARSE_POINT | `SMB2ReadCodecs.swift`, `SMBFileStat`, `SMBee.readlink`, `smbcli readlink` | yes | yes | no | no | partial | Tag metadata is covered by Samba E2E. Target decode has unit coverage; real-server readlink smoke and DFS reparse-data decode are missing. |

## CLI And Operational Coverage

| Feature | Spec | Implementation | Unit | Samba E2E | macOS SMBX | Windows/NAS | Status | Limitations |
|---|---|---|---|---|---|---|---|---|
| `smbcli` core commands | CLI | `Sources/smbcli` | yes | yes | smoke | no | covered | Interactive shell is out of scope. `mget -r` / `mput -r` preserve relative paths; `get -r` / `put -r` support per-file byte progress. Batch `mget` / `mput` per-file progress is future work. |
| JSON output | CLI | `SMBCLIOutput.swift`, `smbcli`, `docs/smbcli-json.md` | yes | yes | no | no | partial | Core inspection commands and `watch` have JSON smoke coverage. Mutating commands expose success JSON when `--json` is set. `--json` errors use a structured stderr object. |
| exit codes | CLI | `SMBCLI.swift`, `docs/smbcli-exit-codes.md` | yes | yes | no | no | covered | Keep exhaustive mapping as `SMBError` evolves. |
| debug redaction | operational | `SMBDebug.swift`, `smbcli --debug/--trace-wire` | yes | yes | no | no | covered | Raw wire trace remains explicitly opt-in. |
| timeout/progress/cancellation | operational | `SMBTransport.swift`, `SMBOperationDeadline.swift`, `SMBTransferProgress.swift`, `SMB2Cancel` | yes | yes | no | no | implemented-but-underverified | Socket-level timeout is broadly wired. `smbcli --operation-timeout` wraps all commands; read, upload, and recursive download/upload/copy/delete expose operation deadlines; recursive transfers retain per-file timeout. Deadline errors are `SMBTransportError.timedOut`. CHANGE_NOTIFY cancellation sends SMB2 CANCEL. Windows/NAS cancellation smoke remains. |

## Release Blockers

- Add and run real-server smoke for Windows SMB Server and at least one NAS class target.
- Keep PR/push E2E gating on SMB 3.0.2 encrypted plus SMB 3.1.1 authenticated signing/encrypted smoke.
- Decide and document whether SMB 2.1 authenticated fallback remains unsupported or becomes opt-in.
- Stabilize public API names, `Sendable` annotations, error taxonomy, and credential surface before SemVer commitment.
