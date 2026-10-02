# API stability policy

SMBee is currently a pre-1.0 SwiftPM package (`0.0.1`). Consumers build it from source
together with their application. This document is the public API freeze note for 0.1.

## 0.1 source contract

The supported high-level surface consists of:

- the `SMBee` facade;
- the public high-level static APIs on `SMBClient`;
- `SMBClientSession` and its scoped `SMBClientTreeSession`;
- credentials, transfer options, callbacks, and returned model values;
- `SMBError`, `SMBTransportError`, and `SMBCodecError`;
- `SMBTransport` for custom transport injection.

Ordinary named calls on this surface receive best-effort source compatibility throughout
the 0.x series. Public wire codecs, crypto helpers, constants, and raw SMB headers remain
provisional low-level APIs until 1.0; consumers that use them should pin an exact version.

Existing nonescaping `SMBCredentialProvider` forwarding calls are compile-tested.
Deadline-enabled provider overloads require an explicit `operationTimeout` argument so
the legacy overload remains selectable. Adding a defaulted parameter does not guarantee
compatibility for references to overloaded methods as function values.

`SMBClient` is a supported high-level entry point alongside `SMBee`. Its public static
connection, session, share/tree/file, transfer, and DFS operations are covered by the 0.x
source-compatibility contract. The facade and the lower-level client do not expose identical
overloads. In particular, custom transports can be supplied only to `SMBClient` overloads
whose signatures include `makeTransport`; `SMBee` does not promise transport injection.
Credential and credential-provider overloads may differ in whether `makeTransport` is
optional, defaulted, or required. The declared signature of each overload is the contract;
do not infer that every overload accepts the same arguments.

| Public entry family | Example calls | Custom transport |
| --- | --- | --- |
| `SMBee` facade | `SMBee.connect`, `SMBee.upload`, `SMBee.download` | Not exposed by the facade |
| `SMBClient.connect` | Credential and credential-provider overloads | Both overloads accept optional `makeTransport` |
| `SMBClient` one-shot high-level operations | `list`, `withReadStream`, `download`, `upload`, `stat`, and other declared operations | Available only on overloads whose signature declares `makeTransport`; defaults vary by overload |
| `SMBClientSession` / `SMBClientTreeSession` | Operations on an established session or tree | Chosen when the session is connected; not replaced per operation |
The single-file `withReadStream` and `download` APIs on `SMBClient` and `SMBee`: their
credential overloads accept an optional
`operationTimeout` (default `nil`); provider overloads with a deadline use a separate
overload that requires the `operationTimeout` argument, while the existing provider
overload remains available. The same optional deadline is available on
`SMBClientSession.withReadStream` and `SMBClientSession.download`.

`operationTimeout` covers one complete cooperative operation. One-shot calls include
credential resolution, connection setup, transfer cleanup, and session teardown. Calls on
an existing `SMBClientSession` begin at the API call and include CREATE through CLOSE plus
download temporary-file cleanup or installation. A resumed download includes remote-prefix
validation and the subsequent append transfer. The deadline reports
`SMBTransportError.timedOut` after cancellation cleanup finishes; callbacks that ignore
cancellation and synchronous local file work can make the call return after the requested
duration. Work already appended to a resume destination is not rolled back.

## Concurrency and cancellation contract

- Public value models and errors crossing concurrency boundaries are `Sendable`.
- `SMBClientSession` and `SMBClientTreeSession` are actors. Actor isolation protects
  actor-isolated state, but an async call can suspend at `await`, allowing another call to
  the same actor to make progress before the first call returns. Multi-request high-level
  operations are not atomic and have no overall ordering guarantee; callers must coordinate
  competing operations such as writes to the same path. Callbacks accepted by the actors are
  `@Sendable` and may run away from the caller's executor.
- Repeated or concurrent `close()` calls on an SMB client session or scoped tree share one
  cleanup operation; each caller returns after that cleanup finishes. Session close releases
  reconnect waiters and closes an in-progress candidate without waiting for credential-provider
  code to return. A scoped-tree setup already in progress gets a bounded grace period; if it does
  not finish, the affected transport is closed to release it.
- Cancelling a task requests cooperative cancellation. An in-flight SMB request may send
  SMB2 CANCEL or drain its response to preserve session correlation before returning.
- `operationTimeout` is also cooperative. It reports `SMBTransportError.timedOut` only
  after the operation task finishes, so elapsed wall-clock time may exceed the duration.
- Cancellation and timeout do not roll back completed local or remote side effects.
- File/tree/session cleanup has a bounded internal deadline. A missing cleanup response
  invalidates and closes the transport because the server-side resource state is unknown;
  callers must establish a new session before continuing.

## Error contract

- `SMBError` represents mapped SMB status, recursive-operation, and session-level errors.
- `SMBTransportError` represents connection failures and operation deadline expiry.
- `SMBCodecError` represents invalid arguments, malformed/truncated wire data, and local
  consistency checks. It is public so consumers can catch every documented error family.
- `CancellationError` represents cooperative Swift task cancellation. A server
  `STATUS_CANCELLED` is translated to `CancellationError`; it is not a timeout.

New cases may be added during 0.x. Consumers should use a fallback branch when switching
over errors and should not parse human-readable associated strings.

## Network transport implementation note

`NWConnectionTransport` currently turns each nonempty segment into its own `Data`, then
enqueues the frame's segments in one Network.framework batch on the shared, non-final
default message context (a separate context per frame stalled the following frame on a real
TCP loopback). Frames are serialized by a FIFO gate. `NWConnection.send` also accepts
`DispatchData`; per-segment `Data` is used here because it keeps ownership and buffer lifetime explicit for Swift `[UInt8]` inputs without
adding discontiguous-storage conversion and retention machinery. The performance effect of
this implementation has not been measured. A send returns after all of its
`contentProcessed` callbacks complete; this indicates processing by Network.framework, not
an acknowledgement from the peer.

## Wire diagnostics

`SMBEE_DEBUG=1`, `SMBEE_TRACE_WIRE=1`, and `SMBEE_TRACE_WIRE_FULL=1` enable full SMB
packet hex in session diagnostics. When an SMB session has an encryption key, plaintext
packets are redacted to their label and byte count even in full-trace mode. This applies
to outbound packets before encryption, inbound packets after decryption, and the
VALIDATE_NEGOTIATE_INFO exception send path. Encrypted transform ciphertext may still be
shown in full. Sessions without an encryption key keep the existing trace behavior.

## Credential migration

`SMBCredential.password` remains source-compatible in 0.1, but direct secret reads and
writes are not intended for the 1.0 API. The staged replacement and deprecation plan is
tracked in [`issues/063-api-credential-password-deprecation.md`](../issues/063-api-credential-password-deprecation.md).
No deprecation attribute will be added until a non-readable replacement credential API
exists. Continue supplying secrets through `SMBCredential(username:password:domain:)` or
an `SMBCredentialProvider`. `SMBClient.connect(..., credential:)` retains a reconnect closure that
captures the supplied credential for the session lifetime. Use the `credentialProvider:` overload
if you do not want a fixed credential captured; its provider closure is retained for the session and
called whenever credentials are needed, so it can return a fresh credential for each reconnect.

## Not currently guaranteed

- ABI or module stability for previously compiled clients.
- Compatibility of function-value references when overload signatures change.
- A stable binary framework or other binary release artifact. Artifact distribution is
  outside the scope of the current release backlog.

Consumers should rebuild after updating the package and use an exact version or revision
when they need a frozen pre-1.0 API.
