# API stability policy

SMBee is currently a pre-1.0 SwiftPM package (`0.0.1`). Consumers build it from source
together with their application. This document is the public API freeze note for 0.1.

## 0.1 source contract

The supported high-level surface consists of:

- the `SMBee` facade;
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

## Concurrency and cancellation contract

- Public value models and errors crossing concurrency boundaries are `Sendable`.
- `SMBClientSession` and `SMBClientTreeSession` are actors. Calls are serialized through
  actor isolation; callbacks accepted by them are `@Sendable` and may run away from the
  caller's executor.
- Cancelling a task requests cooperative cancellation. An in-flight SMB request may send
  SMB2 CANCEL or drain its response to preserve session correlation before returning.
- `operationTimeout` is also cooperative. It reports `SMBTransportError.timedOut` only
  after the operation task finishes, so elapsed wall-clock time may exceed the duration.
- Cancellation and timeout do not roll back completed local or remote side effects.

## Error contract

- `SMBError` represents mapped SMB status, recursive-operation, and session-level errors.
- `SMBTransportError` represents connection failures and operation deadline expiry.
- `SMBCodecError` represents invalid arguments, malformed/truncated wire data, and local
  consistency checks. It is public so consumers can catch every documented error family.
- `CancellationError` represents cooperative Swift task cancellation. A server
  `STATUS_CANCELLED` is translated to `CancellationError`; it is not a timeout.

New cases may be added during 0.x. Consumers should use a fallback branch when switching
over errors and should not parse human-readable associated strings.

## Credential migration

`SMBCredential.password` remains source-compatible in 0.1, but direct secret reads and
writes are not intended for the 1.0 API. The staged replacement and deprecation plan is
tracked in [`issues/063-api-credential-password-deprecation.md`](../issues/063-api-credential-password-deprecation.md).
No deprecation attribute will be added until a non-readable replacement credential API
exists. Continue supplying secrets through `SMBCredential(username:password:domain:)` or
an `SMBCredentialProvider`, and do not retain credentials after connecting.

## Not currently guaranteed

- ABI or module stability for previously compiled clients.
- Compatibility of function-value references when overload signatures change.
- A stable binary framework or other binary release artifact. Artifact distribution is
  outside the scope of the current release backlog.

Consumers should rebuild after updating the package and use an exact version or revision
when they need a frozen pre-1.0 API.
