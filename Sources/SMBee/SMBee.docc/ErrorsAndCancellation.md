# Errors and Cancellation

Handle SMB status, transport, validation, and Swift cancellation separately.

SMBee exposes three error families:

- ``SMBError`` for mapped SMB status and session-level failures.
- ``SMBTransportError`` for connection failures and operation deadlines.
- ``SMBCodecError`` for invalid input, malformed wire messages, and consistency checks.

Recursive operations with `continueOnError: true` report `SMBError.recursiveOperationIncomplete`.
Each ``SMBRecursiveFailure`` retains its path and diagnostic message; its `error` is the
originating `SMBError`, or `nil` for non-SMB errors and values constructed with the
message-only initializer. Equality includes the typed error, so a typed failure and a
message-only failure need not compare equal even when their path and message match.
Aggregated failures do not imply that no work completed; callers must also account for
successful actions before deciding how to present a failure or whether to retry.

Swift task cancellation is reported as `CancellationError`. An operation deadline
reports `SMBTransportError.timedOut`, but it is cooperative: the call waits for the
operation task to finish and may return later than the configured duration.

`SMBError.treeUnavailable(treeId:operation:)` means that one scoped Tree is closing or
retired and refused the request locally. It does not indicate a session failure and is
not an automatic reconnect or retry signal. `SMBError.cleanupFailed(resource:underlying:)`
reports a failed File or Tree cleanup with its resource and originating failure. A
successful `withTree` body throws this cleanup error if disconnecting its temporary Tree
fails; if both the body and cleanup fail, the body error is preserved. An enclosing
operation deadline or caller cancellation takes precedence over a saved body error.

File and scoped Tree cleanup use a five-second soft deadline and a finite hard deadline
of at most sixty seconds, shortened by `requestTimeout` when configured. Uncommitted
cleanup is retired without a MessageId at the soft deadline. A fully sent request reports
the soft timeout while its response drains until the fixed hard deadline. Missing a
response before the hard deadline does not by itself close the shared transport; an
unfinished drain at the hard deadline makes the session terminal. Explicit session close
still closes the transport.

When `close()` is called inside a callback holding an active operation lease, it starts
cleanup and returns without waiting for completion. Calls from outside an active lease
join the shared cleanup and wait for its result to finish.

```swift
do {
    try await SMBee.upload(
        host: "files.example.com",
        credential: credential,
        share: "public",
        path: "incoming/report.txt",
        data: bytes,
        operationTimeout: .seconds(30)
    )
} catch SMBTransportError.timedOut {
    // Inspect remote state before retrying; completed writes are not rolled back.
} catch is CancellationError {
    // The surrounding Swift task was cancelled.
} catch let error as SMBError {
    // Handle mapped server status.
} catch let error as SMBCodecError {
    // Handle validation or protocol consistency failure.
}
```
