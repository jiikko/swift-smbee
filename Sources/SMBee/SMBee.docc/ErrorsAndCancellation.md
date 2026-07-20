# Errors and Cancellation

Handle SMB status, transport, validation, and Swift cancellation separately.

SMBee exposes three error families:

- ``SMBError`` for mapped SMB status and session-level failures.
- ``SMBTransportError`` for connection failures and operation deadlines.
- ``SMBCodecError`` for invalid input, malformed wire messages, and consistency checks.

Swift task cancellation is reported as `CancellationError`. An operation deadline
reports `SMBTransportError.timedOut`, but it is cooperative: the call waits for the
operation task to finish and may return later than the configured duration.

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
