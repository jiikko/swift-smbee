# Custom Transport Requirements

``SMBTransport`` methods can be called while an ``SMBSession`` task is using a
session-owned custom executor. Conformers must not rely on a particular executor,
thread, or thread affinity. The same contract applies to the protocol's default
segmented-send implementation.

## Keep blocking I/O off the caller's executor

Async network waits must suspend the calling task. Do not run name resolution,
blocking connect, read/write, polling, or sleep syscalls directly in the async
method's execution interval. Move those operations to an independent I/O worker
or queue, then resume the async operation with a continuation or awaitable result.
That worker must not inherit or prefer the caller's session executor. Marking a
method `async`, `nonisolated`, or `nonisolated(nonsending)` does not move its work
to another executor.

Short setup and byte copying can remain in the async method. In particular, the
default ``SMBTransport/send(segments:)`` overload joins them before
calling ``SMBTransport/send(_:)``. Large copies can consume CPU, but that is
separate from the blocking-I/O contract.

## Preserve stream and close behavior

Each `send` invocation is one logical byte stream: concurrent sends may appear in
either order, but bytes from different invocations must not interleave. The
segmented overload sends the concatenation as one stream.

`close()` is terminal, idempotent, and short-running. It must begin interruption
without waiting for the peer, a send queue to drain, or an I/O task to finish.
Already-issued `connect`, `send`, and `receive` calls must then return or throw
without a peer response; future I/O must fail. A receive waiting for bytes must
also be released. Do not hold a state lock while doing I/O, calling user code, or
joining tasks. Reconnection uses a new transport instance.

## Example shape

An implementation with blocking socket calls should isolate the worker from the
calling task and bridge completion back asynchronously:

```swift
func receive(maxLength: Int) async throws -> [UInt8] {
    try await withCheckedThrowingContinuation { continuation in
        ioQueue.async {
            do {
                continuation.resume(returning: try receiveBlocking(maxLength: maxLength))
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
```

The worker must also observe terminal close and resume every pending operation.
The example does not prescribe a queue, socket API, cancellation mechanism, or
thread model.
