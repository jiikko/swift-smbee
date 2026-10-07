struct SMBOperationContext: Sendable {
    let now: @Sendable () -> ContinuousClock.Instant
    let deadline: ContinuousClock.Instant
}

/// Runs an operation with a cooperative client-side deadline.
///
/// A timeout requests cancellation of the operation task and reports
/// `SMBTransportError.timedOut` after that task finishes. Because cancellation is
/// cooperative, this call may return after the configured duration. It does not roll
/// back local or remote side effects that already completed.
/// Callers should inspect or reconcile destination state before retrying mutating operations.
public enum SMBOperationDeadline {
    /// Absolute monotonic deadline inherited by nested operations and their child tasks.
    @TaskLocal static var operationContext: SMBOperationContext?

    /// Per-task clock seam used by deterministic tests. Child tasks inherit the value, so
    /// callers can exercise a public API's deadline without changing production behavior.
    @TaskLocal static var sleeperForTesting: (@Sendable (Duration) async throws -> Void)?
    @TaskLocal static var operationCancellationObserverForTesting: (@Sendable () -> Void)?

    public static func run<T: Sendable>(
        timeout: Duration?,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let time = SMBSessionMonotonicTime.production()
        let sleeper: @Sendable (Duration) async throws -> Void = sleeperForTesting ?? { duration in
            try await time.sleep(duration)
        }
        return try await run(timeout: timeout, time: time, sleeper: sleeper, operation: operation)
    }

    /// Internal callers that own their clock (session cleanup) pass it explicitly; the public
    /// entry above resolves the per-task test sleeper, so exactly one place picks the clock.
    static func run<T: Sendable>(
        timeout: Duration?,
        sleeper: @escaping @Sendable (Duration) async throws -> Void,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let time = SMBSessionMonotonicTime.production()
        return try await run(timeout: timeout, time: time, sleeper: sleeper, operation: operation)
    }

    private static func boundedContext(
        timeout: Duration,
        time: SMBSessionMonotonicTime
    ) -> SMBOperationContext {
        let inherited = operationContext
        let now = inherited?.now ?? time.now
        let candidate = now().advanced(by: timeout)
        let deadline = inherited.map { min($0.deadline, candidate) } ?? candidate
        return SMBOperationContext(now: now, deadline: deadline)
    }

    static func run<T: Sendable>(
        timeout: Duration?,
        time: SMBSessionMonotonicTime,
        sleeper: @escaping @Sendable (Duration) async throws -> Void,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        guard let timeout else {
            return try await operation()
        }
        let context = boundedContext(timeout: timeout, time: time)
        let cancellationObserver = operationCancellationObserverForTesting

        return try await $operationContext.withValue(context) {
            try await withThrowingTaskGroup(of: T.self) { group in
                group.addTask {
                    guard let cancellationObserver else {
                        return try await operation()
                    }
                    return try await withTaskCancellationHandler {
                        try await operation()
                    } onCancel: {
                        cancellationObserver()
                    }
                }
                group.addTask {
                    try await sleeper(timeout)
                    throw SMBTransportError.timedOut
                }

                guard let result = try await group.next() else {
                    throw CancellationError()
                }
                group.cancelAll()
                return result
            }
        }
    }
}
