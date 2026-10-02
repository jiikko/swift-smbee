/// Runs an operation with a cooperative client-side deadline.
///
/// A timeout requests cancellation of the operation task and reports
/// `SMBTransportError.timedOut` after that task finishes. Because cancellation is
/// cooperative, this call may return after the configured duration. It does not roll
/// back local or remote side effects that already completed.
/// Callers should inspect or reconcile destination state before retrying mutating operations.
public enum SMBOperationDeadline {
    /// Per-task clock seam used by deterministic tests. Child tasks inherit the value, so
    /// callers can exercise a public API's deadline without changing production behavior.
    @TaskLocal static var sleeperForTesting: (@Sendable (Duration) async throws -> Void)?

    public static func run<T: Sendable>(
        timeout: Duration?,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let sleeper: @Sendable (Duration) async throws -> Void = sleeperForTesting ?? { duration in
            try await Task.sleep(for: duration)
        }
        return try await run(timeout: timeout, sleeper: sleeper, operation: operation)
    }

    /// Internal callers that own their clock (session cleanup) pass it explicitly; the public
    /// entry above resolves the per-task test sleeper, so exactly one place picks the clock.
    static func run<T: Sendable>(
        timeout: Duration?,
        sleeper: @escaping @Sendable (Duration) async throws -> Void,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        guard let timeout else {
            return try await operation()
        }

        return try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                try await operation()
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
