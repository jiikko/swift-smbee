import Foundation

/// Runs an operation with a cooperative client-side deadline.
///
/// A timeout cancels the operation task and reports `SMBTransportError.timedOut`,
/// but it does not roll back local or remote side effects that already completed.
/// Callers should inspect or reconcile destination state before retrying mutating operations.
public enum SMBOperationDeadline {
    public static func run<T: Sendable>(
        timeout: Duration?,
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
                try await Task.sleep(for: timeout)
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
