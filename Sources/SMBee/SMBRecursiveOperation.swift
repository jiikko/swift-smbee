import Foundation

public struct SMBRecursiveFailure: Equatable, Sendable {
    public let path: String
    public let message: String
    /// The originating SMB failure, when available. Message-only and non-SMB failures retain nil.
    public let error: SMBError?

    public init(path: String, message: String) {
        self.path = path
        self.message = message
        self.error = nil
    }

    public init(path: String, error: any Error) {
        self.path = path
        self.message = String(describing: error)
        self.error = error as? SMBError
    }
}

public struct SMBRecursiveAction: Equatable, Sendable {
    public enum Kind: String, Equatable, Sendable {
        case copy
        case upload
        case download
        case delete
        case mkdir
        case skip
    }

    public let kind: Kind
    public let path: String

    public init(kind: Kind, path: String) {
        self.kind = kind
        self.path = path
    }
}

final class SMBRecursiveFailureCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [SMBRecursiveFailure] = []

    func record(path: String, error: Error) {
        lock.lock()
        storage.append(SMBRecursiveFailure(path: path, error: error))
        lock.unlock()
    }

    var failures: [SMBRecursiveFailure] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func throwIfNeeded() throws {
        let failures = failures
        if !failures.isEmpty {
            throw SMBError.recursiveOperationIncomplete(failures: failures)
        }
    }
}
