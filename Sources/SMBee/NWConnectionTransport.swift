import Foundation

#if canImport(Network)
import Network

public final class NWConnectionTransport: SMBTransport, @unchecked Sendable {
    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "dev.smbee.nwconnection")

    public init() {}

    public func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        self.connection = connection
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let resumer = NWContinuationResumer<Void>()
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        if resumer.resume(continuation, with: .success(())) {
                            connection.stateUpdateHandler = nil
                        }
                    case .failed(let error):
                        if resumer.resume(continuation, with: .failure(error)) {
                            connection.stateUpdateHandler = nil
                        }
                    case .cancelled:
                        if resumer.resume(continuation, with: .failure(CancellationError())) {
                            connection.stateUpdateHandler = nil
                        }
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
        try Task.checkCancellation()
    }

    public func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        guard let connection else { throw SMBTransportError.connectionClosed }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let resumer = NWContinuationResumer<Void>()
                connection.send(content: Data(bytes), completion: .contentProcessed { error in
                    if let error {
                        resumer.resume(continuation, with: .failure(error))
                    } else {
                        resumer.resume(continuation, with: .success(()))
                    }
                })
            }
        } onCancel: {
            connection.cancel()
        }
        try Task.checkCancellation()
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        guard let connection else { throw SMBTransportError.connectionClosed }
        let bytes: [UInt8] = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let resumer = NWContinuationResumer<[UInt8]>()
                connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { data, _, isComplete, error in
                    if let error {
                        resumer.resume(continuation, with: .failure(error))
                    } else if let data, !data.isEmpty {
                        resumer.resume(continuation, with: .success(Array(data)))
                    } else if isComplete {
                        resumer.resume(continuation, with: .failure(SMBTransportError.connectionClosed))
                    } else {
                        resumer.resume(continuation, with: .success([]))
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
        try Task.checkCancellation()
        return bytes
    }

    public func close() {
        connection?.cancel()
        connection = nil
    }
}

private final class NWContinuationResumer<Success: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var didResume = false

    @discardableResult
    func resume(_ continuation: CheckedContinuation<Success, Error>, with result: Result<Success, Error>) -> Bool {
        lock.lock()
        if didResume {
            lock.unlock()
            return false
        }
        didResume = true
        lock.unlock()

        switch result {
        case .success(let value):
            continuation.resume(returning: value)
        case .failure(let error):
            continuation.resume(throwing: error)
        }
        return true
    }
}
#endif
