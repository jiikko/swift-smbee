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
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        continuation.resume()
                    case .failed(let error):
                        continuation.resume(throwing: error)
                    case .cancelled:
                        continuation.resume(throwing: CancellationError())
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
                connection.send(content: Data(bytes), completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
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
                connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else if let data, !data.isEmpty {
                        continuation.resume(returning: Array(data))
                    } else if isComplete {
                        continuation.resume(throwing: SMBTransportError.connectionClosed)
                    } else {
                        continuation.resume(returning: [])
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
#endif
