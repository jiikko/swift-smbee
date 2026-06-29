import Foundation

#if canImport(Network)
import Network

public final class NWConnectionTransport: SMBTransport, @unchecked Sendable {
    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "dev.smbee.nwconnection")

    public init() {}

    public func connect(host: String, port: UInt16) async throws {
        let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        self.connection = connection
        try await withCheckedThrowingContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    continuation.resume()
                case .failed(let error):
                    continuation.resume(throwing: error)
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    public func send(_ bytes: [UInt8]) async throws {
        guard let connection else { throw SMBTransportError.connectionClosed }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        guard let connection else { throw SMBTransportError.connectionClosed }
        return try await withCheckedThrowingContinuation { continuation in
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
    }

    public func close() {
        connection?.cancel()
        connection = nil
    }
}
#endif
