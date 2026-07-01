import Foundation

public enum SMBTransportError: Error, Equatable {
    case connectionClosed
    case invalidAddress
    case socketFailure(String)
    case timedOut
}

public protocol SMBTransport: Sendable {
    func connect(host: String, port: UInt16) async throws
    func send(_ bytes: [UInt8]) async throws
    func receive(maxLength: Int) async throws -> [UInt8]
    func close()
}

public final class InMemoryTransport: SMBTransport, @unchecked Sendable {
    private var inbound: [UInt8]
    private(set) var outbound: [UInt8] = []

    public init(inbound: [UInt8] = []) {
        self.inbound = inbound
    }

    public func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    public func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        outbound.append(contentsOf: bytes)
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        guard !inbound.isEmpty else { return [] }
        let count = min(maxLength, inbound.count)
        let chunk = Array(inbound.prefix(count))
        inbound.removeFirst(count)
        try Task.checkCancellation()
        return chunk
    }

    public func close() {}
}
