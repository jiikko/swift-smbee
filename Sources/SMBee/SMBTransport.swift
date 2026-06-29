import Foundation

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
        _ = host
        _ = port
    }

    public func send(_ bytes: [UInt8]) async throws {
        outbound.append(contentsOf: bytes)
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        guard !inbound.isEmpty else { return [] }
        let count = min(maxLength, inbound.count)
        let chunk = Array(inbound.prefix(count))
        inbound.removeFirst(count)
        return chunk
    }

    public func close() {}
}
