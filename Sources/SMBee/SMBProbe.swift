import Foundation

public enum SMBProbe {
    public static func probe(
        host: String,
        port: UInt16 = 445,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws -> SMBProbeResult {
        try await transport.connect(host: host, port: port)
        defer { transport.close() }

        let request = try SMBNegotiateCodec.encodeRequest(clientGuid: UUID())
        try await transport.send(DirectTCPFraming.frame(request))
        let response = try await receiveFramedMessage(from: transport)
        return try SMBNegotiateCodec.decodeResponse(response)
    }

    private static func receiveFramedMessage(from transport: SMBTransport) async throws -> [UInt8] {
        let header = try await receiveExactly(4, from: transport)
        let length = try DirectTCPFraming.length(from: header)
        return try await receiveExactly(length, from: transport)
    }

    private static func receiveExactly(_ count: Int, from transport: SMBTransport) async throws -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(count)
        while bytes.count < count {
            let chunk = try await transport.receive(maxLength: count - bytes.count)
            guard !chunk.isEmpty else { throw SMBTransportError.connectionClosed }
            bytes.append(contentsOf: chunk)
        }
        return bytes
    }
}

public enum SMBURLParser {
    public static func parseProbeURL(_ value: String) throws -> (host: String, port: UInt16) {
        guard let components = URLComponents(string: value), components.scheme == "smb", let host = components.host else {
            throw SMBCodecError.invalidValue("expected smb://host[:port]")
        }
        let port = components.port ?? 445
        guard (1...65535).contains(port) else {
            throw SMBCodecError.invalidValue("invalid port")
        }
        return (host, UInt16(port))
    }
}
