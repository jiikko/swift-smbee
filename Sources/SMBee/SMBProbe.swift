import Foundation

public enum SMBProbe {
    public static func probe(
        host: String,
        port: UInt16 = 445,
        makeTransport: @Sendable () -> SMBTransport = { POSIXSocketTransport() }
    ) async throws -> SMBProbeResult {
        var retryConnectionLoss = true
        while true {
            let transport = makeTransport()
            do {
                let result = try await probeOnce(host: host, port: port, transport: transport)
                transport.close()
                return result
            } catch {
                transport.close()
                guard error.isSMBConnectionLoss else {
                    throw error
                }
                guard retryConnectionLoss else {
                    throw SMBError.connectionLost(operation: "PROBE")
                }
                retryConnectionLoss = false
            }
        }
    }

    private static func probeOnce(
        host: String,
        port: UInt16,
        transport: SMBTransport
    ) async throws -> SMBProbeResult {
        try await transport.connect(host: host, port: port)

        let request = try SMBNegotiateCodec.encodeRequest(clientGuid: UUID())
        if ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1" {
            let traceWire = ProcessInfo.processInfo.environment["SMBEE_TRACE_WIRE"] == "1"
            FileHandle.standardError.write(
                Data("NEGOTIATE request (\(request.count) bytes): \(SMBDebug.packetSummary(request, traceWire: traceWire))\n".utf8)
            )
        }
        try await transport.send(DirectTCPFraming.frame(request))
        let response = try await receiveFramedMessage(from: transport)
        if ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1" {
            let traceWire = ProcessInfo.processInfo.environment["SMBEE_TRACE_WIRE"] == "1"
            FileHandle.standardError.write(
                Data("NEGOTIATE response (\(response.count) bytes): \(SMBDebug.packetSummary(response, traceWire: traceWire))\n".utf8)
            )
        }
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
    public struct ReadURL: Equatable, Sendable {
        public var username: String?
        public var password: String?
        public var host: String
        public var port: UInt16
        public var share: String
        public var path: String
    }

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

    public static func parseReadURL(_ value: String) throws -> ReadURL {
        guard let components = URLComponents(string: value), components.scheme == "smb", let host = components.host else {
            throw SMBCodecError.invalidValue("expected smb://[user@]host[:port]/share[/path]")
        }
        let port = components.port ?? 445
        guard (1...65535).contains(port) else {
            throw SMBCodecError.invalidValue("invalid port")
        }
        let parts = try components.percentEncodedPath
            .split(separator: "/", omittingEmptySubsequences: true)
            .map { try decodeSMBURLPathComponent(String($0)) }
        guard let share = parts.first else {
            throw SMBCodecError.invalidValue("SMB URL must include a share")
        }
        let normalizedShare = try SMBShareName(share).rawValue
        let path = parts.dropFirst().joined(separator: "\\")
        let normalizedPath = try SMBPath.normalize(path)
        let username = try components.percentEncodedUser.map(decodeSMBURLUserInfo)
        let password = try components.percentEncodedPassword.map(decodeSMBURLUserInfo)
        return ReadURL(username: username, password: password, host: host, port: UInt16(port), share: normalizedShare, path: normalizedPath)
    }

    private static func decodeSMBURLPathComponent(_ value: String) throws -> String {
        guard let decoded = value.removingPercentEncoding else {
            throw SMBCodecError.invalidValue("SMB URL path contains invalid percent encoding")
        }
        guard decoded != ".", decoded != ".." else {
            throw SMBCodecError.invalidValue("SMB URL path must not contain . or .. components")
        }
        guard !decoded.contains("/"), !decoded.contains("\\") else {
            throw SMBCodecError.invalidValue("SMB URL path component must not contain path separators")
        }
        return decoded
    }

    private static func decodeSMBURLUserInfo(_ value: String) throws -> String {
        guard let decoded = value.removingPercentEncoding else {
            throw SMBCodecError.invalidValue("SMB URL user info contains invalid percent encoding")
        }
        return decoded
    }
}
