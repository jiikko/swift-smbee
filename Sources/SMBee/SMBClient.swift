import Foundation

public struct SMBDirectoryEntry: Equatable, Sendable {
    public var name: String
    public var fileSize: UInt64
    public var isDirectory: Bool
}

public enum SMBClient {
    public static func list(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws -> [SMBDirectoryEntry] {
        let session = SMBSession(host: host, port: port, credential: credential, transport: transport)
        try await session.connect()
        defer { transport.close() }
        let treeId = try await session.treeConnect(share: share)
        let fileId = try await session.create(treeId: treeId, path: path, directory: true)
        let entries = try await session.queryDirectory(treeId: treeId, fileId: fileId)
        try? await session.close(treeId: treeId, fileId: fileId)
        return entries
    }
}

final class SMBSession {
    private let host: String
    private let port: UInt16
    private let credential: SMBCredential
    private let transport: SMBTransport
    private var messageId: UInt64 = 0
    private var sessionId: UInt64 = 0
    private var signingKey: [UInt8]?

    init(host: String, port: UInt16, credential: SMBCredential, transport: SMBTransport) {
        self.host = host
        self.port = port
        self.credential = credential
        self.transport = transport
    }

    func connect() async throws {
        try await transport.connect(host: host, port: port)
        let negotiate = try SMBNegotiateCodec.encodeRequest(clientGuid: UUID(), messageId: nextMessageId())
        debugDump("NEGOTIATE request", negotiate)
        try await sendUnsigned(negotiate)
        let negotiateResponse = try await receive(label: "NEGOTIATE response")
        let result = try SMBNegotiateCodec.decodeResponse(negotiateResponse)
        guard result.dialect == SMBNegotiateConstants.dialect302 || result.dialect == SMBNegotiateConstants.dialect300 else {
            throw SMBCodecError.invalidValue("authenticated read path currently supports SMB 3.0.x")
        }

        let type1 = SPNEGO.wrapNegTokenInit(NTLM.makeType1(domain: credential.domain))
        let challengePacket = try SMB2SessionSetup.encodeRequest(
            messageId: nextMessageId(),
            sessionId: 0,
            securityBlob: type1,
            signed: false
        )
        debugDump("SESSION_SETUP#1 request", challengePacket)
        try await sendUnsigned(challengePacket)
        let challengeResponse = try await receive(label: "SESSION_SETUP#1 response")
        let challengeHeader = try SMB2Header.decode(challengeResponse)
        guard challengeHeader.status == SMB2Status.moreProcessingRequired else {
            throw SMBCodecError.invalidValue(
                String(format: "expected STATUS_MORE_PROCESSING_REQUIRED, got NTSTATUS 0x%08x", challengeHeader.status)
            )
        }
        sessionId = challengeHeader.sessionId
        let challengeBlob = try SMB2SessionSetup.decodeResponse(challengeResponse)
        let challenge = try NTLM.parseChallenge(SPNEGO.unwrapNTLMToken(challengeBlob))
        let authenticate = try NTLM.makeType3(credential: credential, challenge: challenge)
        let authBlob = SPNEGO.wrapNegTokenResp(authenticate.message)
        let authPacket = try SMB2SessionSetup.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            securityBlob: authBlob,
            signed: false
        )
        debugDump("SESSION_SETUP#2 request", authPacket)
        try await sendUnsigned(authPacket)
        let authResponse = try await receive(label: "SESSION_SETUP#2 response")
        let authHeader = try SMB2Header.decode(authResponse)
        guard authHeader.status == SMB2Status.success else {
            throw SMBCodecError.invalidValue(String(format: "SESSION_SETUP failed with NTSTATUS 0x%08x", authHeader.status))
        }
        sessionId = authHeader.sessionId
        signingKey = SMBCrypto.smb3SigningKey(sessionKey: authenticate.sessionBaseKey)
    }

    func treeConnect(share: String) async throws -> UInt32 {
        let packet = try SMB2TreeConnect.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            path: "\\\\\(host)\\\(share)"
        )
        debugDump("TREE_CONNECT request", packet)
        try await sendSigned(packet)
        let response = try await receive(label: "TREE_CONNECT response")
        try verifySigned(response)
        let header = try SMB2Header.decode(response)
        guard header.status == SMB2Status.success else {
            throw SMBCodecError.invalidValue(String(format: "TREE_CONNECT failed with NTSTATUS 0x%08x", header.status))
        }
        return header.treeId
    }

    func create(treeId: UInt32, path: String, directory: Bool) async throws -> [UInt8] {
        let packet = try SMB2Create.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            path: path,
            directory: directory
        )
        debugDump("CREATE request", packet)
        try await sendSigned(packet)
        let response = try await receive(label: "CREATE response")
        try verifySigned(response)
        let fileId = try SMB2Create.decodeFileId(response)
        debugLine("CREATE response FileId: \(SMBDebug.hex(fileId))")
        return fileId
    }

    func queryDirectory(treeId: UInt32, fileId: [UInt8]) async throws -> [SMBDirectoryEntry] {
        let packet = try SMB2QueryDirectory.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId
        )
        debugDump("QUERY_DIRECTORY request", packet)
        try await sendSigned(packet)
        let response = try await receive(label: "QUERY_DIRECTORY response")
        try verifySigned(response)
        let header = try SMB2Header.decode(response)
        if header.status == SMB2Status.noMoreFiles {
            return []
        }
        guard header.status == SMB2Status.success else {
            throw SMBCodecError.invalidValue(String(format: "QUERY_DIRECTORY failed with NTSTATUS 0x%08x", header.status))
        }
        return try SMB2QueryDirectory.decodeResponse(response)
    }

    func close(treeId: UInt32, fileId: [UInt8]) async throws {
        let packet = try SMB2Close.encodeRequest(messageId: nextMessageId(), sessionId: sessionId, treeId: treeId, fileId: fileId)
        debugDump("CLOSE request", packet)
        try await sendSigned(packet)
        _ = try await receive(label: "CLOSE response")
    }

    private func sendUnsigned(_ packet: [UInt8]) async throws {
        try await transport.send(DirectTCPFraming.frame(packet))
    }

    private func sendSigned(_ packet: [UInt8]) async throws {
        guard let signingKey else { throw SMBCodecError.invalidValue("missing SMB signing key") }
        var signed = packet
        signed[16] |= UInt8(SMB2Flags.signed & 0xff)
        for index in 48..<64 { signed[index] = 0 }
        let signature = try AESCMAC.authenticationCode(key: signingKey, message: signed)
        signed.replaceSubrange(48..<64, with: signature)
        try await transport.send(DirectTCPFraming.frame(signed))
    }

    private func verifySigned(_ packet: [UInt8]) throws {
        guard let signingKey else { return }
        let header = try SMB2Header.decode(packet)
        guard (header.flags & SMB2Flags.signed) != 0 else { return }
        var normalized = packet
        normalized.replaceSubrange(48..<64, with: Array(repeating: 0, count: 16))
        let expected = try AESCMAC.authenticationCode(key: signingKey, message: normalized)
        guard expected == header.signature else {
            throw SMBCodecError.invalidValue("SMB signature verification failed")
        }
    }

    private func receive(label: String) async throws -> [UInt8] {
        let header = try await receiveExactly(4)
        let length = try DirectTCPFraming.length(from: header)
        debugDump("\(label) direct-TCP header length=\(length)", header)
        let body = try await receiveExactly(length)
        debugDump(label, body)
        return body
    }

    private func receiveExactly(_ count: Int) async throws -> [UInt8] {
        var bytes: [UInt8] = []
        while bytes.count < count {
            let chunk = try await transport.receive(maxLength: count - bytes.count)
            guard !chunk.isEmpty else { throw SMBTransportError.connectionClosed }
            bytes += chunk
        }
        return bytes
    }

    private func nextMessageId() -> UInt64 {
        defer { messageId += 1 }
        return messageId
    }

    private func debugDump(_ label: String, _ bytes: [UInt8]) {
        guard ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1" else { return }
        FileHandle.standardError.write(Data("\(label) (\(bytes.count) bytes): \(SMBDebug.hex(bytes))\n".utf8))
    }

    private func debugLine(_ message: String) {
        guard ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1" else { return }
        FileHandle.standardError.write(Data("\(message)\n".utf8))
    }
}

enum SMB2Status {
    static let success: UInt32 = 0x0000_0000
    static let noMoreFiles: UInt32 = 0x8000_0006
    static let moreProcessingRequired: UInt32 = 0xc000_0016
}

enum SMB2Flags {
    static let signed: UInt32 = 0x0000_0008
}
