import Foundation

public struct SMBDirectoryEntry: Equatable, Sendable {
    public var name: String
    public var fileSize: UInt64
    public var isDirectory: Bool
}

public struct SMBFileStat: Equatable, Sendable {
    public var size: UInt64
    public var modifiedTime: Date?
    public var isDirectory: Bool
}

public struct SMBReadRange: Equatable, Sendable {
    public var offset: UInt64
    public var length: UInt64

    public init(offset: UInt64, length: UInt64) {
        self.offset = offset
        self.length = length
    }
}

enum SMBTransferLimits {
    static func negotiatedChunkSize(localLimit: Int, negotiatedLimit: UInt32, transformOverhead: Int = 0) -> Int {
        let usableNegotiatedLimit = max(0, Int(negotiatedLimit) - transformOverhead)
        return max(1, min(localLimit, usableNegotiatedLimit))
    }
}

enum SMBChunkedTransfer {
    static func nextWriteRange(cursor: Int, dataCount: Int, chunkSize: Int) throws -> Range<Int>? {
        guard cursor >= 0, cursor <= dataCount else {
            throw SMBCodecError.invalidValue("write cursor is outside data bounds")
        }
        guard chunkSize > 0 else {
            throw SMBCodecError.invalidValue("write chunk size must be positive")
        }
        guard cursor < dataCount else { return nil }
        let sum = cursor.addingReportingOverflow(chunkSize)
        let end = sum.overflow ? dataCount : min(sum.partialValue, dataCount)
        guard end > cursor, end <= dataCount else {
            throw SMBCodecError.invalidValue("invalid write chunk range")
        }
        return cursor..<end
    }

    static func advancedReadPosition(cursor: UInt64, remaining: UInt64, receivedCount: Int) throws -> (cursor: UInt64, remaining: UInt64) {
        guard receivedCount >= 0 else {
            throw SMBCodecError.invalidValue("read byte count must be non-negative")
        }
        let received = UInt64(receivedCount)
        guard received <= remaining else {
            throw SMBCodecError.invalidValue("SMB read returned more data than requested")
        }
        let nextCursor = cursor.addingReportingOverflow(received)
        guard !nextCursor.overflow else {
            throw SMBCodecError.invalidValue("SMB read offset overflow")
        }
        return (nextCursor.partialValue, remaining - received)
    }
}

public enum SMBClient {
    private static let localWriteChunkLimit = 64 * 1024

    private static func withSession<T>(
        host: String,
        port: UInt16,
        share: String,
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport(),
        operation: (SMBSession, UInt32) async throws -> T
    ) async throws -> T {
        let session = SMBSession(host: host, port: port, credential: credential, transport: transport)
        try await session.connect()
        defer { transport.close() }
        let treeId = try await session.treeConnect(share: share)
        return try await operation(session, treeId)
    }

    public static func list(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String = "",
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws -> [SMBDirectoryEntry] {
        try await withSession(host: host, port: port, share: share, credential: credential, transport: transport) { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: true)
            let entries = try await session.queryDirectory(treeId: treeId, fileId: fileId)
            try? await session.close(treeId: treeId, fileId: fileId)
            return entries
        }
    }

    public static func stat(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws -> SMBFileStat {
        try await withSession(host: host, port: port, share: share, credential: credential, transport: transport) { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: false)
            do {
                let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
                try? await session.close(treeId: treeId, fileId: fileId)
                return stat
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func read(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        range: SMBReadRange? = nil,
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws -> [UInt8] {
        try await withSession(host: host, port: port, share: share, credential: credential, transport: transport) { session, treeId in
            let fileId = try await session.create(treeId: treeId, path: path, directory: false)
            do {
                let stat = try await session.queryInfo(treeId: treeId, fileId: fileId)
                let start = range?.offset ?? 0
                guard start <= stat.size else {
                    throw SMBCodecError.invalidValue("read range starts past end of file")
                }
                let available = stat.size - start
                let requested = range.map { min($0.length, available) } ?? available
                let data = try await session.read(treeId: treeId, fileId: fileId, offset: start, length: requested)
                guard UInt64(data.count) == requested else {
                    throw SMBCodecError.invalidValue("short SMB read: expected \(requested) bytes, got \(data.count)")
                }
                try? await session.close(treeId: treeId, fileId: fileId)
                return data
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func makeDirectory(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, transport: transport) { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .makeDirectory(path: path))
            try await session.close(treeId: treeId, fileId: fileId)
        }
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        data: [UInt8],
        overwrite: Bool = true,
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, transport: transport) { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
            do {
                try await session.write(treeId: treeId, fileId: fileId, data: data)
                try await session.flush(treeId: treeId, fileId: fileId)
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func upload(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        localFile: URL,
        overwrite: Bool = true,
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, transport: transport) { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .upload(path: path, overwrite: overwrite))
            let handle = try FileHandle(forReadingFrom: localFile)
            defer { try? handle.close() }
            do {
                try await session.write(treeId: treeId, fileId: fileId) { maxLength in
                    let length = min(maxLength, localWriteChunkLimit)
                    let data = try handle.read(upToCount: length) ?? Data()
                    return Array(data)
                }
                try await session.flush(treeId: treeId, fileId: fileId)
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func rename(
        host: String,
        port: UInt16 = 445,
        share: String,
        fromPath: String,
        toPath: String,
        replaceIfExists: Bool = false,
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, transport: transport) { session, treeId in
            let fileId = try await session.create(treeId: treeId, request: .rename(path: fromPath))
            do {
                try await session.rename(treeId: treeId, fileId: fileId, newPath: toPath, replaceIfExists: replaceIfExists)
                try? await session.close(treeId: treeId, fileId: fileId)
            } catch {
                try? await session.close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
    }

    public static func delete(
        host: String,
        port: UInt16 = 445,
        share: String,
        path: String,
        directory: Bool = false,
        recursive: Bool = false,
        credential: SMBCredential,
        transport: SMBTransport = POSIXSocketTransport()
    ) async throws {
        try await withSession(host: host, port: port, share: share, credential: credential, transport: transport) { session, treeId in
            if recursive {
                try await session.deleteRecursively(treeId: treeId, path: path, directory: directory)
                return
            }
            let fileId = try await session.create(treeId: treeId, request: .delete(path: path, directory: directory))
            try await session.close(treeId: treeId, fileId: fileId)
        }
    }
}

// swiftlint:disable:next type_body_length
final class SMBSession {
    private let host: String
    private let port: UInt16
    private let credential: SMBCredential
    private let transport: SMBTransport
    private var messageId: UInt64 = 0
    private var sessionId: UInt64 = 0
    private var signingKey: [UInt8]?
    private var encryptionKey: [UInt8]?
    private var decryptionKey: [UInt8]?
    private var transformNonceCounter: UInt64 = 0
    private var maxReadSize: UInt32 = UInt32.max
    private var maxWriteSize: UInt32 = UInt32.max

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
        maxReadSize = result.maxReadSize
        maxWriteSize = result.maxWriteSize
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
        encryptionKey = SMBCrypto.smb302EncryptionKey(sessionKey: authenticate.sessionBaseKey)
        decryptionKey = SMBCrypto.smb302DecryptionKey(sessionKey: authenticate.sessionBaseKey)
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
        try await create(treeId: treeId, request: .read(path: path, directory: directory))
    }

    func create(treeId: UInt32, request: SMB2CreateRequest) async throws -> [UInt8] {
        let packet = try SMB2Create.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            request: request
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

    func queryInfo(treeId: UInt32, fileId: [UInt8]) async throws -> SMBFileStat {
        let packet = try SMB2QueryInfo.encodeRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId
        )
        debugDump("QUERY_INFO request", packet)
        try await sendSigned(packet)
        let response = try await receive(label: "QUERY_INFO response")
        try verifySigned(response)
        let header = try SMB2Header.decode(response)
        guard header.status == SMB2Status.success else {
            throw SMBCodecError.invalidValue(String(format: "QUERY_INFO failed with NTSTATUS 0x%08x", header.status))
        }
        return try SMB2QueryInfo.decodeNetworkOpenInformation(response)
    }

    func read(treeId: UInt32, fileId: [UInt8], offset: UInt64, length: UInt64) async throws -> [UInt8] {
        let chunkSize = UInt64(negotiatedReadChunkSize())
        var cursor = offset
        var remaining = length
        var result: [UInt8] = []
        while remaining > 0 {
            let requestLength = UInt32(min(chunkSize, remaining))
            let packet = try SMB2Read.encodeRequest(
                messageId: nextMessageId(),
                sessionId: sessionId,
                treeId: treeId,
                fileId: fileId,
                offset: cursor,
                length: requestLength
            )
            debugDump("READ request", packet)
            try await sendSigned(packet)
            let response = try await receive(label: "READ response")
            try verifySigned(response)
            let header = try SMB2Header.decode(response)
            if header.status == SMB2Status.endOfFile {
                break
            }
            guard header.status == SMB2Status.success else {
                throw SMBCodecError.invalidValue(String(format: "READ failed with NTSTATUS 0x%08x", header.status))
            }
            let data = try SMB2Read.decodeResponse(response)
            if data.isEmpty { break }
            result += data
            let advanced = try SMBChunkedTransfer.advancedReadPosition(
                cursor: cursor,
                remaining: remaining,
                receivedCount: data.count
            )
            cursor = advanced.cursor
            remaining = advanced.remaining
        }
        return result
    }

    func write(treeId: UInt32, fileId: [UInt8], data: [UInt8]) async throws {
        let chunkSize = negotiatedWriteChunkSize()
        var cursor = 0
        while let range = try SMBChunkedTransfer.nextWriteRange(cursor: cursor, dataCount: data.count, chunkSize: chunkSize) {
            let chunk = Array(data[range])
            let packet = try SMB2Write.encodeRequest(
                messageId: nextMessageId(),
                sessionId: sessionId,
                treeId: treeId,
                fileId: fileId,
                offset: UInt64(cursor),
                data: chunk
            )
            debugDump("WRITE request", packet)
            try await sendSigned(packet)
            let response = try await receive(label: "WRITE response")
            try verifySigned(response)
            let count = try SMB2Write.decodeResponseCount(response)
            guard count == chunk.count else {
                throw SMBCodecError.invalidValue("short SMB write: expected \(chunk.count) bytes, got \(count)")
            }
            cursor = range.upperBound
        }
    }

    func write(treeId: UInt32, fileId: [UInt8], nextChunk: (Int) throws -> [UInt8]) async throws {
        let chunkSize = negotiatedWriteChunkSize()
        var offset: UInt64 = 0
        while true {
            let chunk = try nextChunk(chunkSize)
            if chunk.isEmpty { break }
            let packet = try SMB2Write.encodeRequest(
                messageId: nextMessageId(),
                sessionId: sessionId,
                treeId: treeId,
                fileId: fileId,
                offset: offset,
                data: chunk
            )
            debugDump("WRITE request", packet)
            try await sendSigned(packet)
            let response = try await receive(label: "WRITE response")
            try verifySigned(response)
            let count = try SMB2Write.decodeResponseCount(response)
            guard count == chunk.count else {
                throw SMBCodecError.invalidValue("short SMB write: expected \(chunk.count) bytes, got \(count)")
            }
            let nextOffset = offset.addingReportingOverflow(UInt64(count))
            guard !nextOffset.overflow else {
                throw SMBCodecError.invalidValue("SMB write offset overflow")
            }
            offset = nextOffset.partialValue
        }
    }

    func flush(treeId: UInt32, fileId: [UInt8]) async throws {
        let packet = try SMB2Flush.encodeRequest(messageId: nextMessageId(), sessionId: sessionId, treeId: treeId, fileId: fileId)
        debugDump("FLUSH request", packet)
        try await sendSigned(packet)
        let response = try await receive(label: "FLUSH response")
        try verifySigned(response)
        let header = try SMB2Header.decode(response)
        guard header.status == SMB2Status.success else {
            throw SMBCodecError.invalidValue(String(format: "FLUSH failed with NTSTATUS 0x%08x", header.status))
        }
    }

    func deleteRecursively(treeId: UInt32, path: String, directory: Bool) async throws {
        if directory {
            let fileId = try await create(treeId: treeId, path: path, directory: true)
            do {
                let entries = try await queryDirectory(treeId: treeId, fileId: fileId)
                try? await close(treeId: treeId, fileId: fileId)
                for entry in entries {
                    try await deleteRecursively(treeId: treeId, path: joinSMBPath(path, entry.name), directory: entry.isDirectory)
                }
            } catch {
                try? await close(treeId: treeId, fileId: fileId)
                throw error
            }
        }
        let fileId = try await create(treeId: treeId, request: .delete(path: path, directory: directory))
        try await close(treeId: treeId, fileId: fileId)
    }

    func rename(treeId: UInt32, fileId: [UInt8], newPath: String, replaceIfExists: Bool) async throws {
        let packet = try SMB2SetInfo.encodeRenameRequest(
            messageId: nextMessageId(),
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            newPath: newPath,
            replaceIfExists: replaceIfExists
        )
        debugDump("SET_INFO rename request", packet)
        try await sendSigned(packet)
        let response = try await receive(label: "SET_INFO rename response")
        try verifySigned(response)
        let header = try SMB2Header.decode(response)
        guard header.status == SMB2Status.success else {
            throw SMBCodecError.invalidValue(String(format: "SET_INFO rename failed with NTSTATUS 0x%08x", header.status))
        }
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
        if encryptionKey != nil {
            try await sendEncrypted(packet)
            return
        }
        guard let signingKey else { throw SMBCodecError.invalidValue("missing SMB signing key") }
        var signed = packet
        signed[16] |= UInt8(SMB2Flags.signed & 0xff)
        for index in 48..<64 { signed[index] = 0 }
        let signature = try AESCMAC.authenticationCode(key: signingKey, message: signed)
        signed.replaceSubrange(48..<64, with: signature)
        try await transport.send(DirectTCPFraming.frame(signed))
    }

    private func sendEncrypted(_ packet: [UInt8]) async throws {
        guard let encryptionKey else { throw SMBCodecError.invalidValue("missing SMB encryption key") }
        let nonce11 = nextTransformNonce()
        let nonce16 = nonce11 + Array(repeating: UInt8(0), count: 5)
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce16,
            originalMessageSize: UInt32(packet.count),
            flags: SMB3TransformHeader.aes128CCM,
            sessionId: sessionId
        )
        let sealed = try AESCCM.seal(
            key: encryptionKey,
            nonce: nonce11,
            plaintext: packet,
            authenticatedData: header.authenticatedData(),
            tagLength: 16
        )
        header.signature = sealed.tag
        try await transport.send(DirectTCPFraming.frame(try header.encode() + sealed.ciphertext))
    }

    private func verifySigned(_ packet: [UInt8]) throws {
        if packet.starts(with: SMB3TransformHeader.protocolId) { return }
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
        for pendingCount in 0...SMB2AsyncInterim.maxPendingResponses {
            let packet = try await receiveDecryptedFrame(label: label)
            guard try SMB2AsyncInterim.shouldDiscard(packet) else {
                return packet
            }
            if pendingCount == SMB2AsyncInterim.maxPendingResponses {
                break
            }
            debugLine("\(label) ignored interim STATUS_PENDING async response")
        }
        throw SMBCodecError.invalidValue("too many interim SMB2 STATUS_PENDING responses")
    }

    private func receiveDecryptedFrame(label: String) async throws -> [UInt8] {
        let header = try await receiveExactly(4)
        let length = try DirectTCPFraming.length(from: header)
        debugDump("\(label) direct-TCP header length=\(length)", header)
        let body = try await receiveExactly(length)
        debugDump(label, body)
        if body.starts(with: SMB3TransformHeader.protocolId) {
            return try decryptTransform(body)
        }
        return body
    }

    private func decryptTransform(_ packet: [UInt8]) throws -> [UInt8] {
        guard let decryptionKey else { throw SMBCodecError.invalidValue("missing SMB decryption key") }
        let header = try SMB3TransformHeader.decode(packet)
        guard header.flags == SMB3TransformHeader.aes128CCM else {
            throw SMBCodecError.invalidValue("unsupported SMB3 encryption algorithm")
        }
        guard header.sessionId == sessionId else { throw SMBCodecError.invalidValue("SMB3 transform session id mismatch") }
        let ciphertext = Array(packet.dropFirst(SMB3TransformHeader.encodedSize))
        guard ciphertext.count == Int(header.originalMessageSize) else {
            throw SMBCodecError.invalidValue("SMB3 transform original message size mismatch")
        }
        let plaintext = try AESCCM.open(
            key: decryptionKey,
            nonce: Array(header.nonce.prefix(11)),
            ciphertext: ciphertext,
            authenticatedData: header.authenticatedData(),
            tag: header.signature
        )
        debugDump("decrypted \(packet.count)-byte SMB3 transform", plaintext)
        return plaintext
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

    private func nextTransformNonce() -> [UInt8] {
        defer { transformNonceCounter += 1 }
        let value = transformNonceCounter
        return [
            UInt8((value >> 56) & 0xff),
            UInt8((value >> 48) & 0xff),
            UInt8((value >> 40) & 0xff),
            UInt8((value >> 32) & 0xff),
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff),
            0,
            0,
            0,
        ]
    }

    private func negotiatedWriteChunkSize() -> Int {
        let transformOverhead = encryptionKey == nil ? 0 : SMB3TransformHeader.encodedSize
        return SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, negotiatedLimit: maxWriteSize, transformOverhead: transformOverhead)
    }

    private func negotiatedReadChunkSize() -> Int {
        let transformOverhead = encryptionKey == nil ? 0 : SMB3TransformHeader.encodedSize
        return SMBTransferLimits.negotiatedChunkSize(localLimit: 64 * 1024, negotiatedLimit: maxReadSize, transformOverhead: transformOverhead)
    }

    private func joinSMBPath(_ parent: String, _ child: String) -> String {
        let trimmedParent = parent.trimmingCharacters(in: CharacterSet(charactersIn: "\\/"))
        if trimmedParent.isEmpty { return child }
        return "\(trimmedParent)\\\(child)"
    }

    private func debugDump(_ label: String, _ bytes: [UInt8]) {
        guard ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1" else { return }
        FileHandle.standardError.write(Data("\(label) (\(bytes.count) bytes): \(SMBDebug.hexSummary(bytes))\n".utf8))
    }

    private func debugLine(_ message: String) {
        guard ProcessInfo.processInfo.environment["SMBEE_DEBUG"] == "1" else { return }
        FileHandle.standardError.write(Data("\(message)\n".utf8))
    }
}

enum SMB2Status {
    static let success: UInt32 = 0x0000_0000
    static let pending: UInt32 = 0x0000_0103
    static let noMoreFiles: UInt32 = 0x8000_0006
    static let moreProcessingRequired: UInt32 = 0xc000_0016
    static let endOfFile: UInt32 = 0xc000_0011
}

enum SMB2Flags {
    static let asyncCommand: UInt32 = 0x0000_0002
    static let signed: UInt32 = 0x0000_0008
}

enum SMB2AsyncInterim {
    static let maxPendingResponses = 16

    static func shouldDiscard(_ packet: [UInt8]) throws -> Bool {
        let header = try SMB2Header.decode(packet)
        guard header.status == SMB2Status.pending else { return false }
        guard (header.flags & SMB2Flags.asyncCommand) != 0 else {
            throw SMBCodecError.invalidValue("SMB2 STATUS_PENDING response missing ASYNC_COMMAND flag")
        }
        return true
    }
}
