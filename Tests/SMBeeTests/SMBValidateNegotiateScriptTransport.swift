import Foundation
@testable import SMBee

struct SMBValidationHangGuard {
    static func run<T: Sendable>(
        label: String,
        timeout: Duration = .seconds(5),
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let box = SMBValidationHangGuardBox<T>()
        let operationTask = Task {
            do {
                box.resume(.success(try await operation()))
            } catch {
                box.resume(.failure(error))
            }
        }
        let watchdog = Task {
            try? await Task.sleep(for: timeout)
            operationTask.cancel()
            box.resume(.failure(SMBValidationHangGuardTimeout(label: label)))
        }
        defer { watchdog.cancel() }
        return try await withCheckedThrowingContinuation { continuation in
            box.install(continuation)
        }
    }
}

private struct SMBValidationHangGuardTimeout: Error, CustomStringConvertible {
    let label: String

    var description: String { "Timed out waiting for \(label)" }
}

private final class SMBValidationHangGuardBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?
    private var pendingResult: Result<T, Error>?

    func install(_ continuation: CheckedContinuation<T, Error>) {
        lock.lock()
        if let pendingResult {
            self.pendingResult = nil
            lock.unlock()
            continuation.resume(with: pendingResult)
            return
        }
        self.continuation = continuation
        lock.unlock()
    }

    func resume(_ result: Result<T, Error>) {
        lock.lock()
        guard pendingResult == nil else {
            lock.unlock()
            return
        }
        guard let continuation else {
            pendingResult = result
            lock.unlock()
            return
        }
        self.continuation = nil
        lock.unlock()
        continuation.resume(with: result)
    }
}

struct SMBValidateNegotiateScript {
    static func responseTemplate(
        messageId: UInt64 = 4,
        sessionId: UInt64 = 0x1122_3344_5566_7788,
        treeId: UInt32 = 0x3344,
        capabilities: UInt32 = 0,
        guidBytes: [UInt8] = Array(repeating: 0x42, count: 16),
        securityMode: UInt16 = SMBNegotiateConstants.signingEnabled,
        dialect: UInt16 = SMBNegotiateConstants.dialect302
    ) throws -> [UInt8] {
        guard guidBytes.count == 16 else {
            throw SMBCodecError.invalidValue("VNI fixture GUID must be 16 bytes")
        }
        var packet = try SMB2Header(
            status: SMB2Status.success,
            command: SMB2Commands.ioctl,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        packet += Array(repeating: 0, count: 48)
        writeUInt16LE(49, to: &packet, at: 64)
        writeUInt32LE(SMB2ValidateNegotiateInfo.ctlCode, to: &packet, at: 68)
        packet.replaceSubrange(72..<88, with: SMB2ValidateNegotiateInfo.fileId)
        writeUInt32LE(112, to: &packet, at: 96)
        writeUInt32LE(24, to: &packet, at: 100)
        var output: [UInt8] = []
        appendUInt32LE(capabilities, to: &output)
        output.append(contentsOf: guidBytes)
        appendUInt16LE(securityMode, to: &output)
        appendUInt16LE(dialect, to: &output)
        packet.append(contentsOf: output)
        return packet
    }
}

final class SMBValidateNegotiateScriptTransport: SMBTransport, @unchecked Sendable {
    private struct ValidationStep {
        let template: [UInt8]
    }

    private enum ResponseStep {
        case packet([UInt8])
        case validateNegotiate(ValidationStep)
    }

    private struct PendingReceive {
        let id: UUID
        let maxLength: Int
        let continuation: CheckedContinuation<[UInt8], Error>
    }

    private struct SendDelivery {
        let responseSteps: [ResponseStep]
        let request: SMBWireRequestDescriptor
        let requestWasEncrypted: Bool
    }

    private let lock = NSLock()
    private var responsesByRequest: [SMBWireRequestIdentity: [ResponseStep]] = [:]
    private var responsePreparationError: Error?
    private let credential: SMBCredential
    private let blockWhenDrained: Bool
    private let requestDecoder: SMBWireRequestDecoder?
    private let beforeReceiveRegistration: (@Sendable () -> Void)?
    private var outboundStorage: [UInt8] = []
    private var sentRequestIds: Set<UInt64> = []
    private var authenticationRequest: [UInt8]?
    private var pendingBytes: [UInt8] = []
    private var pendingReceive: PendingReceive?
    private var isClosed = false
    private var closeCountStorage = 0

    var outbound: [UInt8] {
        lock.withLock { outboundStorage }
    }

    var closeCount: Int {
        lock.withLock { closeCountStorage }
    }

    var pendingReceiveTokenForTesting: UUID? {
        lock.withLock { pendingReceive?.id }
    }

    var hasPendingReceiveForTesting: Bool {
        lock.withLock { pendingReceive != nil }
    }

    func cancelPendingReceiveForTesting(token: UUID) {
        cancelPendingReceive(id: token)
    }

    init(
        inbound: [UInt8],
        credential: SMBCredential = SMBCredential(username: "user", password: "pass"),
        blockWhenDrained: Bool = true,
        requestDecoder: SMBWireRequestDecoder? = nil,
        beforeReceiveRegistration: (@Sendable () -> Void)? = nil
    ) {
        self.credential = credential
        self.blockWhenDrained = blockWhenDrained
        self.requestDecoder = requestDecoder
        self.beforeReceiveRegistration = beforeReceiveRegistration
        do {
            self.responsesByRequest = try Self.scriptResponses(from: inbound, credentialIsAnonymous: credential.isAnonymous)
        } catch {
            responsePreparationError = error
        }
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
        guard !lock.withLock({ isClosed }) else { throw SMBTransportError.connectionClosed }
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let packet = try Self.singlePacket(from: bytes)
        let requestWasEncrypted = packet.starts(with: SMB3TransformHeader.protocolId)
        let request = try decodeRequest(packet)
        let delivery = try lock.withLock { () throws -> SendDelivery? in
            guard !isClosed else { throw SMBTransportError.connectionClosed }
            if let responsePreparationError { throw responsePreparationError }
            if request.identity.command == SMB2Commands.cancel {
                guard sentRequestIds.contains(request.identity.messageId) else {
                    throw SMBCodecError.invalidValue("CANCEL does not identify a previously sent request")
                }
                outboundStorage.append(contentsOf: bytes)
                return nil
            }
            guard let steps = responsesByRequest.removeValue(forKey: request.identity) else {
                throw SMBCodecError.invalidValue(
                    "unexpected SMB request command=\(request.identity.command) messageId=\(request.identity.messageId)"
                )
            }
            guard sentRequestIds.insert(request.identity.messageId).inserted else {
                throw SMBCodecError.invalidValue("duplicate SMB request MessageId \(request.identity.messageId)")
            }
            outboundStorage.append(contentsOf: bytes)
            if request.identity.command == SMB2Commands.sessionSetup {
                authenticationRequest = Self.type3Request(packet)
            }
            return SendDelivery(
                responseSteps: steps,
                request: request,
                requestWasEncrypted: requestWasEncrypted
            )
        }
        guard let delivery else { return }
        let ready = try delivery.responseSteps.map { step -> [UInt8] in
            switch step {
            case .packet(let response):
                Self.directTCPFrame(response)
            case .validateNegotiate(let validation):
                try Self.directTCPFrame(completeValidateNegotiateRequest(
                    request: delivery.request,
                    validation: validation,
                    encryptResponse: delivery.requestWasEncrypted
                ))
            }
        }.flatMap { $0 }
        let waiter = try lock.withLock { () throws -> (PendingReceive, [UInt8])? in
            guard !isClosed else { throw SMBTransportError.connectionClosed }
            pendingBytes.append(contentsOf: ready)
            return takePendingReceiveIfReadyLocked()
        }
        if let (pending, responseBytes) = waiter {
            pending.continuation.resume(returning: responseBytes)
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        let receiveId = UUID()
        beforeReceiveRegistration?()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8], Error>) in
                let result: Result<[UInt8], Error>? = lock.withLock {
                    if Task.isCancelled { return .failure(CancellationError()) }
                    if isClosed { return .failure(SMBTransportError.connectionClosed) }
                    if let bytes = takeChunkLocked(maxLength: maxLength) { return .success(bytes) }
                    if !blockWhenDrained && responsesByRequest.isEmpty { return .success([]) }
                    guard pendingReceive == nil else {
                        return .failure(SMBCodecError.invalidValue("concurrent receive on VNI script transport"))
                    }
                    pendingReceive = PendingReceive(id: receiveId, maxLength: maxLength, continuation: continuation)
                    return nil
                }
                if let result { continuation.resume(with: result) }
            }
        } onCancel: {
            self.cancelPendingReceive(id: receiveId)
        }
    }

    func close() {
        let continuation = lock.withLock { () -> CheckedContinuation<[UInt8], Error>? in
            closeCountStorage += 1
            isClosed = true
            let continuation = pendingReceive?.continuation
            pendingReceive = nil
            return continuation
        }
        continuation?.resume(throwing: SMBTransportError.connectionClosed)
    }

    private func completeValidateNegotiateRequest(
        request: SMBWireRequestDescriptor,
        validation: ValidationStep,
        encryptResponse: Bool
    ) throws -> [UInt8] {
        guard request.identity.command == SMB2Commands.ioctl,
              request.controlCode == SMB2ValidateNegotiateInfo.ctlCode else {
            throw SMBCodecError.invalidValue("unexpected IOCTL for VALIDATE_NEGOTIATE_INFO response")
        }
        guard let authenticationRequest = lock.withLock({ authenticationRequest }) else {
            throw SMBCodecError.invalidValue("VNI fixture has no NTLM AUTHENTICATE request")
        }
        let signingKey = try Self.smb302SigningKey(
            authenticationRequest: authenticationRequest,
            credential: credential
        )
        var response = try SMB2Header(
            status: SMB2Status.success,
            command: SMB2Commands.ioctl,
            messageId: request.identity.messageId,
            treeId: request.treeId,
            sessionId: request.sessionId
        ).encode()
        response.append(contentsOf: validation.template.dropFirst(SMB2Header.encodedSize))
        if encryptResponse {
            let exportedSessionKey = try Self.smb302ExportedSessionKey(
                authenticationRequest: authenticationRequest,
                credential: credential
            )
            return try Self.encryptServerPacket(response, sessionId: request.sessionId, messageId: request.identity.messageId,
                                                key: SMBCrypto.smb302DecryptionKey(sessionKey: exportedSessionKey))
        }
        return try signedTestPacket(response, algorithm: .aesCMAC, key: signingKey, sender: .server)
    }

    private func decodeRequest(_ packet: [UInt8]) throws -> SMBWireRequestDescriptor {
        guard packet.starts(with: SMB3TransformHeader.protocolId) else {
            return try requestDecoder?(packet) ?? SMBWireRequestDescriptor(packet: packet)
        }
        if let requestDecoder { return try requestDecoder(packet) }
        guard let authenticationRequest = lock.withLock({ authenticationRequest }) else {
            throw SMBCodecError.invalidValue("encrypted SMB request arrived before NTLM AUTHENTICATE")
        }
        let exportedSessionKey = try Self.smb302ExportedSessionKey(
            authenticationRequest: authenticationRequest,
            credential: credential
        )
        let transform = try SMB3TransformHeader.decode(packet)
        let plaintext = try AESCCM.open(
            key: SMBCrypto.smb302EncryptionKey(sessionKey: exportedSessionKey),
            nonce: Array(transform.nonce.prefix(11)),
            ciphertext: Array(packet.dropFirst(SMB3TransformHeader.encodedSize)),
            authenticatedData: transform.authenticatedData(),
            tag: transform.signature
        )
        return try SMBWireRequestDescriptor(packet: plaintext)
    }

    private func takeChunkLocked(maxLength: Int) -> [UInt8]? {
        if !pendingBytes.isEmpty {
            let count = min(maxLength, pendingBytes.count)
            let bytes = Array(pendingBytes.prefix(count))
            pendingBytes.removeFirst(count)
            return bytes
        }
        return nil
    }

    private func takePendingReceiveIfReadyLocked() -> (PendingReceive, [UInt8])? {
        guard let pendingReceive, let bytes = takeChunkLocked(maxLength: pendingReceive.maxLength) else { return nil }
        self.pendingReceive = nil
        return (pendingReceive, bytes)
    }

    private func cancelPendingReceive(id: UUID) {
        let continuation = lock.withLock { () -> CheckedContinuation<[UInt8], Error>? in
            guard pendingReceive?.id == id else { return nil }
            let continuation = pendingReceive?.continuation
            pendingReceive = nil
            return continuation
        }
        continuation?.resume(throwing: CancellationError())
    }

    private static func scriptResponses(
        from bytes: [UInt8],
        credentialIsAnonymous: Bool
    ) throws -> [SMBWireRequestIdentity: [ResponseStep]] {
        let packets = try frames(from: bytes)
        var result: [SMBWireRequestIdentity: [ResponseStep]] = [:]
        var template: [UInt8]?
        var messageIdShift: UInt64 = 0
        for var packet in packets {
            if isValidateNegotiateTemplate(packet) {
                template = template ?? packet
                if !credentialIsAnonymous, let template {
                    let identity = try SMBWireRequestDescriptor(packet: template).identity
                    result[identity, default: []].append(.validateNegotiate(ValidationStep(template: template)))
                    messageIdShift += 1
                }
                continue
            }
            if messageIdShift > 0 {
                let header = try SMB2Header.decode(packet)
                writeUInt64LE(header.messageId &+ messageIdShift, to: &packet, at: 24)
            }
            let descriptor = try SMBWireRequestDescriptor(packet: packet)
            result[descriptor.identity, default: []].append(.packet(packet))
            if !credentialIsAnonymous,
               messageIdShift > 0,
               let template,
               descriptor.identity.command == SMB2Commands.treeConnect {
                let validationIdentity = SMBWireRequestIdentity(
                    messageId: descriptor.identity.messageId &+ 1,
                    command: SMB2Commands.ioctl
                )
                result[validationIdentity, default: []].append(.validateNegotiate(ValidationStep(template: template)))
                messageIdShift += 1
            }
        }
        return result
    }

    private static func isValidateNegotiateTemplate(_ packet: [UInt8]) -> Bool {
        guard let header = try? SMB2Header.decode(packet),
              header.command == SMB2Commands.ioctl,
              packet.count >= SMB2Header.encodedSize + 8
        else {
            return false
        }
        return readUInt32LE(packet, at: SMB2Header.encodedSize + 4) == SMB2ValidateNegotiateInfo.ctlCode
    }

    private static func frames(from bytes: [UInt8]) throws -> [[UInt8]] {
        var packets: [[UInt8]] = []
        var cursor = 0
        while cursor < bytes.count {
            guard cursor + 4 <= bytes.count else { throw SMBCodecError.truncated }
            let length = try DirectTCPFraming.length(from: Array(bytes[cursor..<(cursor + 4)]))
            let start = cursor + 4
            let end = start + length
            guard end <= bytes.count else { throw SMBCodecError.truncated }
            packets.append(Array(bytes[start..<end]))
            cursor = end
        }
        return packets
    }

    private static func singlePacket(from bytes: [UInt8]) throws -> [UInt8] {
        let packets = try frames(from: bytes)
        guard packets.count == 1 else { throw SMBCodecError.invalidValue("test transport expects one framed SMB request") }
        return packets[0]
    }

    private static func directTCPFrame(_ packet: [UInt8]) -> [UInt8] {
        let length = packet.count
        return [
            0,
            UInt8((length >> 16) & 0xff),
            UInt8((length >> 8) & 0xff),
            UInt8(length & 0xff)
        ] + packet
    }

    private static func type3Request(_ packet: [UInt8]) -> [UInt8]? {
        guard packet.count >= 88 else { return nil }
        let securityOffset = Int(readUInt16LE(packet, at: 76))
        let securityLength = Int(readUInt16LE(packet, at: 78))
        guard securityOffset + securityLength <= packet.count,
              let ntlm = try? SPNEGO.unwrapNTLMToken(Array(packet[securityOffset..<(securityOffset + securityLength)])),
              ntlm.count >= 12,
              readUInt32LE(ntlm, at: 8) == 3
        else {
            return nil
        }
        return ntlm
    }

    private static func smb302SigningKey(
        authenticationRequest: [UInt8],
        credential: SMBCredential
    ) throws -> [UInt8] {
        SMBCrypto.smb3SigningKey(sessionKey: try smb302ExportedSessionKey(
            authenticationRequest: authenticationRequest,
            credential: credential
        ))
    }

    private static func smb302ExportedSessionKey(
        authenticationRequest: [UInt8],
        credential: SMBCredential
    ) throws -> [UInt8] {
        let ntResponse = try readValidatedSecurityBuffer(authenticationRequest, at: 20)
        let encryptedSessionKey = try readValidatedSecurityBuffer(authenticationRequest, at: 52)
        guard ntResponse.count >= 16, encryptedSessionKey.count == 16 else {
            throw SMBCodecError.invalidValue("NTLM AUTHENTICATE request does not carry an SMB session key")
        }
        let responseKey = try NTLM.ntowfv2(credential: credential)
        let sessionBaseKey = SMBCrypto.hmacMD5(key: responseKey, message: Array(ntResponse.prefix(16)))
        return RC4.crypt(key: sessionBaseKey, message: encryptedSessionKey)
    }

    private static func encryptServerPacket(_ packet: [UInt8], sessionId: UInt64, messageId: UInt64, key: [UInt8]) throws -> [UInt8] {
        var nonce = Array(repeating: UInt8(0), count: 11)
        for index in 0..<8 {
            nonce[index] = UInt8(truncatingIfNeeded: messageId >> (index * 8))
        }
        nonce[8] = 0x56
        nonce[9] = 0x4e
        nonce[10] = 0x49
        var header = SMB3TransformHeader(
            signature: Array(repeating: 0, count: 16),
            nonce: nonce + Array(repeating: 0, count: 5),
            originalMessageSize: UInt32(packet.count),
            flags: SMB3TransformHeader.encryptedFlag,
            sessionId: sessionId
        )
        let sealed = try AESCCM.seal(
            key: key,
            nonce: nonce,
            plaintext: packet,
            authenticatedData: header.authenticatedData(),
            tagLength: 16
        )
        header.signature = sealed.tag
        return try header.encode() + sealed.ciphertext
    }

}
