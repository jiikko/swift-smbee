import Foundation
@testable import SMBee

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
        var response: [UInt8]?
    }

    private enum Step {
        case packet([UInt8])
        case validateNegotiate(ValidationStep)
    }

    private struct PendingReceive {
        let maxLength: Int
        let continuation: CheckedContinuation<[UInt8], Error>
    }

    private enum ReceiveDecision {
        case bytes([UInt8])
        case wait
        case end
    }

    private let lock = NSLock()
    private var steps: [Step]
    private let credential: SMBCredential
    private let blockWhenDrained: Bool
    private var outboundStorage: [UInt8] = []
    private var authenticationRequest: [UInt8]?
    private var pendingBytes: [UInt8] = []
    private var pendingReceive: PendingReceive?
    private var closeCountStorage = 0
    private var didBlockAfterScriptStorage = false

    var outbound: [UInt8] {
        lock.withLock { outboundStorage }
    }

    var closeCount: Int {
        lock.withLock { closeCountStorage }
    }

    var didBlockAfterScript: Bool {
        lock.withLock { didBlockAfterScriptStorage }
    }

    init(
        inbound: [UInt8],
        credential: SMBCredential = SMBCredential(username: "user", password: "pass"),
        blockWhenDrained: Bool = false
    ) {
        self.credential = credential
        self.blockWhenDrained = blockWhenDrained
        self.steps = Self.scriptSteps(from: inbound, credentialIsAnonymous: credential.isAnonymous)
    }

    func connect(host: String, port: UInt16) async throws {
        try Task.checkCancellation()
        _ = host
        _ = port
    }

    func send(_ bytes: [UInt8]) async throws {
        try Task.checkCancellation()
        let packet = try Self.singlePacket(from: bytes)
        let header = try SMB2Header.decode(packet)
        lock.withLock {
            outboundStorage.append(contentsOf: bytes)
            if header.command == SMB2Commands.sessionSetup {
                authenticationRequest = Self.type3Request(packet)
            }
        }

        guard header.command == SMB2Commands.ioctl,
              packet.count >= 72,
              readUInt32LE(packet, at: 68) == SMB2ValidateNegotiateInfo.ctlCode
        else {
            return
        }
        try completeValidateNegotiateRequest(requestHeader: header)
    }

    func receive(maxLength: Int) async throws -> [UInt8] {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8], Error>) in
                lock.lock()
                switch nextChunkLocked(maxLength: maxLength) {
                case .bytes(let bytes):
                    lock.unlock()
                    continuation.resume(returning: bytes)
                case .end:
                    lock.unlock()
                    continuation.resume(returning: [])
                case .wait:
                    didBlockAfterScriptStorage = true
                    pendingReceive = PendingReceive(maxLength: maxLength, continuation: continuation)
                    lock.unlock()
                }
            }
        } onCancel: {
            Task { self.cancelPendingReceive() }
        }
    }

    func close() {
        let continuation = lock.withLock { () -> CheckedContinuation<[UInt8], Error>? in
            closeCountStorage += 1
            let continuation = pendingReceive?.continuation
            pendingReceive = nil
            return continuation
        }
        continuation?.resume(returning: [])
    }

    private func completeValidateNegotiateRequest(requestHeader: SMB2Header) throws {
        let state = lock.withLock { () -> (Int, [UInt8])? in
            guard let index = steps.firstIndex(where: { step in
                if case .validateNegotiate(let validation) = step { return validation.response == nil }
                return false
            }), case .validateNegotiate(let validation) = steps[index] else {
                return nil
            }
            return (index, validation.template)
        }
        guard let state else {
            throw SMBTransportError.connectionClosed
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
            messageId: requestHeader.messageId,
            treeId: requestHeader.treeId,
            sessionId: requestHeader.sessionId
        ).encode()
        response.append(contentsOf: state.1.dropFirst(SMB2Header.encodedSize))
        response[16] |= UInt8(SMB2Flags.signed & 0xff)
        for index in 48..<64 { response[index] = 0 }
        let signature = try SMBSessionSigning.signature(
            algorithm: .aesCMAC,
            key: signingKey,
            packet: response,
            sender: .server
        )
        response.replaceSubrange(48..<64, with: signature)

        let delivery = lock.withLock { () -> (PendingReceive, [UInt8])? in
            guard case .validateNegotiate(var validation) = steps[state.0] else { return nil }
            validation.response = response
            steps[state.0] = .validateNegotiate(validation)
            guard let pendingReceive else { return nil }
            if case .bytes(let bytes) = nextChunkLocked(maxLength: pendingReceive.maxLength) {
                self.pendingReceive = nil
                return (pendingReceive, bytes)
            }
            return nil
        }
        if let delivery {
            delivery.0.continuation.resume(returning: delivery.1)
        }
    }

    private func nextChunkLocked(maxLength: Int) -> ReceiveDecision {
        if !pendingBytes.isEmpty {
            let count = min(maxLength, pendingBytes.count)
            let bytes = Array(pendingBytes.prefix(count))
            pendingBytes.removeFirst(count)
            return .bytes(bytes)
        }
        while !steps.isEmpty {
            let step = steps[0]
            switch step {
            case .packet(let packet):
                steps.removeFirst()
                pendingBytes = Self.directTCPFrame(packet)
            case .validateNegotiate(let validation):
                guard let response = validation.response else { return .wait }
                steps.removeFirst()
                pendingBytes = Self.directTCPFrame(response)
            }
            if !pendingBytes.isEmpty { return nextChunkLocked(maxLength: maxLength) }
        }
        return blockWhenDrained ? .wait : .end
    }

    private func cancelPendingReceive() {
        let continuation = lock.withLock { () -> CheckedContinuation<[UInt8], Error>? in
            let continuation = pendingReceive?.continuation
            pendingReceive = nil
            return continuation
        }
        continuation?.resume(throwing: CancellationError())
    }

    private static func scriptSteps(from bytes: [UInt8], credentialIsAnonymous: Bool) -> [Step] {
        guard let packets = try? frames(from: bytes) else { return [.packet(bytes)] }
        var result: [Step] = []
        var template: [UInt8]?
        var messageIdShift: UInt64 = 0
        for var packet in packets {
            if isValidateNegotiateTemplate(packet) {
                template = template ?? packet
                if !credentialIsAnonymous, let template {
                    result.append(.validateNegotiate(ValidationStep(template: template, response: nil)))
                    messageIdShift += 1
                }
                continue
            }
            if messageIdShift > 0 {
                let header = try? SMB2Header.decode(packet)
                if let header {
                    writeUInt64LE(header.messageId &+ messageIdShift, to: &packet, at: 24)
                }
            }
            result.append(.packet(packet))
            if !credentialIsAnonymous,
               messageIdShift > 0,
               let template,
               (try? SMB2Header.decode(packet).command) == SMB2Commands.treeConnect {
                result.append(.validateNegotiate(ValidationStep(template: template, response: nil)))
                messageIdShift += 1
            }
        }
        return result
    }

    private static func isValidateNegotiateTemplate(_ packet: [UInt8]) -> Bool {
        guard let header = try? SMB2Header.decode(packet),
              header.command == SMB2Commands.ioctl,
              packet.count >= 72
        else {
            return false
        }
        return readUInt32LE(packet, at: 68) == SMB2ValidateNegotiateInfo.ctlCode
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
        let ntResponse = try readSecurityBuffer(authenticationRequest, at: 20)
        let encryptedSessionKey = try readSecurityBuffer(authenticationRequest, at: 52)
        guard ntResponse.count >= 16, encryptedSessionKey.count == 16 else {
            throw SMBCodecError.invalidValue("NTLM AUTHENTICATE request does not carry an SMB session key")
        }
        let responseKey = try NTLM.ntowfv2(credential: credential)
        let sessionBaseKey = SMBCrypto.hmacMD5(key: responseKey, message: Array(ntResponse.prefix(16)))
        let exportedSessionKey = RC4.crypt(key: sessionBaseKey, message: encryptedSessionKey)
        return SMBCrypto.smb3SigningKey(sessionKey: exportedSessionKey)
    }

    private static func readSecurityBuffer(_ bytes: [UInt8], at offset: Int) throws -> [UInt8] {
        guard offset + 8 <= bytes.count else { throw SMBCodecError.truncated }
        let length = Int(readUInt16LE(bytes, at: offset))
        let bufferOffset = Int(readUInt32LE(bytes, at: offset + 4))
        guard bufferOffset + length <= bytes.count else { throw SMBCodecError.truncated }
        return Array(bytes[bufferOffset..<(bufferOffset + length)])
    }
}

private func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
    UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
}

private func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    UInt32(bytes[offset]) |
        UInt32(bytes[offset + 1]) << 8 |
        UInt32(bytes[offset + 2]) << 16 |
        UInt32(bytes[offset + 3]) << 24
}

private func writeUInt16LE(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
    bytes[offset] = UInt8(value & 0xff)
    bytes[offset + 1] = UInt8(value >> 8)
}

private func writeUInt32LE(_ value: UInt32, to bytes: inout [UInt8], at offset: Int) {
    for index in 0..<4 {
        bytes[offset + index] = UInt8((value >> UInt32(index * 8)) & 0xff)
    }
}

private func writeUInt64LE(_ value: UInt64, to bytes: inout [UInt8], at offset: Int) {
    for index in 0..<8 {
        bytes[offset + index] = UInt8((value >> UInt64(index * 8)) & 0xff)
    }
}

private func appendUInt16LE(_ value: UInt16, to bytes: inout [UInt8]) {
    bytes.append(UInt8(value & 0xff))
    bytes.append(UInt8(value >> 8))
}

private func appendUInt32LE(_ value: UInt32, to bytes: inout [UInt8]) {
    for index in 0..<4 {
        bytes.append(UInt8((value >> UInt32(index * 8)) & 0xff))
    }
}
