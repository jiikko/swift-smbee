import Foundation

public struct SMBCredential: Sendable {
    public var username: String
    public var password: String
    public var domain: String

    public init(username: String, password: String, domain: String = "") {
        self.username = username
        self.password = password
        self.domain = domain
    }
}

struct NTLMChallenge {
    var targetName: [UInt8]
    var flags: UInt32
    var serverChallenge: [UInt8]
    var targetInfo: [UInt8]
}

enum NTLM {
    static let signature = Array("NTLMSSP\0".utf8)
    static let negotiateUnicode: UInt32 = 0x0000_0001
    static let requestTarget: UInt32 = 0x0000_0004
    static let negotiateSign: UInt32 = 0x0000_0010
    static let negotiateSeal: UInt32 = 0x0000_0020
    static let negotiateNTLM: UInt32 = 0x0000_0200
    static let negotiateAlwaysSign: UInt32 = 0x0000_8000
    static let negotiateExtendedSessionSecurity: UInt32 = 0x0008_0000
    static let negotiateTargetInfo: UInt32 = 0x0080_0000
    static let negotiateVersion: UInt32 = 0x0200_0000
    static let negotiate128: UInt32 = 0x2000_0000
    static let negotiateKeyExchange: UInt32 = 0x4000_0000
    static let negotiate56: UInt32 = 0x8000_0000

    static let negotiateFlags: UInt32 = negotiateUnicode
        | requestTarget
        | negotiateSign
        | negotiateSeal
        | negotiateNTLM
        | negotiateAlwaysSign
        | negotiateExtendedSessionSecurity
        | negotiateTargetInfo
        | negotiateVersion
        | negotiate128
        | negotiateKeyExchange
        | negotiate56

    static func makeType1(domain: String = "", workstation: String = "") -> [UInt8] {
        let domainBytes = Array(domain.uppercased().utf8)
        let workstationBytes = Array(workstation.uppercased().utf8)
        var writer = SMBByteWriter()
        writer.writeBytes(signature)
        writer.writeUInt32LE(1)
        writer.writeUInt32LE(negotiateFlags)
        let domainOffset = UInt32(40)
        let workstationOffset = domainOffset + UInt32(domainBytes.count)
        writeSecurityBuffer(&writer, length: domainBytes.count, offset: domainOffset)
        writeSecurityBuffer(&writer, length: workstationBytes.count, offset: workstationOffset)
        writer.writeBytes([0x06, 0x01, 0xb1, 0x1d, 0, 0, 0, 0x0f])
        writer.writeBytes(domainBytes)
        writer.writeBytes(workstationBytes)
        return writer.bytes
    }

    static func parseChallenge(_ message: [UInt8]) throws -> NTLMChallenge {
        guard message.count >= 48, Array(message[0..<8]) == signature else {
            throw SMBCodecError.invalidValue("invalid NTLM challenge signature")
        }
        guard readUInt32LE(message, at: 8) == 2 else {
            throw SMBCodecError.invalidValue("not an NTLM challenge")
        }
        let target = try readSecurityBuffer(message, at: 12)
        let flags = readUInt32LE(message, at: 20)
        let challenge = Array(message[24..<32])
        let targetInfo = message.count >= 48 ? (try readSecurityBuffer(message, at: 40)) : []
        return NTLMChallenge(targetName: target, flags: flags, serverChallenge: challenge, targetInfo: targetInfo)
    }

    static func makeType3(
        credential: SMBCredential,
        challenge: NTLMChallenge,
        negotiateMessage: [UInt8]? = nil,
        challengeMessage: [UInt8]? = nil,
        timestamp: UInt64 = currentNTTime(),
        clientChallenge: [UInt8] = randomBytes(count: 8),
        exportedSessionKey: [UInt8] = randomBytes(count: 16)
    ) throws -> (message: [UInt8], sessionBaseKey: [UInt8], exportedSessionKey: [UInt8]) {
        guard clientChallenge.count == 8 else {
            throw SMBCodecError.invalidValue("NTLMv2 client challenge must be 8 bytes")
        }
        guard exportedSessionKey.count == 16 else {
            throw SMBCodecError.invalidValue("NTLMv2 exported session key must be 16 bytes")
        }
        let userBytes = utf16le(credential.username)
        let domainBytes = utf16le(credential.domain)
        let workstationBytes = utf16le("")
        let ntowfv2 = ntowfv2(password: credential.password, username: credential.username, domain: credential.domain)
        var blob = SMBByteWriter()
        blob.writeUInt32LE(0x0101_0000)
        blob.writeUInt32LE(0)
        blob.writeUInt64LE(timestamp)
        blob.writeBytes(clientChallenge)
        blob.writeUInt32LE(0)
        blob.writeBytes(challenge.targetInfo)
        if !challenge.targetInfo.suffix(4).allSatisfy({ $0 == 0 }) {
            blob.writeUInt32LE(0)
        }
        let proof = SMBCrypto.hmacMD5(key: ntowfv2, message: challenge.serverChallenge + blob.bytes)
        let ntChallengeResponse = proof + blob.bytes
        let lmChallengeResponse = SMBCrypto.hmacMD5(
            key: ntowfv2,
            message: challenge.serverChallenge + clientChallenge
        ) + clientChallenge
        let sessionBaseKey = SMBCrypto.hmacMD5(key: ntowfv2, message: proof)
        let encryptedRandomSessionKey = RC4.crypt(key: sessionBaseKey, message: exportedSessionKey)
        let includeMIC = targetInfoContainsTimestamp(challenge.targetInfo)
        if includeMIC, negotiateMessage == nil || challengeMessage == nil {
            throw SMBCodecError.invalidValue("NTLM MIC requires type1 and type2 messages")
        }
        let flags = (negotiateFlags & challenge.flags) | negotiateKeyExchange
        let fixedSize = includeMIC ? 88 : 72
        var payloadOffset = UInt32(fixedSize)
        var payload: [UInt8] = []
        func appendPayload(_ bytes: [UInt8]) -> (Int, UInt32) {
            let result = (bytes.count, payloadOffset)
            payload += bytes
            payloadOffset += UInt32(bytes.count)
            return result
        }
        let lm = appendPayload(lmChallengeResponse)
        let nt = appendPayload(ntChallengeResponse)
        let domain = appendPayload(domainBytes)
        let user = appendPayload(userBytes)
        let workstation = appendPayload(workstationBytes)
        let sessionKey = appendPayload(encryptedRandomSessionKey)

        var writer = SMBByteWriter()
        writer.writeBytes(signature)
        writer.writeUInt32LE(3)
        writeSecurityBuffer(&writer, length: lm.0, offset: lm.1)
        writeSecurityBuffer(&writer, length: nt.0, offset: nt.1)
        writeSecurityBuffer(&writer, length: domain.0, offset: domain.1)
        writeSecurityBuffer(&writer, length: user.0, offset: user.1)
        writeSecurityBuffer(&writer, length: workstation.0, offset: workstation.1)
        writeSecurityBuffer(&writer, length: sessionKey.0, offset: sessionKey.1)
        writer.writeUInt32LE(flags)
        writer.writeBytes([0x06, 0x01, 0xb1, 0x1d, 0, 0, 0, 0x0f])
        if includeMIC {
            writer.writeBytes(Array(repeating: 0, count: 16))
        }
        writer.writeBytes(payload)
        var message = writer.bytes
        if includeMIC, let negotiateMessage, let challengeMessage {
            let mic = SMBCrypto.hmacMD5(key: exportedSessionKey, message: negotiateMessage + challengeMessage + message)
            message.replaceSubrange(72..<88, with: mic)
        }
        return (message, sessionBaseKey, exportedSessionKey)
    }

    static func ntowfv2(password: String, username: String, domain: String) -> [UInt8] {
        let ntHash = MD4.hash(utf16le(password))
        return SMBCrypto.hmacMD5(key: ntHash, message: utf16le(username.uppercased() + domain))
    }

    static func ntProofStr(ntowfv2: [UInt8], serverChallenge: [UInt8], blob: [UInt8]) -> [UInt8] {
        SMBCrypto.hmacMD5(key: ntowfv2, message: serverChallenge + blob)
    }

    static func utf16le(_ string: String) -> [UInt8] {
        string.utf16.flatMap { [UInt8($0 & 0xff), UInt8(($0 >> 8) & 0xff)] }
    }

    private static func writeSecurityBuffer(_ writer: inout SMBByteWriter, length: Int, offset: UInt32) {
        writer.writeUInt16LE(UInt16(length))
        writer.writeUInt16LE(UInt16(length))
        writer.writeUInt32LE(offset)
    }

    private static func readSecurityBuffer(_ message: [UInt8], at offset: Int) throws -> [UInt8] {
        let length = Int(readUInt16LE(message, at: offset))
        let bufferOffset = Int(readUInt32LE(message, at: offset + 4))
        guard bufferOffset + length <= message.count else { throw SMBCodecError.truncated }
        return Array(message[bufferOffset..<bufferOffset + length])
    }

    private static func targetInfoContainsTimestamp(_ bytes: [UInt8]) -> Bool {
        var offset = 0
        while offset + 4 <= bytes.count {
            let avID = readUInt16LE(bytes, at: offset)
            let length = Int(readUInt16LE(bytes, at: offset + 2))
            offset += 4
            if avID == 0 { return false }
            if avID == 7 { return true }
            guard offset + length <= bytes.count else { return false }
            offset += length
        }
        return false
    }

    private static func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func currentNTTime() -> UInt64 {
        UInt64((Date().timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
    }

    private static func randomBytes(count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
    }
}

enum RC4 {
    static func crypt(key: [UInt8], message: [UInt8]) -> [UInt8] {
        precondition(!key.isEmpty, "RC4 key must not be empty")
        var state = Array(UInt8.min...UInt8.max)
        var j = 0
        for index in 0..<256 {
            j = (j + Int(state[index]) + Int(key[index % key.count])) & 0xff
            state.swapAt(index, j)
        }
        var i = 0
        j = 0
        return message.map { byte in
            i = (i + 1) & 0xff
            j = (j + Int(state[i])) & 0xff
            state.swapAt(i, j)
            let keyStreamByte = state[(Int(state[i]) + Int(state[j])) & 0xff]
            return byte ^ keyStreamByte
        }
    }
}

enum SPNEGO {
    static func wrapNegTokenInit(_ token: [UInt8]) -> [UInt8] {
        let ntlmOID: [UInt8] = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
        let mechTypes = derSequence(ntlmOID)
        let initToken = derContext(0, mechTypes) + derContext(2, derOctetString(token))
        return derApplication(0, derOID([0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]) + derContext(0, derSequence(initToken)))
    }

    static func wrapNegTokenResp(_ token: [UInt8]) -> [UInt8] {
        derContext(1, derSequence(derContext(2, derOctetString(token))))
    }

    static func unwrapNTLMToken(_ bytes: [UInt8]) throws -> [UInt8] {
        if let index = bytes.firstRange(of: NTLM.signature)?.lowerBound {
            return Array(bytes[index..<bytes.count])
        }
        throw SMBCodecError.invalidValue("SPNEGO response did not contain NTLMSSP token")
    }

    private static func derApplication(_ tag: UInt8, _ value: [UInt8]) -> [UInt8] {
        [0x60 | tag] + derLength(value.count) + value
    }

    private static func derContext(_ tag: UInt8, _ value: [UInt8]) -> [UInt8] {
        [0xa0 | tag] + derLength(value.count) + value
    }

    private static func derSequence(_ value: [UInt8]) -> [UInt8] {
        [0x30] + derLength(value.count) + value
    }

    private static func derOctetString(_ value: [UInt8]) -> [UInt8] {
        [0x04] + derLength(value.count) + value
    }

    private static func derOID(_ value: [UInt8]) -> [UInt8] {
        [0x06] + derLength(value.count) + value
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        precondition(length >= 0, "DER length must be non-negative")
        if length < 0x80 { return [UInt8(length)] }
        var value = length
        var octets: [UInt8] = []
        while value > 0 {
            octets.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(octets.count)] + octets
    }
}
