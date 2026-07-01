import Foundation

public struct SMBCredential: Sendable {
    public var username: String
    public var password: String
    public var ntHash: [UInt8]?
    public var domain: String
    public var isAnonymous: Bool

    public init(username: String, password: String, domain: String = "") {
        self.username = username
        self.password = password
        self.ntHash = nil
        self.domain = domain
        self.isAnonymous = false
    }

    public init(username: String, ntHash: [UInt8], domain: String = "") throws {
        guard ntHash.count == 16 else {
            throw SMBCodecError.invalidValue("NT hash must be 16 bytes")
        }
        self.username = username
        self.password = ""
        self.ntHash = ntHash
        self.domain = domain
        self.isAnonymous = false
    }

    public static var anonymous: SMBCredential {
        SMBCredential(username: "", password: "", domain: "", isAnonymous: true)
    }

    private init(username: String, password: String, domain: String, isAnonymous: Bool) {
        self.username = username
        self.password = password
        self.ntHash = nil
        self.domain = domain
        self.isAnonymous = isAnonymous
    }
}

public typealias SMBCredentialProvider = @Sendable () async throws -> SMBCredential

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
    static let negotiateAnonymous: UInt32 = 0x0000_0800
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
        serverName: String = "",
        negotiateMessage: [UInt8]? = nil,
        challengeMessage: [UInt8]? = nil,
        timestamp: UInt64 = currentNTTime(),
        clientChallenge: [UInt8] = randomBytes(count: 8),
        exportedSessionKey: [UInt8] = randomBytes(count: 16)
    ) throws -> (message: [UInt8], sessionBaseKey: [UInt8], exportedSessionKey: [UInt8]) {
        if credential.isAnonymous {
            return makeAnonymousType3(challenge: challenge)
        }
        guard clientChallenge.count == 8 else {
            throw SMBCodecError.invalidValue("NTLMv2 client challenge must be 8 bytes")
        }
        guard exportedSessionKey.count == 16 else {
            throw SMBCodecError.invalidValue("NTLMv2 exported session key must be 16 bytes")
        }
        let userBytes = utf16le(credential.username)
        let domainBytes = utf16le(credential.domain)
        let workstationBytes = utf16le("")
        let ntowfv2 = try ntowfv2(credential: credential)
        let includeMIC = targetInfoContainsTimestamp(challenge.targetInfo)
        if includeMIC, negotiateMessage == nil || challengeMessage == nil {
            throw SMBCodecError.invalidValue("NTLM MIC requires type1 and type2 messages")
        }
        let targetInfo = includeMIC ? makeMICCompatibleTargetInfo(challenge.targetInfo, serverName: serverName) : challenge.targetInfo
        // MS-NLMP 3.1.5.1.2: CHALLENGE_MESSAGE の TargetInfo に MsvAvTimestamp(AvId=7) がある場合、
        // blob の TimeStamp フィールドにはサーバ提供の timestamp をそのまま使う (currentNTTime() で
        // 上書きしない)。実 macOS SMBX はこの値で NTProofStr を再計算するため、ずれると LOGON_FAILURE。
        // Samba は許容するため Samba E2E では露見しなかった。
        let effectiveTimestamp = serverTimestamp(from: challenge.targetInfo) ?? timestamp
        // NTLMv2_CLIENT_CHALLENGE (MS-NLMP 2.2.2.7): RespType=1, HiRespType=1, Reserved1=0, Reserved2=0。
        // wire 上は先頭バイトから 01 01 00 00 00 00 00 00。0x0101_0000 を UInt32LE で書くと
        // 00 00 01 01 となり RespType の位置がずれる (実 macOS/Heimdal は canonical header で
        // 再構成・照合するため verify ntlm2 hash failed になる。Samba は client blob をそのまま
        // 使うため露見しなかった)。バイト列で明示する。
        var blob = SMBByteWriter()
        blob.writeBytes([0x01, 0x01, 0x00, 0x00])
        blob.writeUInt32LE(0)
        blob.writeUInt64LE(effectiveTimestamp)
        blob.writeBytes(clientChallenge)
        blob.writeUInt32LE(0)
        blob.writeBytes(targetInfo)
        // MS-NLMP 2.2.2.7: temp = ... || ServerName(=targetInfo, MsvAvEOL 込み) || Z(4)。
        // targetInfo は EOL(0000 0000) で終わるが、その後ろに必ず別の Z(4) を付ける
        // (EOL の 0 と混同して条件付きスキップすると末尾 Z(4) が欠落し、実 macOS/Heimdal が
        // canonical 再構成と照合して verify ntlm2 hash failed になる。Samba は露見せず)。
        blob.writeUInt32LE(0)
        let proof = SMBCrypto.hmacMD5(key: ntowfv2, message: challenge.serverChallenge + blob.bytes)
        let ntChallengeResponse = proof + blob.bytes
        // MS-NLMP 3.1.5.1.2: CHALLENGE_MESSAGE の TargetInfo に MsvAvTimestamp がある場合、
        // client は LmChallengeResponse を Z(24) (24 byte の 0) にする (実 macOS SMBX は非0の
        // LM 応答を拒否する。Samba は許容するため Samba E2E では露見しなかった)。
        let lmChallengeResponse = includeMIC
            ? Array(repeating: UInt8(0), count: 24)
            : SMBCrypto.hmacMD5(
                key: ntowfv2,
                message: challenge.serverChallenge + clientChallenge
            ) + clientChallenge
        let sessionBaseKey = SMBCrypto.hmacMD5(key: ntowfv2, message: proof)
        let encryptedRandomSessionKey = RC4.crypt(key: sessionBaseKey, message: exportedSessionKey)
        let flags = ((negotiateFlags & challenge.flags) | negotiateKeyExchange) & ~negotiateSeal
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

    private static func makeAnonymousType3(
        challenge: NTLMChallenge
    ) -> (message: [UInt8], sessionBaseKey: [UInt8], exportedSessionKey: [UInt8]) {
        let lmChallengeResponse: [UInt8] = [0x00]
        let ntChallengeResponse: [UInt8] = []
        let domainBytes: [UInt8] = []
        let userBytes: [UInt8] = []
        let workstationBytes: [UInt8] = []
        let sessionKey: [UInt8] = []
        // ⓥ MS-NLMP anonymous authenticate has no session key material. Keep sign/seal/key-exchange
        // off even if the server challenge advertises them; real Samba guest E2E should confirm
        // whether any server expects extra negotiated bits preserved here.
        let flags = ((negotiateFlags & challenge.flags) | negotiateAnonymous)
            & ~negotiateSign
            & ~negotiateSeal
            & ~negotiateKeyExchange
            & ~negotiateAlwaysSign

        let fixedSize = 72
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
        let key = appendPayload(sessionKey)

        var writer = SMBByteWriter()
        writer.writeBytes(signature)
        writer.writeUInt32LE(3)
        writeSecurityBuffer(&writer, length: lm.0, offset: lm.1)
        writeSecurityBuffer(&writer, length: nt.0, offset: nt.1)
        writeSecurityBuffer(&writer, length: domain.0, offset: domain.1)
        writeSecurityBuffer(&writer, length: user.0, offset: user.1)
        writeSecurityBuffer(&writer, length: workstation.0, offset: workstation.1)
        writeSecurityBuffer(&writer, length: key.0, offset: key.1)
        writer.writeUInt32LE(flags)
        writer.writeBytes([0x06, 0x01, 0xb1, 0x1d, 0, 0, 0, 0x0f])
        writer.writeBytes(payload)
        return (writer.bytes, [], [])
    }

    static func ntowfv2(password: String, username: String, domain: String) -> [UInt8] {
        let ntHash = MD4.hash(utf16le(password))
        return ntowfv2(ntHash: ntHash, username: username, domain: domain)
    }

    static func ntowfv2(ntHash: [UInt8], username: String, domain: String) -> [UInt8] {
        return SMBCrypto.hmacMD5(key: ntHash, message: utf16le(username.uppercased() + domain))
    }

    static func ntowfv2(credential: SMBCredential) throws -> [UInt8] {
        if let ntHash = credential.ntHash {
            guard ntHash.count == 16 else {
                throw SMBCodecError.invalidValue("NT hash must be 16 bytes")
            }
            return ntowfv2(ntHash: ntHash, username: credential.username, domain: credential.domain)
        }
        return ntowfv2(password: credential.password, username: credential.username, domain: credential.domain)
    }

    static func ntProofStr(ntowfv2: [UInt8], serverChallenge: [UInt8], blob: [UInt8]) -> [UInt8] {
        SMBCrypto.hmacMD5(key: ntowfv2, message: serverChallenge + blob)
    }

    static func clientSigningKey(exportedSessionKey: [UInt8]) -> [UInt8] {
        let magic = Array("session key to client-to-server signing key magic constant".utf8) + [0]
        return SMBCrypto.md5(exportedSessionKey + magic)
    }

    static func clientSealingKey(exportedSessionKey: [UInt8]) -> [UInt8] {
        let magic = Array("session key to client-to-server sealing key magic constant".utf8) + [0]
        return SMBCrypto.md5(exportedSessionKey + magic)
    }

    static func makeMechListMIC(exportedSessionKey: [UInt8], mechList: [UInt8] = SPNEGO.ntlmMechTypeListDER) -> [UInt8] {
        // NTLM MakeSignature (MS-NLMP 3.4.4.1, extended session security, seqnum=0)。
        // NTLMSSP_NEGOTIATE_KEY_EXCH が立っているので checksum を sealing key の RC4 stream で
        // 暗号化する (実 macOS/Heimdal はこれを期待。平文 HMAC のままだと mechListMIC 検証に失敗し
        // GSS_S_DEFECTIVE_TOKEN になる)。SEAL flag は立てていないが KEY_EXCH 経路の MIC では RC4 する。
        let signingKey = clientSigningKey(exportedSessionKey: exportedSessionKey)
        let rawChecksum = Array(SMBCrypto.hmacMD5(key: signingKey, message: [0, 0, 0, 0] + mechList).prefix(8))
        let sealingKey = clientSealingKey(exportedSessionKey: exportedSessionKey)
        let checksum = RC4.crypt(key: sealingKey, message: rawChecksum)
        return [0x01, 0x00, 0x00, 0x00] + checksum + [0x00, 0x00, 0x00, 0x00]
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

    /// TargetInfo の MsvAvTimestamp(AvId=7, 8 byte FILETIME LE) を取り出す。無ければ nil。
    private static func serverTimestamp(from bytes: [UInt8]) -> UInt64? {
        var offset = 0
        while offset + 4 <= bytes.count {
            let avID = readUInt16LE(bytes, at: offset)
            let length = Int(readUInt16LE(bytes, at: offset + 2))
            offset += 4
            if avID == 0 { return nil }
            guard offset + length <= bytes.count else { return nil }
            if avID == 7, length == 8 {
                var value: UInt64 = 0
                for i in 0..<8 { value |= UInt64(bytes[offset + i]) << (8 * i) }
                return value
            }
            offset += length
        }
        return nil
    }

    private static func makeMICCompatibleTargetInfo(_ bytes: [UInt8], serverName: String) -> [UInt8] {
        var result: [UInt8] = []
        var offset = 0
        var hasFlags = false
        var hasTargetName = false
        var hasChannelBindings = false

        while offset + 4 <= bytes.count {
            let avID = readUInt16LE(bytes, at: offset)
            let length = Int(readUInt16LE(bytes, at: offset + 2))
            offset += 4
            if avID == 0 { break }
            guard offset + length <= bytes.count else {
                result.append(contentsOf: bytes[(offset - 4)...])
                appendAVPair(id: 0, value: [], to: &result)
                return result
            }

            let value = Array(bytes[offset..<offset + length])
            switch avID {
            case 6:
                hasFlags = true
                let flags = (length == 4 ? readUInt32LE(value, at: 0) : 0) | 0x00000002
                appendAVPair(
                    id: avID,
                    value: [
                        UInt8(flags & 0xff),
                        UInt8((flags >> 8) & 0xff),
                        UInt8((flags >> 16) & 0xff),
                        UInt8((flags >> 24) & 0xff)
                    ],
                    to: &result
                )
            case 9 where !serverName.isEmpty:
                hasTargetName = true
                // The MIC target name is client-selected, so prefer cifs/<serverName> over a server-sent value.
                appendAVPair(id: avID, value: utf16le("cifs/" + serverName), to: &result)
            case 10:
                hasChannelBindings = true
                appendAVPair(id: avID, value: Array(repeating: 0, count: 16), to: &result)
            default:
                appendAVPair(id: avID, value: value, to: &result)
            }
            offset += length
        }

        if !hasFlags {
            appendAVPair(id: 6, value: [0x02, 0x00, 0x00, 0x00], to: &result)
        }
        if !serverName.isEmpty {
            if !hasTargetName {
                appendAVPair(id: 9, value: utf16le("cifs/" + serverName), to: &result)
            }
            if !hasChannelBindings {
                appendAVPair(id: 10, value: Array(repeating: 0, count: 16), to: &result)
            }
        }
        appendAVPair(id: 0, value: [], to: &result)
        return result
    }

    private static func appendAVPair(id: UInt16, value: [UInt8], to bytes: inout [UInt8]) {
        bytes.append(UInt8(id & 0xff))
        bytes.append(UInt8((id >> 8) & 0xff))
        bytes.append(UInt8(value.count & 0xff))
        bytes.append(UInt8((value.count >> 8) & 0xff))
        bytes.append(contentsOf: value)
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
    private static let ntlmOID: [UInt8] = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
    static let ntlmMechTypeListDER: [UInt8] = derSequence(ntlmOID)

    static func wrapNegTokenInit(_ token: [UInt8]) -> [UInt8] {
        let initToken = derContext(0, ntlmMechTypeListDER) + derContext(2, derOctetString(token))
        return derApplication(0, derOID([0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]) + derContext(0, derSequence(initToken)))
    }

    static func wrapNegTokenResp(_ token: [UInt8], mechListMIC: [UInt8]? = nil) -> [UInt8] {
        var response = derContext(2, derOctetString(token))
        if let mechListMIC {
            response += derContext(3, derOctetString(mechListMIC))
        }
        return derContext(1, derSequence(response))
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
