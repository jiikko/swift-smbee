import Foundation

public struct SMBProbeResult: Equatable, Sendable {
    public var dialect: UInt16
    public var signingRequired: Bool
    public var signingAlgorithm: UInt16?
    public var cipher: UInt16?
    public var preauthHashAlgorithm: UInt16?
    public var serverGuid: UUID
}

public enum SMBNegotiateConstants {
    public static let commandNegotiate: UInt16 = 0
    public static let dialect311: UInt16 = 0x0311
    public static let signingRequired: UInt16 = 0x0002
    public static let globalCapEncryption: UInt32 = 0x0000_0040
    public static let preauthContext: UInt16 = 0x0001
    public static let encryptionContext: UInt16 = 0x0002
    public static let signingContext: UInt16 = 0x0008
    public static let sha512: UInt16 = 0x0001
    public static let aes128GCM: UInt16 = 0x0002
    public static let aes256GCM: UInt16 = 0x0004
    public static let aesGMAC: UInt16 = 0x0002
}

public enum SMBNegotiateCodec {
    public static func encodeRequest(
        clientGuid: UUID,
        messageId: UInt64 = 0,
        salt: [UInt8] = Array(repeating: 0, count: 32)
    ) throws -> [UInt8] {
        let contexts = encodeNegotiateContexts(salt: salt)
        let header = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: messageId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(36)
        writer.writeUInt16LE(1)
        writer.writeUInt16LE(0)
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(SMBNegotiateConstants.globalCapEncryption)
        writer.writeBytes(clientGuid.smbWireBytes)
        writer.writeUInt32LE(UInt32(header.count + 36 + 8))
        writer.writeUInt16LE(3)
        writer.writeUInt16LE(0)
        writer.writeUInt16LE(SMBNegotiateConstants.dialect311)
        writer.writeBytes(Array(repeating: 0, count: 6))
        writer.writeBytes(contexts)
        return writer.bytes
    }

    public static func decodeResponse(_ bytes: [UInt8]) throws -> SMBProbeResult {
        let header = try SMB2Header.decode(bytes)
        guard header.command == SMBNegotiateConstants.commandNegotiate else {
            throw SMBCodecError.invalidValue("not an SMB2 NEGOTIATE response")
        }
        guard header.status == 0 else {
            throw SMBCodecError.invalidValue(String(format: "NEGOTIATE failed with NTSTATUS 0x%08x", header.status))
        }
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 65 else {
            throw SMBCodecError.invalidValue("invalid NEGOTIATE response structure size")
        }
        let securityMode = try reader.readUInt16LE()
        let dialect = try reader.readUInt16LE()
        let contextCount = try reader.readUInt16LE()
        let serverGuid = try UUID(smbWireBytes: reader.readBytes(count: 16))
        try reader.skip(count: 4 + 4 + 4 + 4 + 8 + 8)
        let securityBufferOffset = try reader.readUInt16LE()
        let securityBufferLength = try reader.readUInt16LE()
        let contextOffset = try reader.readUInt32LE()
        _ = securityBufferOffset
        _ = securityBufferLength

        var signingAlgorithm: UInt16?
        var cipher: UInt16?
        var preauthHashAlgorithm: UInt16?
        if contextOffset > 0, contextCount > 0 {
            var offset = Int(contextOffset)
            for _ in 0..<contextCount {
                guard offset + 8 <= bytes.count else { throw SMBCodecError.truncated }
                var contextReader = SMBByteReader(bytes: Array(bytes[offset..<bytes.count]))
                let type = try contextReader.readUInt16LE()
                let length = Int(try contextReader.readUInt16LE())
                try contextReader.skip(count: 4)
                let data = try contextReader.readBytes(count: length)
                switch type {
                case SMBNegotiateConstants.preauthContext:
                    var dataReader = SMBByteReader(bytes: data)
                    let algorithmCount = try dataReader.readUInt16LE()
                    let saltLength = try dataReader.readUInt16LE()
                    if algorithmCount > 0 {
                        preauthHashAlgorithm = try dataReader.readUInt16LE()
                    }
                    _ = saltLength
                case SMBNegotiateConstants.encryptionContext:
                    var dataReader = SMBByteReader(bytes: data)
                    let count = try dataReader.readUInt16LE()
                    if count > 0 {
                        cipher = try dataReader.readUInt16LE()
                    }
                case SMBNegotiateConstants.signingContext:
                    var dataReader = SMBByteReader(bytes: data)
                    let count = try dataReader.readUInt16LE()
                    if count > 0 {
                        signingAlgorithm = try dataReader.readUInt16LE()
                    }
                default:
                    break
                }
                offset += 8 + paddedLength(length)
            }
        }

        return SMBProbeResult(
            dialect: dialect,
            signingRequired: (securityMode & SMBNegotiateConstants.signingRequired) != 0,
            signingAlgorithm: signingAlgorithm,
            cipher: cipher,
            preauthHashAlgorithm: preauthHashAlgorithm,
            serverGuid: serverGuid
        )
    }

    private static func encodeNegotiateContexts(salt: [UInt8]) -> [UInt8] {
        var bytes: [UInt8] = []
        appendContext(type: SMBNegotiateConstants.preauthContext, data: encodePreauthData(salt: salt), to: &bytes)
        appendContext(type: SMBNegotiateConstants.encryptionContext, data: encodeEncryptionData(), to: &bytes)
        appendContext(type: SMBNegotiateConstants.signingContext, data: encodeSigningData(), to: &bytes)
        return bytes
    }

    private static func encodePreauthData(salt: [UInt8]) -> [UInt8] {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(1)
        writer.writeUInt16LE(UInt16(salt.count))
        writer.writeUInt16LE(SMBNegotiateConstants.sha512)
        writer.writeBytes(salt)
        return writer.bytes
    }

    private static func encodeEncryptionData() -> [UInt8] {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(2)
        writer.writeUInt16LE(SMBNegotiateConstants.aes128GCM)
        writer.writeUInt16LE(SMBNegotiateConstants.aes256GCM)
        return writer.bytes
    }

    private static func encodeSigningData() -> [UInt8] {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(1)
        writer.writeUInt16LE(SMBNegotiateConstants.aesGMAC)
        return writer.bytes
    }

    private static func appendContext(type: UInt16, data: [UInt8], to bytes: inout [UInt8]) {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(type)
        writer.writeUInt16LE(UInt16(data.count))
        writer.writeUInt32LE(0)
        writer.writeBytes(data)
        writer.padTo8()
        bytes.append(contentsOf: writer.bytes)
    }

    private static func paddedLength(_ length: Int) -> Int {
        ((length + 7) / 8) * 8
    }
}

extension UUID {
    var smbWireBytes: [UInt8] {
        let tuple = uuid
        return [
            tuple.0, tuple.1, tuple.2, tuple.3,
            tuple.4, tuple.5, tuple.6, tuple.7,
            tuple.8, tuple.9, tuple.10, tuple.11,
            tuple.12, tuple.13, tuple.14, tuple.15,
        ]
    }

    init(smbWireBytes bytes: [UInt8]) throws {
        guard bytes.count == 16 else { throw SMBCodecError.invalidValue("UUID must be 16 bytes") }
        self.init(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}
