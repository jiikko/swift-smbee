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
    public static let dialect202: UInt16 = 0x0202
    public static let dialect210: UInt16 = 0x0210
    public static let dialect300: UInt16 = 0x0300
    public static let dialect302: UInt16 = 0x0302
    public static let dialect311: UInt16 = 0x0311
    public static let signingEnabled: UInt16 = 0x0001
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
    private static let negotiateContextCount: UInt16 = 3
    private static let offeredDialects: [UInt16] = [
        SMBNegotiateConstants.dialect202,
        SMBNegotiateConstants.dialect210,
        SMBNegotiateConstants.dialect300,
        SMBNegotiateConstants.dialect302,
        SMBNegotiateConstants.dialect311,
    ]

    public static func encodeRequest(
        clientGuid: UUID,
        messageId: UInt64 = 0,
        salt: [UInt8] = Array(repeating: 0, count: 32)
    ) throws -> [UInt8] {
        let contexts = encodeNegotiateContexts(salt: salt)
        let header = try SMB2Header(command: SMBNegotiateConstants.commandNegotiate, messageId: messageId).encode()
        let dialectBytes = MemoryLayout<UInt16>.size * offeredDialects.count
        let fixedBodySize = 36
        let contextOffset = alignedTo8(header.count + fixedBodySize + dialectBytes)
        let paddingLength = contextOffset - (header.count + fixedBodySize + dialectBytes)

        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(36)
        writer.writeUInt16LE(UInt16(offeredDialects.count))
        writer.writeUInt16LE(SMBNegotiateConstants.signingEnabled)
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(SMBNegotiateConstants.globalCapEncryption)
        writer.writeBytes(clientGuid.smbWireBytes)
        // MS-SMB2 2.2.3 requires NegotiateContextOffset to be relative to the
        // SMB2 header start and 8-byte aligned when dialect 0x0311 is offered.
        writer.writeUInt32LE(UInt32(contextOffset))
        writer.writeUInt16LE(negotiateContextCount)
        writer.writeUInt16LE(0)
        for dialect in offeredDialects {
            writer.writeUInt16LE(dialect)
        }
        writer.writeBytes(Array(repeating: 0, count: paddingLength))
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
        if dialect == SMBNegotiateConstants.dialect311, contextCount > 0 {
            guard contextOffset >= SMB2Header.encodedSize + 65,
                  contextOffset % 8 == 0,
                  contextOffset < bytes.count
            else {
                throw SMBCodecError.invalidValue("invalid NEGOTIATE context offset")
            }
            var offset = Int(contextOffset)
            for _ in 0..<contextCount {
                guard offset + 8 <= bytes.count else { throw SMBCodecError.truncated }
                var contextReader = SMBByteReader(bytes: Array(bytes[offset..<bytes.count]))
                let type = try contextReader.readUInt16LE()
                let length = Int(try contextReader.readUInt16LE())
                try contextReader.skip(count: 4)
                guard offset + 8 + length <= bytes.count else { throw SMBCodecError.truncated }
                let data = try contextReader.readBytes(count: length)
                switch type {
                case SMBNegotiateConstants.preauthContext:
                    var dataReader = SMBByteReader(bytes: data)
                    let algorithmCount = try dataReader.readUInt16LE()
                    let saltLength = try dataReader.readUInt16LE()
                    guard length >= 4 + Int(algorithmCount) * 2 + Int(saltLength) else {
                        throw SMBCodecError.invalidValue("invalid PREAUTH context length")
                    }
                    if algorithmCount > 0 {
                        preauthHashAlgorithm = try dataReader.readUInt16LE()
                    }
                    _ = saltLength
                case SMBNegotiateConstants.encryptionContext:
                    var dataReader = SMBByteReader(bytes: data)
                    let count = try dataReader.readUInt16LE()
                    guard length == 2 + Int(count) * 2 else {
                        throw SMBCodecError.invalidValue("invalid ENCRYPTION context length")
                    }
                    if count > 0 {
                        cipher = try dataReader.readUInt16LE()
                    }
                case SMBNegotiateConstants.signingContext:
                    var dataReader = SMBByteReader(bytes: data)
                    let count = try dataReader.readUInt16LE()
                    guard length == 2 + Int(count) * 2 else {
                        throw SMBCodecError.invalidValue("invalid SIGNING context length")
                    }
                    if count > 0 {
                        signingAlgorithm = try dataReader.readUInt16LE()
                    }
                default:
                    break
                }
                let nextOffset = offset + 8 + paddedLength(length)
                guard nextOffset <= bytes.count else { throw SMBCodecError.truncated }
                offset = nextOffset
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
        appendContext(type: SMBNegotiateConstants.preauthContext, data: encodePreauthData(salt: salt), padTo8: true, to: &bytes)
        appendContext(type: SMBNegotiateConstants.encryptionContext, data: encodeEncryptionData(), padTo8: true, to: &bytes)
        appendContext(type: SMBNegotiateConstants.signingContext, data: encodeSigningData(), padTo8: false, to: &bytes)
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

    private static func appendContext(type: UInt16, data: [UInt8], padTo8: Bool, to bytes: inout [UInt8]) {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(type)
        writer.writeUInt16LE(UInt16(data.count))
        writer.writeUInt32LE(0)
        writer.writeBytes(data)
        if padTo8 {
            writer.padTo8()
        }
        bytes.append(contentsOf: writer.bytes)
    }

    private static func paddedLength(_ length: Int) -> Int {
        alignedTo8(length)
    }

    private static func alignedTo8(_ length: Int) -> Int {
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
