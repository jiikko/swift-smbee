struct SMB3TransformHeader: Equatable {
    static let encodedSize = 52
    static let protocolId: [UInt8] = [0xfd, 0x53, 0x4d, 0x42]
    static let encryptedFlag: UInt16 = 0x0001

    var signature: [UInt8]
    var nonce: [UInt8]
    var originalMessageSize: UInt32
    var flags: UInt16
    var sessionId: UInt64

    func encode() throws -> [UInt8] {
        guard signature.count == 16 else { throw SMBCodecError.invalidValue("SMB3 transform signature must be 16 bytes") }
        guard nonce.count == 16 else { throw SMBCodecError.invalidValue("SMB3 transform nonce must be 16 bytes") }
        var writer = SMBByteWriter()
        writer.writeBytes(Self.protocolId)
        writer.writeBytes(signature)
        writer.writeBytes(nonce)
        writer.writeUInt32LE(originalMessageSize)
        writer.writeUInt16LE(0)
        writer.writeUInt16LE(flags)
        writer.writeUInt64LE(sessionId)
        return writer.bytes
    }

    func authenticatedData() throws -> [UInt8] {
        let encoded = try encode()
        // MS-SMB2 2.2.41 / 3.1.4.3: SMB3 transform AAD excludes ProtocolId
        // and Signature and covers Nonce through SessionId.
        return Array(encoded[20..<Self.encodedSize])
    }

    static func decode(_ bytes: [UInt8]) throws -> SMB3TransformHeader {
        guard bytes.count >= encodedSize else { throw SMBCodecError.truncated }
        var reader = SMBByteReader(bytes: bytes)
        guard try reader.readBytes(count: 4) == protocolId else {
            throw SMBCodecError.invalidValue("invalid SMB3 transform protocol id")
        }
        let signature = try reader.readBytes(count: 16)
        let nonce = try reader.readBytes(count: 16)
        let originalMessageSize = try reader.readUInt32LE()
        let reserved = try reader.readUInt16LE()
        let flags = try reader.readUInt16LE()
        let sessionId = try reader.readUInt64LE()
        guard reserved == 0 else { throw SMBCodecError.invalidValue("invalid SMB3 transform reserved field") }
        return SMB3TransformHeader(
            signature: signature,
            nonce: nonce,
            originalMessageSize: originalMessageSize,
            flags: flags,
            sessionId: sessionId
        )
    }
}
