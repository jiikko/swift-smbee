import Foundation

public struct SMB2Header: Equatable, Sendable {
    public static let encodedSize = 64

    public var creditCharge: UInt16
    public var status: UInt32
    public var command: UInt16
    public var credits: UInt16
    public var flags: UInt32
    public var nextCommand: UInt32
    public var messageId: UInt64
    public var treeId: UInt32
    public var sessionId: UInt64
    public var signature: [UInt8]

    public init(
        creditCharge: UInt16 = 0,
        status: UInt32 = 0,
        command: UInt16,
        credits: UInt16 = 1,
        flags: UInt32 = 0,
        nextCommand: UInt32 = 0,
        messageId: UInt64,
        treeId: UInt32 = 0,
        sessionId: UInt64 = 0,
        signature: [UInt8] = Array(repeating: 0, count: 16)
    ) {
        self.creditCharge = creditCharge
        self.status = status
        self.command = command
        self.credits = credits
        self.flags = flags
        self.nextCommand = nextCommand
        self.messageId = messageId
        self.treeId = treeId
        self.sessionId = sessionId
        self.signature = signature
    }

    public func encode() throws -> [UInt8] {
        guard signature.count == 16 else {
            throw SMBCodecError.invalidValue("SMB2 signature must be 16 bytes")
        }
        var writer = SMBByteWriter()
        writer.writeBytes([0xfe, 0x53, 0x4d, 0x42])
        writer.writeUInt16LE(64)
        writer.writeUInt16LE(creditCharge)
        writer.writeUInt32LE(status)
        writer.writeUInt16LE(command)
        writer.writeUInt16LE(credits)
        writer.writeUInt32LE(flags)
        writer.writeUInt32LE(nextCommand)
        writer.writeUInt64LE(messageId)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(treeId)
        writer.writeUInt64LE(sessionId)
        writer.writeBytes(signature)
        return writer.bytes
    }

    public static func decode(_ bytes: [UInt8]) throws -> SMB2Header {
        guard bytes.count >= encodedSize else { throw SMBCodecError.truncated }
        var reader = SMBByteReader(bytes: bytes)
        let protocolId = try reader.readBytes(count: 4)
        guard protocolId == [0xfe, 0x53, 0x4d, 0x42] else {
            throw SMBCodecError.invalidValue(
                "invalid SMB2 protocol id: firstBytes=\(SMBDebug.hexPrefix(bytes, count: 32)) length=\(bytes.count)"
            )
        }
        guard try reader.readUInt16LE() == 64 else {
            throw SMBCodecError.invalidValue("invalid SMB2 header size")
        }
        let creditCharge = try reader.readUInt16LE()
        let status = try reader.readUInt32LE()
        let command = try reader.readUInt16LE()
        let credits = try reader.readUInt16LE()
        let flags = try reader.readUInt32LE()
        let nextCommand = try reader.readUInt32LE()
        let messageId = try reader.readUInt64LE()
        try reader.skip(count: 4)
        let treeId = try reader.readUInt32LE()
        let sessionId = try reader.readUInt64LE()
        let signature = try reader.readBytes(count: 16)
        return SMB2Header(
            creditCharge: creditCharge,
            status: status,
            command: command,
            credits: credits,
            flags: flags,
            nextCommand: nextCommand,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId,
            signature: signature
        )
    }
}
