import Foundation

enum SMB2Commands {
    static let sessionSetup: UInt16 = 1
    static let treeConnect: UInt16 = 3
    static let create: UInt16 = 5
    static let close: UInt16 = 6
    static let read: UInt16 = 8
    static let queryInfo: UInt16 = 16
    static let queryDirectory: UInt16 = 14
}

enum SMB2SessionSetup {
    static func encodeRequest(messageId: UInt64, sessionId: UInt64, securityBlob: [UInt8], signed: Bool) throws -> [UInt8] {
        let header = try SMB2Header(
            command: SMB2Commands.sessionSetup,
            flags: signed ? SMB2Flags.signed : 0,
            messageId: messageId,
            sessionId: sessionId
        ).encode()
        let securityOffset = SMB2Header.encodedSize + 24
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(25)
        writer.writeUInt8(0)
        writer.writeUInt8(1)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt16LE(UInt16(securityOffset))
        writer.writeUInt16LE(UInt16(securityBlob.count))
        writer.writeUInt64LE(0)
        writer.writeBytes(securityBlob)
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws -> [UInt8] {
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 9 else {
            throw SMBCodecError.invalidValue("invalid SESSION_SETUP response structure size")
        }
        try reader.skip(count: 2)
        let offset = Int(try reader.readUInt16LE())
        let length = Int(try reader.readUInt16LE())
        guard offset + length <= bytes.count else { throw SMBCodecError.truncated }
        return Array(bytes[offset..<offset + length])
    }
}

enum SMB2TreeConnect {
    static func encodeRequest(messageId: UInt64, sessionId: UInt64, path: String) throws -> [UInt8] {
        let header = try SMB2Header(command: SMB2Commands.treeConnect, messageId: messageId, sessionId: sessionId).encode()
        let pathBytes = NTLM.utf16le(path)
        let pathOffset = SMB2Header.encodedSize + 8
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(9)
        writer.writeUInt16LE(0)
        writer.writeUInt16LE(UInt16(pathOffset))
        writer.writeUInt16LE(UInt16(pathBytes.count))
        writer.writeBytes(pathBytes)
        return writer.bytes
    }
}

enum SMB2Create {
    private static let fixedPartSize = 56
    private static let nameOffset = SMB2Header.encodedSize + fixedPartSize
    private static let responseFileIdOffset = SMB2Header.encodedSize + 64

    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32, path: String, directory: Bool) throws -> [UInt8] {
        let header = try SMB2Header(command: SMB2Commands.create, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        let nameBytes = NTLM.utf16le(relativeCreateName(path))
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(57)
        writer.writeUInt8(0)
        writer.writeUInt8(0)
        writer.writeUInt32LE(0x0000_0002)
        writer.writeUInt64LE(0)
        writer.writeUInt64LE(0)
        writer.writeUInt32LE(directory ? 0x0000_0089 : 0x0000_0081)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0x0000_0007)
        writer.writeUInt32LE(0x0000_0001)
        writer.writeUInt32LE(directory ? 0x0000_0001 : 0x0000_0040)
        writer.writeUInt16LE(UInt16(nameOffset))
        writer.writeUInt16LE(UInt16(nameBytes.count))
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeBytes(nameBytes.isEmpty ? [0] : nameBytes)
        return writer.bytes
    }

    private static func relativeCreateName(_ path: String) -> String {
        path.trimmingCharacters(in: CharacterSet(charactersIn: "\\/"))
    }

    static func decodeFileId(_ bytes: [UInt8]) throws -> [UInt8] {
        let header = try SMB2Header.decode(bytes)
        guard header.status == SMB2Status.success else {
            throw SMBCodecError.invalidValue(String(format: "CREATE failed with NTSTATUS 0x%08x", header.status))
        }
        let offset = responseFileIdOffset
        guard bytes.count >= offset + 16 else { throw SMBCodecError.truncated }
        return Array(bytes[offset..<offset + 16])
    }
}

enum SMB2QueryInfo {
    private static let fixedPartSize = 40
    private static let bufferOffset = SMB2Header.encodedSize + fixedPartSize

    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32, fileId: [UInt8]) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.queryInfo, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(41)
        writer.writeUInt8(0x01)
        writer.writeUInt8(34)
        writer.writeUInt32LE(65_536)
        writer.writeUInt16LE(UInt16(bufferOffset))
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeBytes(fileId)
        // MS-SMB2 QUERY_INFO has a variable Buffer[] field; Samba accepts a one byte pad when InputBufferLength is 0.
        writer.writeUInt8(0)
        return writer.bytes
    }

    static func decodeNetworkOpenInformation(_ bytes: [UInt8]) throws -> SMBFileStat {
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 9 else {
            throw SMBCodecError.invalidValue("invalid QUERY_INFO response structure size")
        }
        let offset = Int(try reader.readUInt16LE())
        let length = Int(try reader.readUInt32LE())
        guard offset + length <= bytes.count else { throw SMBCodecError.truncated }
        let data = Array(bytes[offset..<offset + length])
        guard data.count >= 56 else { throw SMBCodecError.truncated }
        let lastWriteTime = readUInt64LE(data, at: 24)
        let endOfFile = readUInt64LE(data, at: 40)
        let attributes = readUInt32LE(data, at: 52)
        return SMBFileStat(size: endOfFile, modifiedTime: filetimeToDate(lastWriteTime), isDirectory: (attributes & 0x10) != 0)
    }
}

enum SMB2Read {
    private static let fixedPartSize = 48
    private static let bufferOffset = SMB2Header.encodedSize + fixedPartSize

    static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        length: UInt32
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.read, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(49)
        // MS-SMB2 READ Padding is reserved; 0x50 is the conventional SMB2 header + fixed prefix offset used by clients.
        writer.writeUInt8(0x50)
        writer.writeUInt8(0)
        writer.writeUInt32LE(length)
        writer.writeUInt64LE(offset)
        writer.writeBytes(fileId)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt16LE(0)
        writer.writeUInt16LE(0)
        // MS-SMB2 READ has a variable Buffer[] field; keep one byte pad for Samba compatibility.
        writer.writeUInt8(0)
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws -> [UInt8] {
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 17 else {
            throw SMBCodecError.invalidValue("invalid READ response structure size")
        }
        let dataOffset = Int(try reader.readUInt8())
        try reader.skip(count: 1)
        let dataLength = Int(try reader.readUInt32LE())
        guard dataOffset + dataLength <= bytes.count else { throw SMBCodecError.truncated }
        return Array(bytes[dataOffset..<dataOffset + dataLength])
    }
}

enum SMB2QueryDirectory {
    private static let fixedPartSize = 32
    private static let fileNameOffset = SMB2Header.encodedSize + fixedPartSize

    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32, fileId: [UInt8]) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(33)
        writer.writeUInt8(37)
        writer.writeUInt8(0x01)
        writer.writeUInt32LE(0)
        writer.writeBytes(fileId)
        writer.writeUInt16LE(UInt16(fileNameOffset))
        writer.writeUInt16LE(2)
        writer.writeUInt32LE(65_536)
        writer.writeBytes([0x2a, 0x00])
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws -> [SMBDirectoryEntry] {
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 9 else {
            throw SMBCodecError.invalidValue("invalid QUERY_DIRECTORY response structure size")
        }
        let offset = Int(try reader.readUInt16LE())
        let length = Int(try reader.readUInt32LE())
        guard offset + length <= bytes.count else { throw SMBCodecError.truncated }
        let data = Array(bytes[offset..<offset + length])
        var entries: [SMBDirectoryEntry] = []
        var entryOffset = 0
        while entryOffset + 104 <= data.count {
            let next = Int(readUInt32LE(data, at: entryOffset))
            let attributes = readUInt32LE(data, at: entryOffset + 56)
            let endOfFile = readUInt64LE(data, at: entryOffset + 40)
            let nameLength = Int(readUInt32LE(data, at: entryOffset + 60))
            let nameOffset = entryOffset + 104
            guard nameOffset + nameLength <= data.count else { throw SMBCodecError.truncated }
            let name = decodeUTF16LE(Array(data[nameOffset..<nameOffset + nameLength]))
            if name != "." && name != ".." {
                entries.append(SMBDirectoryEntry(name: name, fileSize: endOfFile, isDirectory: (attributes & 0x10) != 0))
            }
            if next == 0 { break }
            entryOffset += next
        }
        return entries
    }

    private static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func readUInt64LE(_ bytes: [UInt8], at offset: Int) -> UInt64 {
        UInt64(readUInt32LE(bytes, at: offset)) | (UInt64(readUInt32LE(bytes, at: offset + 4)) << 32)
    }
}

enum SMB2Close {
    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32, fileId: [UInt8]) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.close, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(24)
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(0)
        writer.writeBytes(fileId)
        return writer.bytes
    }
}

func decodeUTF16LE(_ bytes: [UInt8]) -> String {
    let units = stride(from: 0, to: bytes.count - 1, by: 2).map {
        UInt16(bytes[$0]) | (UInt16(bytes[$0 + 1]) << 8)
    }
    return String(decoding: units, as: UTF16.self)
}

private func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    UInt32(bytes[offset])
        | (UInt32(bytes[offset + 1]) << 8)
        | (UInt32(bytes[offset + 2]) << 16)
        | (UInt32(bytes[offset + 3]) << 24)
}

private func readUInt64LE(_ bytes: [UInt8], at offset: Int) -> UInt64 {
    UInt64(readUInt32LE(bytes, at: offset)) | (UInt64(readUInt32LE(bytes, at: offset + 4)) << 32)
}

private func filetimeToDate(_ value: UInt64) -> Date? {
    guard value != 0 else { return nil }
    let secondsBetween1601And1970: TimeInterval = 11_644_473_600
    return Date(timeIntervalSince1970: (TimeInterval(value) / 10_000_000) - secondsBetween1601And1970)
}
