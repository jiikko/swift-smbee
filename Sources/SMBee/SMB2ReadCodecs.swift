import Foundation

enum SMB2Commands {
    static let sessionSetup: UInt16 = 1
    static let logoff: UInt16 = 2
    static let treeConnect: UInt16 = 3
    static let treeDisconnect: UInt16 = 4
    static let create: UInt16 = 5
    static let close: UInt16 = 6
    static let flush: UInt16 = 7
    static let read: UInt16 = 8
    static let write: UInt16 = 9
    static let setInfo: UInt16 = 17
    static let queryInfo: UInt16 = 16
    static let queryDirectory: UInt16 = 14
}

enum SMB2Logoff {
    static func encodeRequest(messageId: UInt64, sessionId: UInt64) throws -> [UInt8] {
        let header = try SMB2Header(command: SMB2Commands.logoff, messageId: messageId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(4)
        writer.writeUInt16LE(0)
        return writer.bytes
    }
}

enum SMB2TreeDisconnect {
    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32) throws -> [UInt8] {
        let header = try SMB2Header(command: SMB2Commands.treeDisconnect, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(4)
        writer.writeUInt16LE(0)
        return writer.bytes
    }
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
        let pathBytes = NTLM.utf16le(try treeConnectPath(path))
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

    private static func treeConnectPath(_ path: String) throws -> String {
        guard path.hasPrefix("\\\\") else { return path }
        let parts = path.dropFirst(2).split(separator: "\\", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2 else {
            throw SMBCodecError.invalidValue("TREE_CONNECT path must be \\\\host\\share")
        }
        return "\\\\\(parts[0])\\\(try SMBShareName(parts[1]).rawValue)"
    }
}

enum SMB2Create {
    private static let fixedPartSize = 56
    private static let nameOffset = SMB2Header.encodedSize + fixedPartSize
    private static let responseFileIdOffset = SMB2Header.encodedSize + 64

    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32, path: String, directory: Bool) throws -> [UInt8] {
        try encodeRequest(
            messageId: messageId,
            sessionId: sessionId,
            treeId: treeId,
            request: SMB2CreateRequest.read(path: path, directory: directory)
        )
    }

    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32, request: SMB2CreateRequest) throws -> [UInt8] {
        let header = try SMB2Header(command: SMB2Commands.create, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        let nameBytes = NTLM.utf16le(try relativeCreateName(request.path))
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(57)
        writer.writeUInt8(0)
        writer.writeUInt8(0)
        writer.writeUInt32LE(0x0000_0002)
        writer.writeUInt64LE(0)
        writer.writeUInt64LE(0)
        writer.writeUInt32LE(request.desiredAccess)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(request.shareAccess)
        writer.writeUInt32LE(request.createDisposition)
        writer.writeUInt32LE(request.createOptions)
        writer.writeUInt16LE(UInt16(nameOffset))
        writer.writeUInt16LE(UInt16(nameBytes.count))
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeBytes(nameBytes.isEmpty ? [0] : nameBytes)
        return writer.bytes
    }

    private static func relativeCreateName(_ path: String) throws -> String {
        try SMBPath.normalize(path)
    }

    static func decodeFileId(_ bytes: [UInt8]) throws -> [UInt8] {
        let header = try SMB2Header.decode(bytes)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "CREATE")
        let offset = responseFileIdOffset
        guard bytes.count >= offset + 16 else { throw SMBCodecError.truncated }
        return Array(bytes[offset..<offset + 16])
    }
}

struct SMB2CreateRequest {
    var path: String
    var desiredAccess: UInt32
    var shareAccess: UInt32 = 0x0000_0007
    var createDisposition: UInt32
    var createOptions: UInt32

    static func read(path: String, directory: Bool) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: directory ? 0x0000_0089 : 0x0000_0081,
            createDisposition: 0x0000_0001,
            createOptions: directory ? 0x0000_0001 : 0x0000_0040
        )
    }

    static func makeDirectory(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0000_0001 | 0x0000_0004 | 0x0000_0080,
            createDisposition: 0x0000_0002,
            createOptions: 0x0000_0001
        )
    }

    static func upload(path: String, overwrite: Bool) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0000_0002 | 0x0000_0080,
            createDisposition: overwrite ? 0x0000_0005 : 0x0000_0002,
            createOptions: 0x0000_0040
        )
    }

    static func delete(path: String, directory: Bool) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0001_0000,
            createDisposition: 0x0000_0001,
            createOptions: (directory ? 0x0000_0001 : 0x0000_0040) | 0x0000_1000
        )
    }

    static func rename(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0001_0000 | 0x0000_0080,
            createDisposition: 0x0000_0001,
            createOptions: 0
        )
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
        return SMBFileStat(
            size: endOfFile,
            modifiedTime: filetimeToDate(lastWriteTime),
            isDirectory: (attributes & 0x10) != 0,
            attributes: attributes
        )
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

enum SMB2Write {
    private static let fixedPartSize = 48
    private static let dataOffset = SMB2Header.encodedSize + fixedPartSize

    static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        offset: UInt64,
        data: [UInt8]
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.write, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(49)
        writer.writeUInt16LE(UInt16(dataOffset))
        writer.writeUInt32LE(UInt32(data.count))
        writer.writeUInt64LE(offset)
        writer.writeBytes(fileId)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt16LE(0)
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(0)
        writer.writeBytes(data.isEmpty ? [0] : data)
        return writer.bytes
    }

    static func decodeResponseCount(_ bytes: [UInt8]) throws -> UInt32 {
        let header = try SMB2Header.decode(bytes)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "WRITE")
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 17 else {
            throw SMBCodecError.invalidValue("invalid WRITE response structure size")
        }
        try reader.skip(count: 2)
        return try reader.readUInt32LE()
    }
}

enum SMB2SetInfo {
    private static let fixedPartSize = 32
    private static let bufferOffset = SMB2Header.encodedSize + fixedPartSize

    static func encodeRenameRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        newPath: String,
        replaceIfExists: Bool
    ) throws -> [UInt8] {
        let nameBytes = NTLM.utf16le(try relativeInfoName(newPath))
        var buffer = SMBByteWriter()
        buffer.writeUInt8(replaceIfExists ? 1 : 0)
        buffer.writeBytes(Array(repeating: 0, count: 7))
        buffer.writeUInt64LE(0)
        buffer.writeUInt32LE(UInt32(nameBytes.count))
        buffer.writeBytes(nameBytes)
        return try encodeRequest(
            messageId: messageId,
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            fileInfoClass: 10,
            buffer: buffer.bytes
        )
    }

    private static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        fileInfoClass: UInt8,
        buffer: [UInt8]
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.setInfo, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(33)
        writer.writeUInt8(0x01)
        writer.writeUInt8(fileInfoClass)
        writer.writeUInt32LE(UInt32(buffer.count))
        writer.writeUInt16LE(UInt16(bufferOffset))
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(0)
        writer.writeBytes(fileId)
        writer.writeBytes(buffer.isEmpty ? [0] : buffer)
        return writer.bytes
    }

    private static func relativeInfoName(_ path: String) throws -> String {
        try SMBPath.normalize(path)
    }
}

enum SMB2QueryDirectory {
    private static let fixedPartSize = 32
    private static let fileNameOffset = SMB2Header.encodedSize + fixedPartSize

    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32, fileId: [UInt8], restartScan: Bool = true) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.queryDirectory, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(33)
        writer.writeUInt8(37)
        writer.writeUInt8(restartScan ? 0x01 : 0x00)
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
                entries.append(SMBDirectoryEntry(
                    name: name,
                    fileSize: endOfFile,
                    isDirectory: (attributes & 0x10) != 0,
                    attributes: attributes
                ))
            }
            if next == 0 { break }
            guard next >= 104, entryOffset + next <= data.count else { throw SMBCodecError.truncated }
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

enum SMB2Flush {
    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32, fileId: [UInt8]) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.flush, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
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
