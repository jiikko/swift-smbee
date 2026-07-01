import Foundation
// swiftlint:disable file_length

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
    static let ioctl: UInt16 = 11
    static let cancel: UInt16 = 12
    static let changeNotify: UInt16 = 15
    static let setInfo: UInt16 = 17
    static let queryInfo: UInt16 = 16
    static let queryDirectory: UInt16 = 14
}

public struct SMBFileChange: Equatable, Sendable {
    public let action: SMBFileChangeAction
    public let name: String

    public init(action: SMBFileChangeAction, name: String) {
        self.action = action
        self.name = name
    }
}

public enum SMBFileChangeAction: Equatable, Sendable {
    case added
    case removed
    case modified
    case renamedOldName
    case renamedNewName
    case other(UInt32)

    init(rawValue: UInt32) {
        switch rawValue {
        case 1: self = .added
        case 2: self = .removed
        case 3: self = .modified
        case 4: self = .renamedOldName
        case 5: self = .renamedNewName
        default: self = .other(rawValue)
        }
    }
}

public struct SMBChangeNotifyFilter: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    public static let fileName = SMBChangeNotifyFilter(rawValue: 0x0000_0001)
    public static let dirName = SMBChangeNotifyFilter(rawValue: 0x0000_0002)
    public static let attributes = SMBChangeNotifyFilter(rawValue: 0x0000_0004)
    public static let size = SMBChangeNotifyFilter(rawValue: 0x0000_0008)
    public static let lastWrite = SMBChangeNotifyFilter(rawValue: 0x0000_0010)
    public static let lastAccess = SMBChangeNotifyFilter(rawValue: 0x0000_0020)
    public static let creation = SMBChangeNotifyFilter(rawValue: 0x0000_0040)
    public static let ea = SMBChangeNotifyFilter(rawValue: 0x0000_0080)
    public static let security = SMBChangeNotifyFilter(rawValue: 0x0000_0100)
    public static let `default`: SMBChangeNotifyFilter = [.fileName, .dirName, .attributes, .lastWrite]
}

public enum SMBChangeNotifyEvent: Equatable, Sendable {
    case changes([SMBFileChange])
    case overflow
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

    static func decodeResponse(_ bytes: [UInt8]) throws -> SMBTreeConnectResult {
        let header = try SMB2Header.decode(bytes)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "TREE_CONNECT")
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 16 else {
            throw SMBCodecError.invalidValue("invalid TREE_CONNECT response structure size")
        }
        let shareType = try reader.readUInt8()
        try reader.skip(count: 1)
        let shareFlags = try reader.readUInt32LE()
        let capabilities = try reader.readUInt32LE()
        let maximalAccess = try reader.readUInt32LE()
        return SMBTreeConnectResult(
            treeId: header.treeId,
            shareType: shareType,
            shareFlags: shareFlags,
            capabilities: capabilities,
            maximalAccess: maximalAccess
        )
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

    static func changeNotify(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0000_0001,
            createDisposition: 0x0000_0001,
            createOptions: 0x0000_0001
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

    static func metadata(path: String, directory: Bool) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0000_0100 | 0x0000_0080,
            createDisposition: 0x0000_0001,
            createOptions: directory ? 0x0000_0001 : 0x0000_0040
        )
    }

    static func querySecurity(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0002_0000,
            createDisposition: 0x0000_0001,
            createOptions: 0
        )
    }

    static func setSecurity(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0004_0000,
            createDisposition: 0x0000_0001,
            createOptions: 0
        )
    }

    static func namedPipe(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x8000_0000 | 0x4000_0000,
            createDisposition: 0x0000_0001,
            createOptions: 0
        )
    }
}

enum SMB2QueryInfo {
    static let infoTypeFile: UInt8 = 0x01
    static let infoTypeFilesystem: UInt8 = 0x02
    static let infoTypeSecurity: UInt8 = 0x03
    static let fileNetworkOpenInformation: UInt8 = 34
    static let fileAttributeTagInformation: UInt8 = 35
    static let fileFsVolumeInformation: UInt8 = 1
    static let fileFsAttributeInformation: UInt8 = 5
    static let fileFsFullSizeInformation: UInt8 = 7
    static let securityOwner: UInt32 = 0x0000_0001
    static let securityGroup: UInt32 = 0x0000_0002
    static let securityDACL: UInt32 = 0x0000_0004

    private static let fixedPartSize = 40
    private static let bufferOffset = SMB2Header.encodedSize + fixedPartSize

    static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        infoType: UInt8 = infoTypeFile,
        fileInfoClass: UInt8 = fileNetworkOpenInformation,
        outputBufferLength: UInt32 = 65_536,
        additionalInformation: UInt32 = 0
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.queryInfo, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(41)
        writer.writeUInt8(infoType)
        writer.writeUInt8(fileInfoClass)
        writer.writeUInt32LE(outputBufferLength)
        writer.writeUInt16LE(UInt16(bufferOffset))
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(additionalInformation)
        writer.writeUInt32LE(0)
        writer.writeBytes(fileId)
        // MS-SMB2 QUERY_INFO has a variable Buffer[] field; Samba accepts a one byte pad when InputBufferLength is 0.
        writer.writeUInt8(0)
        return writer.bytes
    }

    static func decodeNetworkOpenInformation(_ bytes: [UInt8]) throws -> SMBFileStat {
        let data = try decodeOutputBuffer(bytes)
        guard data.count >= 56 else { throw SMBCodecError.truncated }
        // FILE_NETWORK_OPEN_INFORMATION (MS-FSCC 2.4.65):
        //   CreationTime 0 / LastAccessTime 8 / LastWriteTime 16 / ChangeTime 24 /
        //   AllocationSize 32 / EndOfFile 40 / FileAttributes 48 / Reserved 52.
        // 旧実装は LastAccess/LastWrite/ChangeTime を 8 byte ずらして読み、FileAttributes を
        // Reserved (offset 52) から読んでいたため isDirectory が常に false だった
        // (size = EndOfFile 40 だけ偶然正しい)。directory stat の isDirectory が効かない
        // 原因だったので正しい offset に修正する。
        let creationTime = readUInt64LE(data, at: 0)
        let lastAccessTime = readUInt64LE(data, at: 8)
        let lastWriteTime = readUInt64LE(data, at: 16)
        let changeTime = readUInt64LE(data, at: 24)
        let endOfFile = readUInt64LE(data, at: 40)
        let attributes = readUInt32LE(data, at: 48)
        return SMBFileStat(
            size: endOfFile,
            modifiedTime: filetimeToDate(lastWriteTime),
            isDirectory: (attributes & 0x10) != 0,
            attributes: attributes,
            creationTime: filetimeToDate(creationTime),
            lastAccessTime: filetimeToDate(lastAccessTime),
            changeTime: filetimeToDate(changeTime)
        )
    }

    static func decodeAttributeTagInformation(_ bytes: [UInt8]) throws -> (attributes: UInt32, reparseTag: UInt32) {
        let data = try decodeOutputBuffer(bytes)
        guard data.count >= 8 else { throw SMBCodecError.truncated }
        return (
            attributes: readUInt32LE(data, at: 0),
            reparseTag: readUInt32LE(data, at: 4)
        )
    }

    static func decodeFullSizeInformation(_ bytes: [UInt8]) throws -> (totalBytes: UInt64, availableBytes: UInt64) {
        let data = try decodeOutputBuffer(bytes)
        guard data.count >= 32 else { throw SMBCodecError.truncated }
        let totalAllocationUnits = readUInt64LE(data, at: 0)
        let callerAvailableAllocationUnits = readUInt64LE(data, at: 8)
        let sectorsPerAllocationUnit = UInt64(readUInt32LE(data, at: 24))
        let bytesPerSector = UInt64(readUInt32LE(data, at: 28))
        let bytesPerAllocationUnit = sectorsPerAllocationUnit * bytesPerSector
        return (
            totalBytes: totalAllocationUnits * bytesPerAllocationUnit,
            availableBytes: callerAvailableAllocationUnits * bytesPerAllocationUnit
        )
    }

    static func decodeAttributeInformation(_ bytes: [UInt8]) throws -> (filesystemName: String, maxComponentLength: UInt32, filesystemAttributes: UInt32) {
        let data = try decodeOutputBuffer(bytes)
        guard data.count >= 12 else { throw SMBCodecError.truncated }
        let attributes = readUInt32LE(data, at: 0)
        let maxComponentLength = readUInt32LE(data, at: 4)
        let nameLength = Int(readUInt32LE(data, at: 8))
        guard data.count >= 12 + nameLength else { throw SMBCodecError.truncated }
        return (
            filesystemName: try utf16LEString(Array(data[12..<12 + nameLength])),
            maxComponentLength: maxComponentLength,
            filesystemAttributes: attributes
        )
    }

    static func decodeVolumeInformation(_ bytes: [UInt8]) throws -> (volumeLabel: String, volumeSerialNumber: UInt32) {
        let data = try decodeOutputBuffer(bytes)
        guard data.count >= 18 else { throw SMBCodecError.truncated }
        let serialNumber = readUInt32LE(data, at: 8)
        let labelLength = Int(readUInt32LE(data, at: 12))
        guard data.count >= 18 + labelLength else { throw SMBCodecError.truncated }
        return (
            volumeLabel: try utf16LEString(Array(data[18..<18 + labelLength])),
            volumeSerialNumber: serialNumber
        )
    }

    static func decodeSecurityInfo(_ bytes: [UInt8]) throws -> SMBSecurityInfo {
        try decodeSecurityDescriptor(decodeOutputBuffer(bytes))
    }

    static func decodeSecurityDescriptor(_ data: [UInt8]) throws -> SMBSecurityInfo {
        guard data.count >= 20 else { throw SMBCodecError.truncated }
        guard data[0] == 1 else {
            throw SMBCodecError.invalidValue("unsupported SECURITY_DESCRIPTOR revision")
        }
        let control = readUInt16LE(data, at: 2)
        let ownerOffset = Int(readUInt32LE(data, at: 4))
        let groupOffset = Int(readUInt32LE(data, at: 8))
        let daclOffset = Int(readUInt32LE(data, at: 16))
        return SMBSecurityInfo(
            ownerSID: ownerOffset == 0 ? nil : try decodeSID(data, at: ownerOffset, limit: data.count),
            groupSID: groupOffset == 0 ? nil : try decodeSID(data, at: groupOffset, limit: data.count),
            dacl: daclOffset == 0 ? nil : try decodeACL(data, at: daclOffset),
            controlFlags: control
        )
    }

    private static func decodeOutputBuffer(_ bytes: [UInt8]) throws -> [UInt8] {
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 9 else {
            throw SMBCodecError.invalidValue("invalid QUERY_INFO response structure size")
        }
        let offset = Int(try reader.readUInt16LE())
        let length = Int(try reader.readUInt32LE())
        guard offset + length <= bytes.count else { throw SMBCodecError.truncated }
        return Array(bytes[offset..<offset + length])
    }

    private static func decodeACL(_ data: [UInt8], at offset: Int) throws -> [SMBAccessControlEntry] {
        guard offset >= 0, offset + 8 <= data.count else { throw SMBCodecError.truncated }
        let aclSize = Int(readUInt16LE(data, at: offset + 2))
        let aceCount = Int(readUInt16LE(data, at: offset + 4))
        guard aclSize >= 8, offset + aclSize <= data.count else { throw SMBCodecError.truncated }
        let aclEnd = offset + aclSize
        var cursor = offset + 8
        var entries: [SMBAccessControlEntry] = []
        entries.reserveCapacity(aceCount)
        for _ in 0..<aceCount {
            guard cursor + 4 <= aclEnd else { throw SMBCodecError.truncated }
            let type = data[cursor]
            let flags = data[cursor + 1]
            let aceSize = Int(readUInt16LE(data, at: cursor + 2))
            guard aceSize >= 4, cursor + aceSize <= aclEnd else { throw SMBCodecError.truncated }
            let aceEnd = cursor + aceSize
            let accessMask = aceSize >= 8 ? readUInt32LE(data, at: cursor + 4) : 0
            let trusteeSID: String?
            if (type == 0 || type == 1), cursor + 8 < aceEnd {
                trusteeSID = try decodeSID(data, at: cursor + 8, limit: aceEnd)
            } else {
                // ⓥ Object/callback ACE layouts can carry object GUID fields before a SID; keep
                // the mask when present and skip by AceSize instead of guessing the trustee offset.
                trusteeSID = nil
            }
            entries.append(SMBAccessControlEntry(type: type, flags: flags, accessMask: accessMask, trusteeSID: trusteeSID))
            cursor = aceEnd
        }
        return entries
    }

    private static func decodeSID(_ data: [UInt8], at offset: Int, limit: Int) throws -> String {
        guard offset >= 0, offset + 8 <= limit, limit <= data.count else { throw SMBCodecError.truncated }
        guard data[offset] == 1 else {
            throw SMBCodecError.invalidValue("unsupported SID revision")
        }
        let subAuthorityCount = Int(data[offset + 1])
        let sidLength = 8 + subAuthorityCount * 4
        guard offset + sidLength <= limit else { throw SMBCodecError.truncated }
        var authority: UInt64 = 0
        for byte in data[(offset + 2)..<(offset + 8)] {
            authority = (authority << 8) | UInt64(byte)
        }
        var parts = ["S", "1", "\(authority)"]
        for index in 0..<subAuthorityCount {
            parts.append("\(readUInt32LE(data, at: offset + 8 + index * 4))")
        }
        return parts.joined(separator: "-")
    }

    private static func utf16LEString(_ bytes: [UInt8]) throws -> String {
        guard bytes.count.isMultiple(of: 2) else {
            throw SMBCodecError.invalidValue("UTF-16LE byte length must be even")
        }
        var codeUnits: [UInt16] = []
        codeUnits.reserveCapacity(bytes.count / 2)
        var index = 0
        while index < bytes.count {
            codeUnits.append(UInt16(bytes[index]) | (UInt16(bytes[index + 1]) << 8))
            index += 2
        }
        return String(decoding: codeUnits, as: UTF16.self)
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

enum SMB2Ioctl {
    static let fsctlPipeTransceive: UInt32 = 0x0011_c017
    static let fsctlDfsGetReferrals: UInt32 = 0x0006_0194
    static let fsctlSrvRequestResumeKey: UInt32 = 0x0014_0078
    static let fsctlSrvCopychunkWrite: UInt32 = 0x0014_40f4

    private static let fixedPartSize = 56
    private static let bufferOffset = SMB2Header.encodedSize + fixedPartSize
    private static let isFsctl: UInt32 = 0x0000_0001

    static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        ctlCode: UInt32,
        input: [UInt8],
        maxOutputResponse: UInt32
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.ioctl, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(57)
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(ctlCode)
        writer.writeBytes(fileId)
        writer.writeUInt32LE(UInt32(bufferOffset))
        writer.writeUInt32LE(UInt32(input.count))
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(0)
        writer.writeUInt32LE(maxOutputResponse)
        writer.writeUInt32LE(isFsctl)
        writer.writeUInt32LE(0)
        writer.writeBytes(input.isEmpty ? [0] : input)
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws -> [UInt8] {
        let response = try decodeResponseWithStatus(bytes, allowedStatuses: [SMB2Status.success])
        return response.output
    }

    static func decodeResponseWithStatus(_ bytes: [UInt8], allowedStatuses: Set<UInt32>) throws -> SMB2IoctlResponse {
        let header = try SMB2Header.decode(bytes)
        if !allowedStatuses.contains(header.status) {
            try SMBErrorMapper.throwIfFailure(status: header.status, operation: "IOCTL")
        }
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        let structureSize = try reader.readUInt16LE()
        // An SMB2 ERROR response (StructureSize 9) carries no IOCTL output buffer. Servers
        // return it for non-success statuses the caller explicitly allows — e.g.
        // STATUS_INVALID_DEVICE_REQUEST when server-side copychunk is unsupported, which the
        // copy path uses to fall back to client-side READ/WRITE. Surface status, empty output.
        if structureSize == 9 && header.status != SMB2Status.success {
            return SMB2IoctlResponse(status: header.status, output: [])
        }
        guard structureSize == 49 else {
            throw SMBCodecError.invalidValue("invalid IOCTL response structure size")
        }
        try reader.skip(count: 2)
        _ = try reader.readUInt32LE()
        try reader.skip(count: 16)
        _ = try reader.readUInt32LE()
        _ = try reader.readUInt32LE()
        let outputOffset = Int(try reader.readUInt32LE())
        let outputCount = Int(try reader.readUInt32LE())
        try reader.skip(count: 8)
        guard outputOffset + outputCount <= bytes.count else { throw SMBCodecError.truncated }
        return SMB2IoctlResponse(status: header.status, output: Array(bytes[outputOffset..<outputOffset + outputCount]))
    }
}

struct SMB2IoctlResponse {
    var status: UInt32
    var output: [UInt8]
}

enum SMB2CopyChunk {
    static let resumeKeySize = 24
    // SRV_REQUEST_RESUME_KEY_RSP = ResumeKey(24) + ContextLength(4) + Context(variable).
    // Requesting only the 24-byte key makes the server reject the IOCTL with
    // STATUS_BUFFER_TOO_SMALL, so size the output buffer for the full structure.
    static let resumeKeyResponseMaxSize: UInt32 = 1024
    static let defaultMaxChunks: UInt32 = 256
    static let defaultMaxChunkSize: UInt32 = 1_048_576
    static let defaultMaxTotalSize: UInt32 = 16_777_216

    static func decodeResumeKeyResponse(_ output: [UInt8]) throws -> [UInt8] {
        guard output.count >= resumeKeySize else { throw SMBCodecError.truncated }
        return Array(output[..<resumeKeySize])
    }

    static func encodeCopyChunkRequest(resumeKey: [UInt8], chunks: [SMB2CopyChunkRange]) throws -> [UInt8] {
        guard resumeKey.count == resumeKeySize else {
            throw SMBCodecError.invalidValue("SMB copychunk resume key must be 24 bytes")
        }
        guard !chunks.isEmpty else {
            throw SMBCodecError.invalidValue("SMB copychunk request must contain at least one chunk")
        }
        guard chunks.count <= Int(UInt32.max) else {
            throw SMBCodecError.invalidValue("SMB copychunk chunk count overflow")
        }

        var writer = SMBByteWriter()
        writer.writeBytes(resumeKey)
        writer.writeUInt32LE(UInt32(chunks.count))
        writer.writeUInt32LE(0)
        for chunk in chunks {
            writer.writeUInt64LE(chunk.sourceOffset)
            writer.writeUInt64LE(chunk.targetOffset)
            writer.writeUInt32LE(chunk.length)
            writer.writeUInt32LE(0)
        }
        return writer.bytes
    }

    static func decodeCopyChunkResponse(_ output: [UInt8]) throws -> SMB2CopyChunkResponse {
        guard output.count >= 12 else { throw SMBCodecError.truncated }
        var reader = SMBByteReader(bytes: output)
        return SMB2CopyChunkResponse(
            chunksWritten: try reader.readUInt32LE(),
            chunkBytesWritten: try reader.readUInt32LE(),
            totalBytesWritten: try reader.readUInt32LE()
        )
    }
}

struct SMB2CopyChunkRange: Equatable {
    var sourceOffset: UInt64
    var targetOffset: UInt64
    var length: UInt32
}

struct SMB2CopyChunkResponse: Equatable {
    var chunksWritten: UInt32
    var chunkBytesWritten: UInt32
    var totalBytesWritten: UInt32
}

enum SMB2SetInfo {
    private static let fixedPartSize = 32
    private static let bufferOffset = SMB2Header.encodedSize + fixedPartSize
    static let infoTypeFile: UInt8 = 0x01
    static let infoTypeSecurity: UInt8 = 0x03
    static let securityDACL: UInt32 = 0x0000_0004
    static let accessAllowedAceType: UInt8 = 0x00
    static let accessDeniedAceType: UInt8 = 0x01
    private static let securityDescriptorSelfRelative: UInt16 = 0x8000
    private static let securityDescriptorDACLPresent: UInt16 = 0x0004

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

    static func encodeBasicInfoRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        update: SMBFileMetadataUpdate
    ) throws -> [UInt8] {
        var buffer = SMBByteWriter()
        buffer.writeUInt64LE(dateToFiletime(update.creationTime))
        buffer.writeUInt64LE(dateToFiletime(update.lastAccessTime))
        buffer.writeUInt64LE(dateToFiletime(update.modifiedTime))
        buffer.writeUInt64LE(dateToFiletime(update.changeTime))
        buffer.writeUInt32LE(update.attributes ?? 0)
        buffer.writeUInt32LE(0)
        return try encodeRequest(
            messageId: messageId,
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            fileInfoClass: 4,
            buffer: buffer.bytes
        )
    }

    static func encodeSecurityDescriptorRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        ownerSID: String?,
        groupSID: String?,
        dacl: [SMBAccessControlEntry],
        force: Bool = false
    ) throws -> [UInt8] {
        let descriptor = try encodeSecurityDescriptor(ownerSID: ownerSID, groupSID: groupSID, dacl: dacl, force: force)
        return try encodeRequest(
            messageId: messageId,
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            infoType: infoTypeSecurity,
            fileInfoClass: 0,
            additionalInformation: securityDACL,
            buffer: descriptor
        )
    }

    static func encodeSecurityDescriptor(
        ownerSID: String?,
        groupSID: String?,
        dacl: [SMBAccessControlEntry],
        force: Bool = false
    ) throws -> [UInt8] {
        try validateWritableDACL(dacl, force: force)
        var payload = Array(repeating: UInt8(0), count: 20)
        payload[0] = 1
        writeUInt16LE(securityDescriptorSelfRelative | securityDescriptorDACLPresent, to: &payload, at: 2)
        if let ownerSID {
            writeUInt32LE(UInt32(payload.count), to: &payload, at: 4)
            payload.append(contentsOf: try encodeSID(ownerSID))
        }
        if let groupSID {
            writeUInt32LE(UInt32(payload.count), to: &payload, at: 8)
            payload.append(contentsOf: try encodeSID(groupSID))
        }
        writeUInt32LE(UInt32(payload.count), to: &payload, at: 16)
        payload.append(contentsOf: try encodeACL(dacl))
        return payload
    }

    static func validateWritableDACL(_ dacl: [SMBAccessControlEntry], force: Bool = false) throws {
        for ace in dacl {
            guard ace.trusteeSID != nil else {
                throw SMBCodecError.invalidValue("DACL ACE trustee SID is required for SET_SECURITY")
            }
        }
        guard !force else { return }
        guard !dacl.isEmpty else {
            throw SMBCodecError.invalidValue("refusing to write empty DACL without force")
        }
        guard dacl.contains(where: { $0.type == accessAllowedAceType }) else {
            throw SMBCodecError.invalidValue("refusing to write DACL without ACCESS_ALLOWED ACE without force")
        }
    }

    static func encodeSID(_ sid: String) throws -> [UInt8] {
        let parts = sid.split(separator: "-")
        guard parts.count >= 3, parts[0] == "S", parts[1] == "1" else {
            throw SMBCodecError.invalidValue("invalid SID string")
        }
        guard let authority = UInt64(parts[2]), authority <= 0x0000_ffff_ffff else {
            throw SMBCodecError.invalidValue("invalid SID identifier authority")
        }
        let subAuthorityStrings = parts.dropFirst(3)
        guard subAuthorityStrings.count <= Int(UInt8.max) else {
            throw SMBCodecError.invalidValue("SID has too many sub-authorities")
        }
        var writer = SMBByteWriter()
        writer.writeUInt8(1)
        writer.writeUInt8(UInt8(subAuthorityStrings.count))
        for shift in stride(from: 40, through: 0, by: -8) {
            writer.writeUInt8(UInt8((authority >> UInt64(shift)) & 0xff))
        }
        for part in subAuthorityStrings {
            guard let value = UInt32(part) else {
                throw SMBCodecError.invalidValue("invalid SID sub-authority")
            }
            writer.writeUInt32LE(value)
        }
        return writer.bytes
    }

    static func encodeACL(_ dacl: [SMBAccessControlEntry]) throws -> [UInt8] {
        guard dacl.count <= Int(UInt16.max) else {
            throw SMBCodecError.invalidValue("DACL has too many ACEs")
        }
        var aces: [UInt8] = []
        for ace in dacl {
            aces.append(contentsOf: try encodeACE(ace))
        }
        let aclSize = 8 + aces.count
        guard aclSize <= Int(UInt16.max) else {
            throw SMBCodecError.invalidValue("DACL is too large")
        }
        var writer = SMBByteWriter()
        writer.writeUInt8(2)
        writer.writeUInt8(0)
        writer.writeUInt16LE(UInt16(aclSize))
        writer.writeUInt16LE(UInt16(dacl.count))
        writer.writeUInt16LE(0)
        writer.writeBytes(aces)
        return writer.bytes
    }

    static func encodeACE(_ ace: SMBAccessControlEntry) throws -> [UInt8] {
        guard ace.type == accessAllowedAceType || ace.type == accessDeniedAceType else {
            throw SMBCodecError.invalidValue("unsupported ACE type for SET_SECURITY")
        }
        guard let trusteeSID = ace.trusteeSID else {
            throw SMBCodecError.invalidValue("DACL ACE trustee SID is required for SET_SECURITY")
        }
        let sid = try encodeSID(trusteeSID)
        let aceSize = 8 + sid.count
        guard aceSize <= Int(UInt16.max) else {
            throw SMBCodecError.invalidValue("ACE is too large")
        }
        var writer = SMBByteWriter()
        writer.writeUInt8(ace.type)
        writer.writeUInt8(ace.flags)
        writer.writeUInt16LE(UInt16(aceSize))
        writer.writeUInt32LE(ace.accessMask)
        writer.writeBytes(sid)
        return writer.bytes
    }

    private static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        infoType: UInt8 = infoTypeFile,
        fileInfoClass: UInt8,
        additionalInformation: UInt32 = 0,
        buffer: [UInt8]
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(command: SMB2Commands.setInfo, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(33)
        writer.writeUInt8(infoType)
        writer.writeUInt8(fileInfoClass)
        writer.writeUInt32LE(UInt32(buffer.count))
        writer.writeUInt16LE(UInt16(bufferOffset))
        writer.writeUInt16LE(0)
        writer.writeUInt32LE(additionalInformation)
        writer.writeBytes(fileId)
        writer.writeBytes(buffer.isEmpty ? [0] : buffer)
        return writer.bytes
    }

    private static func relativeInfoName(_ path: String) throws -> String {
        try SMBPath.normalize(path)
    }

    private static func writeUInt16LE(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
    }

    private static func writeUInt32LE(_ value: UInt32, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
        bytes[offset + 2] = UInt8((value >> 16) & 0xff)
        bytes[offset + 3] = UInt8((value >> 24) & 0xff)
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
            let creationTime = readUInt64LE(data, at: entryOffset + 8)
            let lastWriteTime = readUInt64LE(data, at: entryOffset + 24)
            let attributes = readUInt32LE(data, at: entryOffset + 56)
            let endOfFile = readUInt64LE(data, at: entryOffset + 40)
            let nameLength = Int(readUInt32LE(data, at: entryOffset + 60))
            let rawFileId = readUInt64LE(data, at: entryOffset + 96)
            let fileId = rawFileId == 0 ? nil : rawFileId
            let nameOffset = entryOffset + 104
            guard nameOffset + nameLength <= data.count else { throw SMBCodecError.truncated }
            let name = decodeUTF16LE(Array(data[nameOffset..<nameOffset + nameLength]))
            if name != "." && name != ".." {
                entries.append(SMBDirectoryEntry(
                    name: name,
                    fileSize: endOfFile,
                    isDirectory: (attributes & 0x10) != 0,
                    attributes: attributes,
                    fileId: fileId,
                    modifiedTime: filetimeToDate(lastWriteTime),
                    creationTime: filetimeToDate(creationTime)
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

enum SMB2ChangeNotify {
    static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        completionFilter: SMBChangeNotifyFilter = .default,
        watchTree: Bool = false,
        outputBufferLength: UInt32 = 65_536
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let header = try SMB2Header(
            command: SMB2Commands.changeNotify,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(32)
        writer.writeUInt16LE(watchTree ? 0x0001 : 0x0000)
        writer.writeUInt32LE(outputBufferLength)
        writer.writeBytes(fileId)
        writer.writeUInt32LE(completionFilter.rawValue)
        writer.writeUInt32LE(0)
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws -> [SMBFileChange] {
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 9 else {
            throw SMBCodecError.invalidValue("invalid CHANGE_NOTIFY response structure size")
        }
        let offset = Int(try reader.readUInt16LE())
        let length = Int(try reader.readUInt32LE())
        guard offset >= SMB2Header.encodedSize, offset + length <= bytes.count else {
            throw SMBCodecError.truncated
        }
        return try decodeFileNotifyInformation(Array(bytes[offset..<offset + length]))
    }

    static func decodeFileNotifyInformation(_ data: [UInt8]) throws -> [SMBFileChange] {
        var changes: [SMBFileChange] = []
        var entryOffset = 0
        while entryOffset < data.count {
            guard entryOffset + 12 <= data.count else { throw SMBCodecError.truncated }
            let next = Int(readUInt32LE(data, at: entryOffset))
            let action = readUInt32LE(data, at: entryOffset + 4)
            let nameLength = Int(readUInt32LE(data, at: entryOffset + 8))
            let nameOffset = entryOffset + 12
            guard nameOffset + nameLength <= data.count else { throw SMBCodecError.truncated }
            let nameBytes = Array(data[nameOffset..<nameOffset + nameLength])
            changes.append(SMBFileChange(action: SMBFileChangeAction(rawValue: action), name: decodeUTF16LE(nameBytes)))
            if next == 0 { break }
            guard next >= 12, entryOffset + next <= data.count else { throw SMBCodecError.truncated }
            entryOffset += next
        }
        return changes
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

private func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
    UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
}

private func readUInt64LE(_ bytes: [UInt8], at offset: Int) -> UInt64 {
    UInt64(readUInt32LE(bytes, at: offset)) | (UInt64(readUInt32LE(bytes, at: offset + 4)) << 32)
}

private func filetimeToDate(_ value: UInt64) -> Date? {
    guard value != 0 else { return nil }
    let secondsBetween1601And1970: TimeInterval = 11_644_473_600
    return Date(timeIntervalSince1970: (TimeInterval(value) / 10_000_000) - secondsBetween1601And1970)
}

private func dateToFiletime(_ date: Date?) -> UInt64 {
    guard let date else { return 0 }
    let secondsBetween1601And1970: TimeInterval = 11_644_473_600
    return UInt64((date.timeIntervalSince1970 + secondsBetween1601And1970) * 10_000_000)
}
