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
    static let lock: UInt16 = 10
    static let ioctl: UInt16 = 11
    static let cancel: UInt16 = 12
    static let echo: UInt16 = 13
    static let changeNotify: UInt16 = 15
    static let setInfo: UInt16 = 17
    static let queryInfo: UInt16 = 16
    static let queryDirectory: UInt16 = 14
    static let oplockBreak: UInt16 = 18
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

    public var changes: [SMBFileChange]? {
        if case .changes(let changes) = self {
            return changes
        }
        return nil
    }

    public var requiresRescan: Bool {
        self == .overflow
    }
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

enum SMB2Cancel {
    static func encodeRequest(messageId: UInt64, sessionId: UInt64, treeId: UInt32 = 0) throws -> [UInt8] {
        let header = try SMB2Header(command: SMB2Commands.cancel, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
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

enum SMB2Echo {
    static func encodeRequest(messageId: UInt64, sessionId: UInt64) throws -> [UInt8] {
        let header = try SMB2Header(command: SMB2Commands.echo, messageId: messageId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(4)
        writer.writeUInt16LE(0)
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws {
        let header = try SMB2Header.decode(bytes)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "ECHO")
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 4 else {
            throw SMBCodecError.invalidValue("invalid ECHO response structure size")
        }
        try reader.skip(count: 2)
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
        try writer.writeUInt16LE(count: securityBlob.count, of: "SESSION_SETUP security blob")
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
        try writer.writeUInt16LE(count: pathBytes.count, of: "TREE_CONNECT path")
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
        try writer.writeUInt16LE(count: nameBytes.count, of: "CREATE name")
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

    static func readMetadata(path: String, directory: Bool) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: directory ? 0x0000_0089 : 0x0000_0081,
            createDisposition: 0x0000_0001,
            // Query the directory entry itself rather than following a reparse target.
            createOptions: (directory ? 0x0000_0001 : 0x0000_0040) | 0x0020_0000
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

    static func byteRangeLock(path: String) -> SMB2CreateRequest {
        // Byte-range locks require an open with read or write data access (MS-SMB2 §3.3.5.14).
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0000_0001 | 0x0000_0002 | 0x0000_0080,
            createDisposition: 0x0000_0001,
            createOptions: 0x0000_0040
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

    /// Open an existing file with read+write data access for sparse FSCTLs
    /// (SET_SPARSE / SET_ZERO_DATA / QUERY_ALLOCATED_RANGES).
    static func sparse(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0000_0001 | 0x0000_0002 | 0x0000_0080,
            createDisposition: 0x0000_0001,
            createOptions: 0x0000_0040
        )
    }

    static func uploadResume(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            // Resume validation reads the existing prefix through this same handle before writing.
            // Keeping validation and writes on one open also prevents a path replacement race.
            desiredAccess: 0x0000_0001 | 0x0000_0002 | 0x0000_0080,
            createDisposition: 0x0000_0001,
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

    static func deleteReparsePoint(path: String, directory: Bool) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0001_0000,
            createDisposition: 0x0000_0001,
            // FILE_OPEN_REPARSE_POINT prevents deletion from following the target.
            createOptions: (directory ? 0x0000_0001 : 0x0000_0040) | 0x0000_1000 | 0x0020_0000
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

    static func reparsePoint(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0000_0080,
            createDisposition: 0x0000_0001,
            createOptions: 0x0000_0020 | 0x0020_0000
        )
    }

    static func setReparsePoint(path: String) -> SMB2CreateRequest {
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0000_0100,
            createDisposition: 0x0000_0001,
            createOptions: 0x0000_0040 | 0x0020_0000
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

    static func setSecurity(path: String, includeOwner: Bool = false) -> SMB2CreateRequest {
        // WRITE_DAC for DACL writes; WRITE_OWNER additionally required to set owner/group.
        SMB2CreateRequest(
            path: path,
            desiredAccess: 0x0004_0000 | (includeOwner ? 0x0008_0000 : 0),
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
        let allocationSize = readUInt64LE(data, at: 32)
        let endOfFile = readUInt64LE(data, at: 40)
        let attributes = readUInt32LE(data, at: 48)
        return SMBFileStat(
            size: endOfFile,
            modifiedTime: filetimeToDate(lastWriteTime),
            isDirectory: (attributes & 0x10) != 0,
            attributes: attributes,
            allocationSize: allocationSize,
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
            if type == 0 || type == 1, cursor + 8 < aceEnd {
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
        let creditCharge = SMB2Credit.charge(forPayloadLength: UInt64(length))
        let header = try SMB2Header(
            creditCharge: creditCharge,
            command: SMB2Commands.read,
            credits: creditCharge,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
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
        let creditCharge = SMB2Credit.charge(forPayloadLength: data.count)
        let header = try SMB2Header(
            creditCharge: creditCharge,
            command: SMB2Commands.write,
            credits: creditCharge,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        // A WRITE packet carries the caller's payload. Reserve its exact wire size so
        // appending each 64 KiB chunk does not grow and copy the backing buffer.
        var writer = SMBByteWriter(capacity: dataOffset + max(1, data.count))
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
    static let fsctlGetReparsePoint: UInt32 = 0x0009_00a8
    static let fsctlSetReparsePoint: UInt32 = 0x0009_00a4
    static let fsctlSrvRequestResumeKey: UInt32 = 0x0014_0078
    static let fsctlSrvCopychunkWrite: UInt32 = 0x0014_40f4
    static let fsctlSetSparse: UInt32 = 0x0009_00c4
    static let fsctlSetZeroData: UInt32 = 0x0009_80c8
    static let fsctlQueryAllocatedRanges: UInt32 = 0x0009_40cf

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

/// A byte range reported as allocated (non-hole) by FSCTL_QUERY_ALLOCATED_RANGES (MS-FSCC 2.3.x).
public struct SMBAllocatedRange: Equatable, Sendable {
    public let offset: UInt64
    public let length: UInt64

    public init(offset: UInt64, length: UInt64) {
        self.offset = offset
        self.length = length
    }
}

enum SMB2SparseFile {
    /// FSCTL_SET_SPARSE input: a single SetSparse BOOLEAN (MS-FSCC 2.3.68). Empty input
    /// also sets sparse, but sending the explicit byte lets callers clear the flag too.
    static func encodeSetSparseInput(_ sparse: Bool) -> [UInt8] {
        [sparse ? 1 : 0]
    }

    /// FSCTL_SET_ZERO_DATA input: FILE_ZERO_DATA_INFORMATION { FileOffset, BeyondFinalZero }
    /// (MS-FSCC 2.3.79). Zeroes (punches a hole in) `[offset, offset+length)`.
    static func encodeSetZeroDataInput(offset: UInt64, length: UInt64) throws -> [UInt8] {
        let end = offset.addingReportingOverflow(length)
        guard !end.overflow else {
            throw SMBCodecError.invalidValue("zero-data range overflows UInt64")
        }
        var writer = SMBByteWriter()
        writer.writeUInt64LE(offset)
        writer.writeUInt64LE(end.partialValue)
        return writer.bytes
    }

    /// FSCTL_QUERY_ALLOCATED_RANGES input: FILE_ALLOCATED_RANGE_BUFFER { FileOffset, Length }
    /// describing the region to probe (MS-FSCC 2.3.64).
    static func encodeQueryAllocatedRangesInput(offset: UInt64, length: UInt64) -> [UInt8] {
        var writer = SMBByteWriter()
        writer.writeUInt64LE(offset)
        writer.writeUInt64LE(length)
        return writer.bytes
    }

    /// Decode the FILE_ALLOCATED_RANGE_BUFFER array returned by FSCTL_QUERY_ALLOCATED_RANGES.
    /// An empty output means the whole probed region is a hole (fully sparse).
    static func decodeAllocatedRanges(_ output: [UInt8]) throws -> [SMBAllocatedRange] {
        guard output.count % 16 == 0 else {
            throw SMBCodecError.invalidValue("allocated-range buffer is not a multiple of 16 bytes")
        }
        var reader = SMBByteReader(bytes: output)
        var ranges: [SMBAllocatedRange] = []
        for _ in 0..<(output.count / 16) {
            let offset = try reader.readUInt64LE()
            let length = try reader.readUInt64LE()
            ranges.append(SMBAllocatedRange(offset: offset, length: length))
        }
        return ranges
    }
}

enum SMB2ReparsePoint {
    static func encodeSymbolicLink(
        substituteName: String,
        printName: String,
        relative: Bool
    ) throws -> [UInt8] {
        let substitute = Array(substituteName.utf16).flatMap(littleEndianBytes)
        let printable = Array(printName.utf16).flatMap(littleEndianBytes)
        var data = SMBByteWriter()
        data.writeUInt16LE(0)
        try data.writeUInt16LE(count: substitute.count, of: "reparse substitute name")
        try data.writeUInt16LE(count: substitute.count, of: "reparse print-name offset")
        try data.writeUInt16LE(count: printable.count, of: "reparse print name")
        data.writeUInt32LE(relative ? 1 : 0)
        data.writeBytes(substitute)
        data.writeBytes(printable)

        var buffer = SMBByteWriter()
        buffer.writeUInt32LE(SMBReparseTags.symlink)
        try buffer.writeUInt16LE(count: data.bytes.count, of: "reparse data")
        buffer.writeUInt16LE(0)
        buffer.writeBytes(data.bytes)
        return buffer.bytes
    }

    private static func littleEndianBytes(_ codeUnit: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: codeUnit), UInt8(truncatingIfNeeded: codeUnit >> 8)]
    }

    static func decode(_ bytes: [UInt8]) throws -> SMBReparsePoint {
        guard bytes.count >= 8 else { throw SMBCodecError.truncated }
        let tag = readUInt32LE(bytes, at: 0)
        let dataLength = Int(readUInt16LE(bytes, at: 4))
        guard bytes.count >= 8 + dataLength else { throw SMBCodecError.truncated }
        let data = Array(bytes[8..<8 + dataLength])
        switch tag {
        case SMBReparseTags.symlink:
            return try decodeSymbolicLink(tag: tag, data: data)
        case SMBReparseTags.mountPoint:
            return try decodeMountPoint(tag: tag, data: data)
        case SMBReparseTags.lxSymlink:
            return try decodeLxSymlink(tag: tag, data: data)
        default:
            // DFS (0x8000000A) and NFS (0x80000014) reparse data are marked
            // "server-side interpretation only, not meaningful over the wire" in the
            // MS-FSCC reparse tag table, so clients must treat them as opaque. For DFS
            // links use FSCTL_DFS_GET_REFERRALS (`smbcli dfs`) to resolve targets.
            return SMBReparsePoint(tag: tag, rawData: data)
        }
    }

    private static func decodeLxSymlink(tag: UInt32, data: [UInt8]) throws -> SMBReparsePoint {
        // MS-FSCC §2.1.2.7: Version(4, MUST be 2) + UTF-8 target path.
        guard data.count >= 4 else { throw SMBCodecError.truncated }
        guard readUInt32LE(data, at: 0) == 2 else {
            throw SMBCodecError.invalidValue("unsupported LX symlink reparse data version")
        }
        let target = String(bytes: data.dropFirst(4), encoding: .utf8) ?? ""
        return SMBReparsePoint(tag: tag, substituteName: target, rawData: data)
    }

    private static func decodeSymbolicLink(tag: UInt32, data: [UInt8]) throws -> SMBReparsePoint {
        guard data.count >= 12 else { throw SMBCodecError.truncated }
        let substituteOffset = Int(readUInt16LE(data, at: 0))
        let substituteLength = Int(readUInt16LE(data, at: 2))
        let printOffset = Int(readUInt16LE(data, at: 4))
        let printLength = Int(readUInt16LE(data, at: 6))
        let flags = readUInt32LE(data, at: 8)
        let pathBuffer = Array(data.dropFirst(12))
        return SMBReparsePoint(
            tag: tag,
            substituteName: try decodePathBuffer(pathBuffer, offset: substituteOffset, length: substituteLength),
            printName: try decodePathBuffer(pathBuffer, offset: printOffset, length: printLength),
            flags: flags,
            rawData: data
        )
    }

    private static func decodeMountPoint(tag: UInt32, data: [UInt8]) throws -> SMBReparsePoint {
        guard data.count >= 8 else { throw SMBCodecError.truncated }
        let substituteOffset = Int(readUInt16LE(data, at: 0))
        let substituteLength = Int(readUInt16LE(data, at: 2))
        let printOffset = Int(readUInt16LE(data, at: 4))
        let printLength = Int(readUInt16LE(data, at: 6))
        let pathBuffer = Array(data.dropFirst(8))
        return SMBReparsePoint(
            tag: tag,
            substituteName: try decodePathBuffer(pathBuffer, offset: substituteOffset, length: substituteLength),
            printName: try decodePathBuffer(pathBuffer, offset: printOffset, length: printLength),
            rawData: data
        )
    }

    private static func decodePathBuffer(_ bytes: [UInt8], offset: Int, length: Int) throws -> String {
        guard offset >= 0, length >= 0, offset + length <= bytes.count else {
            throw SMBCodecError.truncated
        }
        return decodeUTF16LE(Array(bytes[offset..<offset + length]))
    }
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
    static let securityOwner: UInt32 = 0x0000_0001
    static let securityGroup: UInt32 = 0x0000_0002
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
        buffer.writeUInt64LE(try dateToFiletime(update.creationTime))
        buffer.writeUInt64LE(try dateToFiletime(update.lastAccessTime))
        buffer.writeUInt64LE(try dateToFiletime(update.modifiedTime))
        buffer.writeUInt64LE(try dateToFiletime(update.changeTime))
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

    /// Non-nil components are the ones written: AdditionalInformation carries
    /// OWNER/GROUP/DACL bits for exactly the provided pieces (MS-SMB2 SET_INFO security).
    static func encodeSecurityDescriptorRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        ownerSID: String?,
        groupSID: String?,
        dacl: [SMBAccessControlEntry]?,
        force: Bool = false
    ) throws -> [UInt8] {
        var additionalInformation: UInt32 = 0
        if ownerSID != nil { additionalInformation |= securityOwner }
        if groupSID != nil { additionalInformation |= securityGroup }
        if dacl != nil { additionalInformation |= securityDACL }
        guard additionalInformation != 0 else {
            throw SMBCodecError.invalidValue("SET_SECURITY requires owner, group, or DACL")
        }
        let descriptor = try encodeSecurityDescriptor(ownerSID: ownerSID, groupSID: groupSID, dacl: dacl, force: force)
        return try encodeRequest(
            messageId: messageId,
            sessionId: sessionId,
            treeId: treeId,
            fileId: fileId,
            infoType: infoTypeSecurity,
            fileInfoClass: 0,
            additionalInformation: additionalInformation,
            buffer: descriptor
        )
    }

    static func encodeSecurityDescriptor(
        ownerSID: String?,
        groupSID: String?,
        dacl: [SMBAccessControlEntry]?,
        force: Bool = false
    ) throws -> [UInt8] {
        if let dacl {
            try validateWritableDACL(dacl, force: force)
        }
        var payload = Array(repeating: UInt8(0), count: 20)
        payload[0] = 1
        let control: UInt16 = securityDescriptorSelfRelative | (dacl != nil ? securityDescriptorDACLPresent : 0)
        writeUInt16LE(control, to: &payload, at: 2)
        if let ownerSID {
            writeUInt32LE(UInt32(payload.count), to: &payload, at: 4)
            payload.append(contentsOf: try encodeSID(ownerSID))
        }
        if let groupSID {
            writeUInt32LE(UInt32(payload.count), to: &payload, at: 8)
            payload.append(contentsOf: try encodeSID(groupSID))
        }
        if let dacl {
            writeUInt32LE(UInt32(payload.count), to: &payload, at: 16)
            payload.append(contentsOf: try encodeACL(dacl))
        }
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
        try writer.writeUInt16LE(count: aclSize, of: "ACL")
        try writer.writeUInt16LE(count: dacl.count, of: "DACL ACE count")
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
        try writer.writeUInt16LE(count: aceSize, of: "ACE")
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
    static let outputBufferSize: UInt32 = 256 * 1024

    /// MS-SMB2 §3.2.4.1.5: a request whose output buffer exceeds 64KiB must carry a
    /// CreditCharge of ceil(size / 65536); Samba rejects charge=1 with INVALID_PARAMETER.
    /// Callers cap `outputBufferLength` by the granted credit window (see
    /// `SMBSession.queryDirectoryPage`) so the request never blocks waiting for
    /// credits a stingy server has not granted.
    static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        restartScan: Bool = true,
        outputBufferLength: UInt32 = outputBufferSize
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        let creditCharge = SMB2Credit.charge(forPayloadLength: UInt64(outputBufferLength))
        let header = try SMB2Header(
            creditCharge: creditCharge,
            command: SMB2Commands.queryDirectory,
            credits: creditCharge,
            messageId: messageId,
            treeId: treeId,
            sessionId: sessionId
        ).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(33)
        writer.writeUInt8(37)
        writer.writeUInt8(restartScan ? 0x01 : 0x00)
        writer.writeUInt32LE(0)
        writer.writeBytes(fileId)
        writer.writeUInt16LE(UInt16(fileNameOffset))
        writer.writeUInt16LE(2)
        writer.writeUInt32LE(outputBufferLength)
        writer.writeBytes([0x2a, 0x00])
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws -> [SMBDirectoryEntry] {
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 9 else {
            throw SMBCodecError.invalidValue("invalid QUERY_DIRECTORY response structure size")
        }
        let dataOffset = Int(try reader.readUInt16LE())
        let length = Int(try reader.readUInt32LE())
        guard dataOffset + length <= bytes.count else { throw SMBCodecError.truncated }
        let data = bytes[dataOffset..<dataOffset + length]
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
            let nameStart = data.startIndex + nameOffset
            let name = decodeUTF16LE(Array(data[nameStart..<nameStart + nameLength]))
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

    private static func readUInt32LE(_ bytes: ArraySlice<UInt8>, at offset: Int) -> UInt32 {
        let i = bytes.startIndex + offset
        return UInt32(bytes[i])
            | (UInt32(bytes[i + 1]) << 8)
            | (UInt32(bytes[i + 2]) << 16)
            | (UInt32(bytes[i + 3]) << 24)
    }

    private static func readUInt64LE(_ bytes: ArraySlice<UInt8>, at offset: Int) -> UInt64 {
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

struct SMB2LockElement: Equatable, Sendable {
    static let sharedLock: UInt32 = 0x0000_0001
    static let exclusiveLock: UInt32 = 0x0000_0002
    static let unlock: UInt32 = 0x0000_0004
    static let failImmediately: UInt32 = 0x0000_0010

    var offset: UInt64
    var length: UInt64
    var flags: UInt32

    static func lock(offset: UInt64, length: UInt64, shared: Bool, failImmediately: Bool) -> SMB2LockElement {
        SMB2LockElement(
            offset: offset,
            length: length,
            flags: (shared ? sharedLock : exclusiveLock) | (failImmediately ? SMB2LockElement.failImmediately : 0)
        )
    }

    static func unlock(offset: UInt64, length: UInt64) -> SMB2LockElement {
        SMB2LockElement(offset: offset, length: length, flags: unlock)
    }
}

enum SMB2Lock {
    static func encodeRequest(
        messageId: UInt64,
        sessionId: UInt64,
        treeId: UInt32,
        fileId: [UInt8],
        elements: [SMB2LockElement]
    ) throws -> [UInt8] {
        guard fileId.count == 16 else { throw SMBCodecError.invalidValue("SMB FileId must be 16 bytes") }
        guard !elements.isEmpty, elements.count <= Int(UInt16.max) else {
            throw SMBCodecError.invalidValue("SMB LOCK requires 1...65535 lock elements")
        }
        let header = try SMB2Header(command: SMB2Commands.lock, messageId: messageId, treeId: treeId, sessionId: sessionId).encode()
        var writer = SMBByteWriter()
        writer.writeBytes(header)
        writer.writeUInt16LE(48)
        try writer.writeUInt16LE(count: elements.count, of: "LOCK element list")
        writer.writeUInt32LE(0)
        writer.writeBytes(fileId)
        for element in elements {
            writer.writeUInt64LE(element.offset)
            writer.writeUInt64LE(element.length)
            writer.writeUInt32LE(element.flags)
            writer.writeUInt32LE(0)
        }
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws {
        let header = try SMB2Header.decode(bytes)
        try SMBErrorMapper.throwIfFailure(status: header.status, operation: "LOCK")
        var reader = SMBByteReader(bytes: Array(bytes.dropFirst(SMB2Header.encodedSize)))
        guard try reader.readUInt16LE() == 4 else {
            throw SMBCodecError.invalidValue("invalid LOCK response structure size")
        }
        try reader.skip(count: 2)
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

private func dateToFiletime(_ date: Date?) throws -> UInt64 {
    guard let date else { return 0 }
    let secondsBetween1601And1970: TimeInterval = 11_644_473_600
    let ticks = (date.timeIntervalSince1970 + secondsBetween1601And1970) * 10_000_000
    guard ticks.isFinite, ticks >= 0, ticks <= Double(UInt64.max) else {
        throw SMBCodecError.invalidValue("date is outside SMB FILETIME range")
    }
    return UInt64(ticks)
}
