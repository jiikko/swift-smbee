import Foundation

public enum SMBCLIExitCode {
    public static let success: Int32 = 0
    public static let other: Int32 = 1
    public static let usage: Int32 = 2
    public static let authentication: Int32 = 3
    public static let notFound: Int32 = 4
    public static let connection: Int32 = 5

    public static func code(for error: SMBError) -> Int32 {
        switch error {
        case .logonFailure, .accessDenied:
            authentication
        case .notFound:
            notFound
        case .connectionLost, .transport, .networkNameDeleted:
            connection
        case .sharingViolation, .nameCollision, .directoryNotEmpty, .fileIsADirectory,
             .notADirectory, .diskFull, .objectNameInvalid, .endOfFile, .unsupported,
             .protocolError, .invalidRecursion:
            other
        }
    }
}

public enum SMBCLIOutput {
    public static func jsonData(for probe: SMBProbeResult) throws -> Data {
        try encoder.encode(ProbeJSON(probe))
    }

    public static func jsonData(for entries: [SMBDirectoryEntry]) throws -> Data {
        try encoder.encode(entries.map(DirectoryEntryJSON.init))
    }

    public static func jsonData(for stat: SMBFileStat) throws -> Data {
        try encoder.encode(FileStatJSON(stat))
    }

    public static func jsonData(for volumeInfo: SMBVolumeInfo) throws -> Data {
        try encoder.encode(VolumeInfoJSON(volumeInfo))
    }

    public static func jsonData(for securityInfo: SMBSecurityInfo) throws -> Data {
        try encoder.encode(SecurityInfoJSON(securityInfo))
    }

    public static func jsonData(for shares: [SMBShareInfo]) throws -> Data {
        try encoder.encode(shares.map(ShareInfoJSON.init))
    }

    public static func jsonString(for probe: SMBProbeResult) throws -> String {
        try string(from: jsonData(for: probe))
    }

    public static func jsonString(for entries: [SMBDirectoryEntry]) throws -> String {
        try string(from: jsonData(for: entries))
    }

    public static func jsonString(for stat: SMBFileStat) throws -> String {
        try string(from: jsonData(for: stat))
    }

    public static func jsonString(for volumeInfo: SMBVolumeInfo) throws -> String {
        try string(from: jsonData(for: volumeInfo))
    }

    public static func jsonString(for securityInfo: SMBSecurityInfo) throws -> String {
        try string(from: jsonData(for: securityInfo))
    }

    public static func jsonString(for shares: [SMBShareInfo]) throws -> String {
        try string(from: jsonData(for: shares))
    }

    public static func hex<T: FixedWidthInteger>(_ value: T, width: Int) -> String {
        "0x" + String(format: "%0\(width)x", Int(value))
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private static func string(from data: Data) throws -> String {
        guard let string = String(data: data, encoding: .utf8) else {
            throw SMBError.protocolError("JSON output was not valid UTF-8")
        }
        return string
    }

    fileprivate static func dateString(_ date: Date?) -> String? {
        guard let date else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}

private struct ProbeJSON: Encodable {
    var dialect: String
    var signingRequired: Bool
    var signingAlgorithm: String?
    var cipher: String?
    var preauthHashAlgorithm: String?
    var serverGuid: String
    var maxTransactSize: UInt32
    var maxReadSize: UInt32
    var maxWriteSize: UInt32

    init(_ probe: SMBProbeResult) {
        dialect = SMBCLIOutput.hex(probe.dialect, width: 4)
        signingRequired = probe.signingRequired
        signingAlgorithm = probe.signingAlgorithm.map { SMBCLIOutput.hex($0, width: 4) }
        cipher = probe.cipher.map { SMBCLIOutput.hex($0, width: 4) }
        preauthHashAlgorithm = probe.preauthHashAlgorithm.map { SMBCLIOutput.hex($0, width: 4) }
        serverGuid = probe.serverGuid.uuidString
        maxTransactSize = probe.maxTransactSize
        maxReadSize = probe.maxReadSize
        maxWriteSize = probe.maxWriteSize
    }
}

private struct DirectoryEntryJSON: Encodable {
    var name: String
    var size: UInt64
    var isDirectory: Bool
    var attributes: String

    init(_ entry: SMBDirectoryEntry) {
        name = entry.name
        size = entry.fileSize
        isDirectory = entry.isDirectory
        attributes = SMBCLIOutput.hex(entry.attributes, width: 8)
    }
}

private struct FileStatJSON: Encodable {
    var size: UInt64
    var isDirectory: Bool
    var attributes: String
    var reparseTag: String?
    var reparseKind: String?
    var creationTime: String?
    var lastAccessTime: String?
    var modifiedTime: String?
    var changeTime: String?

    init(_ stat: SMBFileStat) {
        size = stat.size
        isDirectory = stat.isDirectory
        attributes = SMBCLIOutput.hex(stat.attributes, width: 8)
        reparseTag = stat.reparseTag.map { SMBCLIOutput.hex($0, width: 8) }
        reparseKind = stat.reparseKind?.description
        creationTime = SMBCLIOutput.dateString(stat.creationTime)
        lastAccessTime = SMBCLIOutput.dateString(stat.lastAccessTime)
        modifiedTime = SMBCLIOutput.dateString(stat.modifiedTime)
        changeTime = SMBCLIOutput.dateString(stat.changeTime)
    }
}

private struct VolumeInfoJSON: Encodable {
    var totalBytes: UInt64
    var usedBytes: UInt64
    var availableBytes: UInt64
    var filesystemName: String
    var volumeLabel: String
    var maxComponentLength: UInt32
    var filesystemAttributes: String
    var volumeSerialNumber: UInt32

    init(_ info: SMBVolumeInfo) {
        totalBytes = info.totalBytes
        usedBytes = info.usedBytes
        availableBytes = info.availableBytes
        filesystemName = info.filesystemName
        volumeLabel = info.volumeLabel
        maxComponentLength = info.maxComponentLength
        filesystemAttributes = SMBCLIOutput.hex(info.filesystemAttributes, width: 8)
        volumeSerialNumber = info.volumeSerialNumber
    }
}

private struct SecurityInfoJSON: Encodable {
    var ownerSID: String?
    var groupSID: String?
    var dacl: [AccessControlEntryJSON]?
    var controlFlags: String

    init(_ info: SMBSecurityInfo) {
        ownerSID = info.ownerSID
        groupSID = info.groupSID
        dacl = info.dacl?.map(AccessControlEntryJSON.init)
        controlFlags = SMBCLIOutput.hex(info.controlFlags, width: 4)
    }
}

private struct AccessControlEntryJSON: Encodable {
    var type: UInt8
    var flags: String
    var accessMask: String
    var trusteeSID: String?

    init(_ ace: SMBAccessControlEntry) {
        type = ace.type
        flags = SMBCLIOutput.hex(ace.flags, width: 2)
        accessMask = SMBCLIOutput.hex(ace.accessMask, width: 8)
        trusteeSID = ace.trusteeSID
    }
}

private struct ShareInfoJSON: Encodable {
    var name: String
    var type: String?
    var comment: String?

    init(_ share: SMBShareInfo) {
        name = share.name
        type = share.type.map { SMBCLIOutput.hex($0, width: 8) }
        comment = share.comment
    }
}
