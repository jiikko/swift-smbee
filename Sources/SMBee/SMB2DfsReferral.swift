import Foundation

public struct SMBDfsReferralResult: Sendable {
    public let pathConsumed: Int
    public let headerFlags: UInt32
    public let referrals: [SMBDfsReferral]
}

public struct SMBDfsReferral: Sendable {
    public let versionNumber: UInt16
    public let serverType: UInt16
    public let flags: UInt16
    public let timeToLive: UInt32
    public let dfsPath: String?
    public let alternatePath: String?
    public let networkAddress: String?
}

enum SMB2DfsReferral {
    private static let referralHeaderSize = 8
    private static let referralV3V4FixedSize = 34
    private static let nameListReferralFlag: UInt16 = 0x0002

    static func encodeRequestInput(path: String, maxLevel: UInt16 = 4) -> [UInt8] {
        var writer = SMBByteWriter()
        writer.writeUInt16LE(maxLevel)
        writer.writeBytes(NTLM.utf16le(path))
        writer.writeUInt16LE(0)
        return writer.bytes
    }

    static func decodeResponse(_ bytes: [UInt8]) throws -> SMBDfsReferralResult {
        var reader = SMBByteReader(bytes: bytes)
        let pathConsumed = Int(try reader.readUInt16LE())
        let numberOfReferrals = Int(try reader.readUInt16LE())
        let headerFlags = try reader.readUInt32LE()
        var referrals: [SMBDfsReferral] = []
        var entryOffset = referralHeaderSize

        for _ in 0..<numberOfReferrals {
            guard entryOffset + 4 <= bytes.count else { throw SMBCodecError.truncated }
            let versionNumber = readUInt16LE(bytes, at: entryOffset)
            let size = Int(readUInt16LE(bytes, at: entryOffset + 2))
            guard size >= 4, entryOffset + size <= bytes.count else { throw SMBCodecError.truncated }
            if versionNumber == 3 || versionNumber == 4 {
                referrals.append(try decodeReferralV3V4(bytes: bytes, entryOffset: entryOffset, size: size, versionNumber: versionNumber))
            }
            entryOffset += size
        }

        return SMBDfsReferralResult(pathConsumed: pathConsumed, headerFlags: headerFlags, referrals: referrals)
    }

    private static func decodeReferralV3V4(bytes: [UInt8], entryOffset: Int, size: Int, versionNumber: UInt16) throws -> SMBDfsReferral {
        guard size >= referralV3V4FixedSize else { throw SMBCodecError.truncated }
        let serverType = readUInt16LE(bytes, at: entryOffset + 4)
        let flags = readUInt16LE(bytes, at: entryOffset + 6)
        let timeToLive = readUInt32LE(bytes, at: entryOffset + 8)
        let dfsPathOffset = Int(readUInt16LE(bytes, at: entryOffset + 12))
        let alternatePathOffset = Int(readUInt16LE(bytes, at: entryOffset + 14))
        let networkAddressOffset = Int(readUInt16LE(bytes, at: entryOffset + 16))

        // ⓥ NameListReferral changes the meaning of these offsets for DC referrals. Keep
        // the metadata and skip best-effort string parsing rather than guessing the format.
        if flags & nameListReferralFlag != 0 {
            return SMBDfsReferral(
                versionNumber: versionNumber,
                serverType: serverType,
                flags: flags,
                timeToLive: timeToLive,
                dfsPath: nil,
                alternatePath: nil,
                networkAddress: nil
            )
        }

        return SMBDfsReferral(
            versionNumber: versionNumber,
            serverType: serverType,
            flags: flags,
            timeToLive: timeToLive,
            dfsPath: try decodeReferralString(bytes: bytes, entryOffset: entryOffset, entrySize: size, stringOffset: dfsPathOffset),
            alternatePath: try decodeReferralString(bytes: bytes, entryOffset: entryOffset, entrySize: size, stringOffset: alternatePathOffset),
            networkAddress: try decodeReferralString(bytes: bytes, entryOffset: entryOffset, entrySize: size, stringOffset: networkAddressOffset)
        )
    }

    private static func decodeReferralString(bytes: [UInt8], entryOffset: Int, entrySize: Int, stringOffset: Int) throws -> String? {
        guard stringOffset != 0 else { return nil }
        guard stringOffset >= referralV3V4FixedSize else { throw SMBCodecError.truncated }
        // Synthetic fixtures commonly pack strings inside the referral entry. Samba
        // emits strings after the fixed-size entry, but the offsets remain relative
        // to the referral entry.
        let absoluteOffset: Int
        let stringEnd: Int
        if stringOffset < entrySize {
            absoluteOffset = entryOffset + stringOffset
            stringEnd = entryOffset + entrySize
        } else {
            absoluteOffset = entryOffset + stringOffset
            stringEnd = bytes.count
        }
        guard absoluteOffset < stringEnd else { throw SMBCodecError.truncated }
        var cursor = absoluteOffset
        while cursor + 1 < stringEnd {
            if bytes[cursor] == 0 && bytes[cursor + 1] == 0 {
                return decodeUTF16LE(Array(bytes[absoluteOffset..<cursor]))
            }
            cursor += 2
        }
        throw SMBCodecError.truncated
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
}
