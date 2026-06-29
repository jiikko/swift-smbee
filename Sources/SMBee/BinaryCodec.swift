import Foundation

enum SMBCodecError: Error, Equatable {
    case truncated
    case invalidValue(String)
}

struct SMBByteWriter {
    private(set) var bytes: [UInt8] = []

    mutating func writeUInt8(_ value: UInt8) {
        bytes.append(value)
    }

    mutating func writeUInt16LE(_ value: UInt16) {
        bytes.append(UInt8(value & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
    }

    mutating func writeUInt32LE(_ value: UInt32) {
        bytes.append(UInt8(value & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 24) & 0xff))
    }

    mutating func writeUInt64LE(_ value: UInt64) {
        writeUInt32LE(UInt32(value & 0xffff_ffff))
        writeUInt32LE(UInt32((value >> 32) & 0xffff_ffff))
    }

    mutating func writeBytes(_ value: [UInt8]) {
        bytes.append(contentsOf: value)
    }

    mutating func padTo8() {
        while bytes.count % 8 != 0 {
            bytes.append(0)
        }
    }
}

struct SMBByteReader {
    let bytes: [UInt8]
    private(set) var offset: Int = 0

    var remaining: Int { bytes.count - offset }

    mutating func readUInt8() throws -> UInt8 {
        guard offset < bytes.count else { throw SMBCodecError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func readUInt16LE() throws -> UInt16 {
        let raw = try readBytes(count: 2)
        return UInt16(raw[0]) | (UInt16(raw[1]) << 8)
    }

    mutating func readUInt32LE() throws -> UInt32 {
        let raw = try readBytes(count: 4)
        return UInt32(raw[0])
            | (UInt32(raw[1]) << 8)
            | (UInt32(raw[2]) << 16)
            | (UInt32(raw[3]) << 24)
    }

    mutating func readUInt64LE() throws -> UInt64 {
        let low = UInt64(try readUInt32LE())
        let high = UInt64(try readUInt32LE())
        return low | (high << 32)
    }

    mutating func readBytes(count: Int) throws -> [UInt8] {
        guard count >= 0, offset + count <= bytes.count else { throw SMBCodecError.truncated }
        let value = Array(bytes[offset..<offset + count])
        offset += count
        return value
    }

    mutating func skip(count: Int) throws {
        _ = try readBytes(count: count)
    }
}
