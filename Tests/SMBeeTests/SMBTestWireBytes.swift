@testable import SMBee

func readUInt16LE(_ bytes: [UInt8], at offset: Int) -> UInt16 {
    UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
}

func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    UInt32(bytes[offset])
        | (UInt32(bytes[offset + 1]) << 8)
        | (UInt32(bytes[offset + 2]) << 16)
        | (UInt32(bytes[offset + 3]) << 24)
}

func writeUInt16LE(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
    bytes[offset] = UInt8(value & 0xff)
    bytes[offset + 1] = UInt8((value >> 8) & 0xff)
}

func writeUInt32LE(_ value: UInt32, to bytes: inout [UInt8], at offset: Int) {
    bytes[offset] = UInt8(value & 0xff)
    bytes[offset + 1] = UInt8((value >> 8) & 0xff)
    bytes[offset + 2] = UInt8((value >> 16) & 0xff)
    bytes[offset + 3] = UInt8((value >> 24) & 0xff)
}

func writeUInt64LE(_ value: UInt64, to bytes: inout [UInt8], at offset: Int) {
    writeUInt32LE(UInt32(value & 0xffff_ffff), to: &bytes, at: offset)
    writeUInt32LE(UInt32(value >> 32), to: &bytes, at: offset + 4)
}

func appendUInt16LE(_ value: UInt16, to bytes: inout [UInt8]) {
    bytes.append(UInt8(value & 0xff))
    bytes.append(UInt8(value >> 8))
}

func appendUInt32LE(_ value: UInt32, to bytes: inout [UInt8]) {
    bytes.append(UInt8(value & 0xff))
    bytes.append(UInt8((value >> 8) & 0xff))
    bytes.append(UInt8((value >> 16) & 0xff))
    bytes.append(UInt8((value >> 24) & 0xff))
}

func readSecurityBuffer(_ bytes: [UInt8], at offset: Int) -> [UInt8] {
    let length = Int(readUInt16LE(bytes, at: offset))
    let bufferOffset = Int(readUInt32LE(bytes, at: offset + 4))
    return Array(bytes[bufferOffset..<(bufferOffset + length)])
}

func readValidatedSecurityBuffer(_ bytes: [UInt8], at offset: Int) throws -> [UInt8] {
    guard offset >= 0, offset <= bytes.count - 8 else {
        throw SMBCodecError.truncated
    }
    let length = Int(readUInt16LE(bytes, at: offset))
    let bufferOffset = Int(readUInt32LE(bytes, at: offset + 4))
    guard bufferOffset >= 0, bufferOffset <= bytes.count, length <= bytes.count - bufferOffset else {
        throw SMBCodecError.truncated
    }
    return readSecurityBuffer(bytes, at: offset)
}

func testPacketSignatureInput(_ packet: [UInt8]) -> [UInt8] {
    var normalized = packet
    normalized[16] |= UInt8(SMB2Flags.signed & 0xff)
    normalized.replaceSubrange(48..<64, with: Array(repeating: 0, count: 16))
    return normalized
}

func signedTestPacket(
    _ packet: [UInt8],
    algorithm: SMBSessionSigningAlgorithm,
    key: [UInt8],
    sender: SMBSessionSigningSender
) throws -> [UInt8] {
    var signed = testPacketSignatureInput(packet)
    let signature = try SMBSessionSigning.signature(
        algorithm: algorithm,
        key: key,
        packet: signed,
        sender: sender
    )
    signed.replaceSubrange(48..<64, with: signature)
    return signed
}
