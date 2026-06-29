import Foundation

public enum AESCCM {
    public static func seal(
        key: [UInt8],
        nonce: [UInt8],
        plaintext: [UInt8],
        authenticatedData: [UInt8],
        tagLength: Int = 16
    ) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
        try validate(key: key, nonce: nonce, tagLength: tagLength)
        let tag = try authenticationTag(
            key: key,
            nonce: nonce,
            message: plaintext,
            authenticatedData: authenticatedData,
            tagLength: tagLength
        )
        let stream = try ctrCrypt(key: key, nonce: nonce, input: plaintext)
        let s0 = try AES128.encryptBlock(key: key, block: counterBlock(nonce: nonce, counter: 0))
        var encryptedTag = Array(tag)
        for index in 0..<tagLength {
            encryptedTag[index] ^= s0[index]
        }
        return (stream, encryptedTag)
    }

    public static func open(
        key: [UInt8],
        nonce: [UInt8],
        ciphertext: [UInt8],
        authenticatedData: [UInt8],
        tag: [UInt8]
    ) throws -> [UInt8] {
        try validate(key: key, nonce: nonce, tagLength: tag.count)
        let plaintext = try ctrCrypt(key: key, nonce: nonce, input: ciphertext)
        let expected = try seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            authenticatedData: authenticatedData,
            tagLength: tag.count
        ).tag
        guard constantTimeEqual(expected, tag) else {
            throw SMBCodecError.invalidValue("AES-CCM authentication failed")
        }
        return plaintext
    }

    private static func validate(key: [UInt8], nonce: [UInt8], tagLength: Int) throws {
        guard key.count == 16 else { throw SMBCodecError.invalidValue("AES-CCM requires a 16-byte key") }
        guard (7...13).contains(nonce.count) else { throw SMBCodecError.invalidValue("AES-CCM nonce must be 7...13 bytes") }
        guard (4...16).contains(tagLength), tagLength % 2 == 0 else {
            throw SMBCodecError.invalidValue("AES-CCM tag length must be even and 4...16 bytes")
        }
    }

    private static func authenticationTag(
        key: [UInt8],
        nonce: [UInt8],
        message: [UInt8],
        authenticatedData: [UInt8],
        tagLength: Int
    ) throws -> [UInt8] {
        let q = 15 - nonce.count
        guard message.count < (1 << (8 * q)) else {
            throw SMBCodecError.invalidValue("AES-CCM message too large for nonce length")
        }
        var b0Flags = UInt8(((tagLength - 2) / 2) << 3) | UInt8(q - 1)
        if !authenticatedData.isEmpty { b0Flags |= 0x40 }
        var macInput = [b0Flags] + nonce + encodeLength(message.count, bytes: q)
        if !authenticatedData.isEmpty {
            macInput += encodeAADLength(authenticatedData.count)
            macInput += authenticatedData
            while macInput.count % 16 != 0 { macInput.append(0) }
        }
        macInput += message
        while macInput.count % 16 != 0 { macInput.append(0) }

        var x = [UInt8](repeating: 0, count: 16)
        for offset in stride(from: 0, to: macInput.count, by: 16) {
            var block = Array(macInput[offset..<offset + 16])
            for index in 0..<16 { block[index] ^= x[index] }
            x = try AES128.encryptBlock(key: key, block: block)
        }
        return Array(x.prefix(tagLength))
    }

    private static func ctrCrypt(key: [UInt8], nonce: [UInt8], input: [UInt8]) throws -> [UInt8] {
        guard !input.isEmpty else { return [] }
        var output = input
        var counter = 1
        var offset = 0
        while offset < input.count {
            let stream = try AES128.encryptBlock(key: key, block: counterBlock(nonce: nonce, counter: counter))
            let blockLength = min(16, input.count - offset)
            for index in 0..<blockLength {
                output[offset + index] ^= stream[index]
            }
            offset += blockLength
            counter += 1
        }
        return output
    }

    private static func counterBlock(nonce: [UInt8], counter: Int) -> [UInt8] {
        let q = 15 - nonce.count
        return [UInt8(q - 1)] + nonce + encodeLength(counter, bytes: q)
    }

    private static func encodeLength(_ value: Int, bytes: Int) -> [UInt8] {
        (0..<bytes).map { shift in
            UInt8((value >> (8 * (bytes - 1 - shift))) & 0xff)
        }
    }

    private static func encodeAADLength(_ length: Int) -> [UInt8] {
        if length < 0xff00 {
            return [UInt8((length >> 8) & 0xff), UInt8(length & 0xff)]
        }
        var encoded: [UInt8] = [0xff, 0xfe]
        encoded += encodeLength(length, bytes: 4)
        return encoded
    }

    private static func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for index in 0..<lhs.count {
            diff |= lhs[index] ^ rhs[index]
        }
        return diff == 0
    }
}
