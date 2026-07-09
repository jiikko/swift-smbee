import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif

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
        let encryptedTag = try encryptTag(tag, key: key, nonce: nonce)
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
        // Recompute the CBC-MAC over the decrypted plaintext directly (issues/014):
        // routing through seal() here would run the CTR keystream a second time for
        // nothing — the MAC only needs the plaintext and S0.
        let expectedTag = try authenticationTag(
            key: key,
            nonce: nonce,
            message: plaintext,
            authenticatedData: authenticatedData,
            tagLength: tag.count
        )
        let expected = try encryptTag(expectedTag, key: key, nonce: nonce)
        guard constantTimeEqual(expected, tag) else {
            throw SMBCodecError.invalidValue("AES-CCM authentication failed")
        }
        return plaintext
    }

    private static func encryptTag(_ tag: [UInt8], key: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        let s0 = try encryptBlock(key: key, block: counterBlock(nonce: nonce, counter: 0))
        var encryptedTag = Array(tag)
        for index in 0..<tag.count {
            encryptedTag[index] ^= s0[index]
        }
        return encryptedTag
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
        return Array(try cbcMACLastBlock(key: key, paddedInput: macInput).prefix(tagLength))
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

    // MARK: - AES primitives (CommonCrypto-accelerated on Apple platforms)

    // CCM の CTR / CBC-MAC は Apple platform では CommonCrypto (HW AES) に委譲する
    // (issues/014: pure-Swift AES128 は -Onone で 64 KiB あたり ~830 ms かかり、
    // 暗号化 SMB read の実効スループットを 0.08 MB/s に落としていた)。
    // CommonCrypto が無い platform (Linux) は従来の pure-Swift AES128 に落ちる。

    private static func ctrCrypt(key: [UInt8], nonce: [UInt8], input: [UInt8]) throws -> [UInt8] {
        guard !input.isEmpty else { return [] }
        #if canImport(CommonCrypto)
        // CCM の counter block は先頭が flags(1 byte) + nonce、末尾 q バイトが big-endian
        // counter (payload は counter=1 起点)。CommonCrypto の CTR は 16-byte block 全体を
        // big-endian インクリメントするため、counter が q バイト境界を溢れない限り
        // CCM の A_i 系列と一致する。溢れ条件 (block 数 + 1 >= 2^(8q)) は
        // authenticationTag の message 長ガード (message.count < 2^(8q)) が先に弾く。
        var cryptorOrNil: CCCryptorRef?
        let iv = counterBlock(nonce: nonce, counter: 1)
        let createStatus = iv.withUnsafeBufferPointer { ivPointer in
            key.withUnsafeBufferPointer { keyPointer in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivPointer.baseAddress,
                    keyPointer.baseAddress,
                    key.count,
                    nil,
                    0,
                    0,
                    0,
                    &cryptorOrNil
                )
            }
        }
        guard createStatus == kCCSuccess, let cryptor = cryptorOrNil else {
            throw SMBCodecError.invalidValue("AES-CTR cryptor creation failed: \(createStatus)")
        }
        defer { CCCryptorRelease(cryptor) }
        var output = [UInt8](repeating: 0, count: input.count)
        var moved = 0
        let updateStatus = input.withUnsafeBufferPointer { inputPointer in
            output.withUnsafeMutableBufferPointer { outputPointer in
                CCCryptorUpdate(
                    cryptor,
                    inputPointer.baseAddress,
                    input.count,
                    outputPointer.baseAddress,
                    outputPointer.count,
                    &moved
                )
            }
        }
        guard updateStatus == kCCSuccess, moved == input.count else {
            throw SMBCodecError.invalidValue("AES-CTR update failed: \(updateStatus)")
        }
        return output
        #else
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
        #endif
    }

    /// CBC-MAC = zero-IV CBC 暗号化の最終ブロック。`paddedInput` は 16 の倍数であること。
    private static func cbcMACLastBlock(key: [UInt8], paddedInput: [UInt8]) throws -> [UInt8] {
        precondition(paddedInput.count % 16 == 0)
        #if canImport(CommonCrypto)
        var output = [UInt8](repeating: 0, count: paddedInput.count)
        var moved = 0
        let status = paddedInput.withUnsafeBufferPointer { inputPointer in
            key.withUnsafeBufferPointer { keyPointer in
                output.withUnsafeMutableBufferPointer { outputPointer in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        0,
                        keyPointer.baseAddress,
                        key.count,
                        nil,
                        inputPointer.baseAddress,
                        paddedInput.count,
                        outputPointer.baseAddress,
                        outputPointer.count,
                        &moved
                    )
                }
            }
        }
        guard status == kCCSuccess, moved == paddedInput.count else {
            throw SMBCodecError.invalidValue("AES-CBC-MAC failed: \(status)")
        }
        return Array(output.suffix(16))
        #else
        var x = [UInt8](repeating: 0, count: 16)
        for offset in stride(from: 0, to: paddedInput.count, by: 16) {
            var block = Array(paddedInput[offset..<offset + 16])
            for index in 0..<16 { block[index] ^= x[index] }
            x = try AES128.encryptBlock(key: key, block: block)
        }
        return x
        #endif
    }

    private static func encryptBlock(key: [UInt8], block: [UInt8]) throws -> [UInt8] {
        #if canImport(CommonCrypto)
        var output = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = block.withUnsafeBufferPointer { blockPointer in
            key.withUnsafeBufferPointer { keyPointer in
                output.withUnsafeMutableBufferPointer { outputPointer in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyPointer.baseAddress,
                        key.count,
                        nil,
                        blockPointer.baseAddress,
                        block.count,
                        outputPointer.baseAddress,
                        outputPointer.count,
                        &moved
                    )
                }
            }
        }
        guard status == kCCSuccess, moved == 16 else {
            throw SMBCodecError.invalidValue("AES-ECB block encryption failed: \(status)")
        }
        return output
        #else
        return try AES128.encryptBlock(key: key, block: block)
        #endif
    }
}
