#if canImport(CommonCrypto)
import CommonCrypto
#elseif canImport(CryptoExtras)
import Crypto
import CryptoExtras
#endif

enum AES128 {
    static func encryptBlock(key: [UInt8], block: [UInt8]) throws -> [UInt8] {
        guard key.count == 16, block.count == 16 else {
            throw SMBCodecError.invalidValue("AES-128 requires 16-byte key and block")
        }
        return try encryptBlock(expandedKey: expandKey(key), block: block)
    }

    static func expandedKey(_ key: [UInt8]) throws -> [UInt8] {
        guard key.count == 16 else {
            throw SMBCodecError.invalidValue("AES-128 requires a 16-byte key")
        }
        return expandKey(key)
    }

    static func encryptBlock(expandedKey roundKeys: [UInt8], block: [UInt8]) throws -> [UInt8] {
        guard roundKeys.count == 176, block.count == 16 else {
            throw SMBCodecError.invalidValue("AES-128 requires an expanded key and 16-byte block")
        }
        var state = block
        try encryptBlockInPlace(expandedKey: roundKeys, state: &state)
        return state
    }

    static func encryptBlockInPlace(expandedKey roundKeys: [UInt8], state: inout [UInt8]) throws {
        guard roundKeys.count == 176, state.count == 16 else {
            throw SMBCodecError.invalidValue("AES-128 requires an expanded key and 16-byte block")
        }
        addRoundKey(&state, roundKeys, offset: 0)
        for round in 1..<10 {
            subBytes(&state)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, roundKeys, offset: round * 16)
        }
        subBytes(&state)
        shiftRows(&state)
        addRoundKey(&state, roundKeys, offset: 160)
    }

    private static func expandKey(_ key: [UInt8]) -> [UInt8] {
        var expanded = key
        var bytesGenerated = 16
        var rconIndex = 1
        var temp = [UInt8](repeating: 0, count: 4)
        while bytesGenerated < 176 {
            for index in 0..<4 {
                temp[index] = expanded[bytesGenerated - 4 + index]
            }
            if bytesGenerated % 16 == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]]
                for index in 0..<4 { temp[index] = sbox[Int(temp[index])] }
                temp[0] ^= rcon[rconIndex]
                rconIndex += 1
            }
            for index in 0..<4 {
                expanded.append(expanded[bytesGenerated - 16] ^ temp[index])
                bytesGenerated += 1
            }
        }
        return expanded
    }

    private static func addRoundKey(_ state: inout [UInt8], _ key: [UInt8], offset: Int) {
        for index in 0..<16 { state[index] ^= key[offset + index] }
    }

    private static func subBytes(_ state: inout [UInt8]) {
        for index in 0..<16 { state[index] = sbox[Int(state[index])] }
    }

    private static func shiftRows(_ state: inout [UInt8]) {
        let row1 = (state[1], state[5], state[9], state[13])
        state[1] = row1.1; state[5] = row1.2; state[9] = row1.3; state[13] = row1.0
        let row2 = (state[2], state[6], state[10], state[14])
        state[2] = row2.2; state[6] = row2.3; state[10] = row2.0; state[14] = row2.1
        let row3 = (state[3], state[7], state[11], state[15])
        state[3] = row3.3; state[7] = row3.0; state[11] = row3.1; state[15] = row3.2
    }

    private static func mixColumns(_ state: inout [UInt8]) {
        for column in 0..<4 {
            let i = column * 4
            let a0 = state[i], a1 = state[i + 1], a2 = state[i + 2], a3 = state[i + 3]
            state[i] = multiply2(a0) ^ multiply3(a1) ^ a2 ^ a3
            state[i + 1] = a0 ^ multiply2(a1) ^ multiply3(a2) ^ a3
            state[i + 2] = a0 ^ a1 ^ multiply2(a2) ^ multiply3(a3)
            state[i + 3] = multiply3(a0) ^ a1 ^ a2 ^ multiply2(a3)
        }
    }

    private static func multiply2(_ value: UInt8) -> UInt8 {
        let shifted = value << 1
        return (value & 0x80) == 0 ? shifted : shifted ^ 0x1b
    }

    private static func multiply3(_ value: UInt8) -> UInt8 {
        multiply2(value) ^ value
    }

    private static let rcon: [UInt8] = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ]

    private static let sbox: [UInt8] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
}

public enum AESCMAC {
#if canImport(CryptoExtras) && !canImport(CommonCrypto)
    /// Reuses the BoringSSL CMAC key schedule while keeping each message one-shot.
    /// Copying the template clones the native context, so a finalized message never
    /// contaminates the next packet.
    struct Context {
        private let template: AES.CMAC

        init(key: [UInt8]) throws {
            guard key.count == 16 else {
                throw SMBCodecError.invalidValue("AES-CMAC requires a 16-byte key")
            }
            template = try AES.CMAC(key: SymmetricKey(data: key))
        }

        func authenticationCode(message: [UInt8]) -> [UInt8] {
            var authenticator = template
            message.withUnsafeBytes { authenticator.update(bufferPointer: $0) }
            return Array(authenticator.finalize())
        }
    }
#endif

    public static func authenticationCode(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        guard key.count == 16 else { throw SMBCodecError.invalidValue("AES-CMAC requires a 16-byte key") }
        // Keep the context one-shot: session close/reconnect must not leave expanded key state behind.
        // Apple uses its system AES implementation; Linux uses swift-crypto's BoringSSL-backed CMAC.
        #if canImport(CommonCrypto)
        return try commonCryptoAuthenticationCode(key: key, message: message)
        #elseif canImport(CryptoExtras)
        var authenticator = try AES.CMAC(key: SymmetricKey(data: key))
        message.withUnsafeBytes { authenticator.update(bufferPointer: $0) }
        return Array(authenticator.finalize())
        #else
        return try pureSwiftAuthenticationCode(key: key, message: message)
        #endif
    }

    #if canImport(CommonCrypto)
    private static func commonCryptoAuthenticationCode(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        var l = [UInt8](repeating: 0, count: 16)
        try commonCryptoEncryptInPlace(key: key, input: &l, options: CCOptions(kCCOptionECBMode))
        let subkey = !message.isEmpty && message.count % 16 == 0 ? dbl(l) : dbl(dbl(l))

        var input = message
        if input.isEmpty || input.count % 16 != 0 {
            input.append(0x80)
            input.append(contentsOf: repeatElement(0, count: (16 - input.count % 16) % 16))
        }
        let lastBlockOffset = input.count - 16
        for index in 0..<16 { input[lastBlockOffset + index] ^= subkey[index] }

        try commonCryptoEncryptInPlace(key: key, input: &input, options: 0)
        return Array(input.suffix(16))
    }

    private static func commonCryptoEncryptInPlace(
        key: [UInt8], input: inout [UInt8], options: CCOptions
    ) throws {
        let inputCount = input.count
        var moved = 0
        let status = input.withUnsafeMutableBufferPointer { inputPointer in
            key.withUnsafeBufferPointer { keyPointer in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    options,
                    keyPointer.baseAddress,
                    key.count,
                    nil,
                    inputPointer.baseAddress,
                    inputCount,
                    inputPointer.baseAddress,
                    inputCount,
                    &moved
                )
            }
        }
        guard status == kCCSuccess, moved == inputCount else {
            throw SMBCodecError.invalidValue("AES-CMAC CommonCrypto operation failed: \(status)")
        }
    }
    #endif

    static func pureSwiftAuthenticationCode(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        guard key.count == 16 else { throw SMBCodecError.invalidValue("AES-CMAC requires a 16-byte key") }
        let expandedKey = try AES128.expandedKey(key)
        var l = [UInt8](repeating: 0, count: 16)
        try AES128.encryptBlockInPlace(expandedKey: expandedKey, state: &l)
        let k1 = dbl(l)
        let k2 = dbl(k1)
        let blockCount = max(1, (message.count + 15) / 16)
        let complete = !message.isEmpty && message.count % 16 == 0
        var last = [UInt8](repeating: 0, count: 16)
        let lastStart = (blockCount - 1) * 16
        if complete {
            for index in 0..<16 { last[index] = message[lastStart + index] }
            xor(&last, k1)
        } else {
            if lastStart < message.count {
                for index in 0..<(message.count - lastStart) { last[index] = message[lastStart + index] }
            }
            last[message.count - lastStart] = 0x80
            xor(&last, k2)
        }
        var state = [UInt8](repeating: 0, count: 16)
        if blockCount > 1 {
            for blockIndex in 0..<(blockCount - 1) {
                let start = blockIndex * 16
                for index in 0..<16 { state[index] ^= message[start + index] }
                try AES128.encryptBlockInPlace(expandedKey: expandedKey, state: &state)
            }
        }
        xor(&last, state)
        try AES128.encryptBlockInPlace(expandedKey: expandedKey, state: &last)
        return last
    }

    private static func dbl(_ input: [UInt8]) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 16)
        var carry: UInt8 = 0
        for index in stride(from: 15, through: 0, by: -1) {
            let byte = input[index]
            output[index] = (byte << 1) | carry
            carry = (byte & 0x80) == 0 ? 0 : 1
        }
        if carry != 0 { output[15] ^= 0x87 }
        return output
    }

    private static func xor(_ lhs: inout [UInt8], _ rhs: [UInt8]) {
        for index in 0..<lhs.count { lhs[index] ^= rhs[index] }
    }
}
