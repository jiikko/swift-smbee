public enum MD4 {
    public static func hash(_ bytes: [UInt8]) -> [UInt8] {
        var message = bytes
        let bitLength = UInt64(message.count) * 8
        message.append(0x80)
        while message.count % 64 != 56 {
            message.append(0)
        }
        for shift in stride(from: 0, to: 64, by: 8) {
            message.append(UInt8((bitLength >> UInt64(shift)) & 0xff))
        }

        var a: UInt32 = 0x6745_2301
        var b: UInt32 = 0xefcd_ab89
        var c: UInt32 = 0x98ba_dcfe
        var d: UInt32 = 0x1032_5476

        for chunkStart in stride(from: 0, to: message.count, by: 64) {
            var x = [UInt32](repeating: 0, count: 16)
            for index in 0..<16 {
                let base = chunkStart + index * 4
                x[index] = UInt32(message[base])
                    | (UInt32(message[base + 1]) << 8)
                    | (UInt32(message[base + 2]) << 16)
                    | (UInt32(message[base + 3]) << 24)
            }

            let aa = a
            let bb = b
            let cc = c
            let dd = d

            round1(&a, b, c, d, x[0], 3)
            round1(&d, a, b, c, x[1], 7)
            round1(&c, d, a, b, x[2], 11)
            round1(&b, c, d, a, x[3], 19)
            round1(&a, b, c, d, x[4], 3)
            round1(&d, a, b, c, x[5], 7)
            round1(&c, d, a, b, x[6], 11)
            round1(&b, c, d, a, x[7], 19)
            round1(&a, b, c, d, x[8], 3)
            round1(&d, a, b, c, x[9], 7)
            round1(&c, d, a, b, x[10], 11)
            round1(&b, c, d, a, x[11], 19)
            round1(&a, b, c, d, x[12], 3)
            round1(&d, a, b, c, x[13], 7)
            round1(&c, d, a, b, x[14], 11)
            round1(&b, c, d, a, x[15], 19)

            round2(&a, b, c, d, x[0], 3)
            round2(&d, a, b, c, x[4], 5)
            round2(&c, d, a, b, x[8], 9)
            round2(&b, c, d, a, x[12], 13)
            round2(&a, b, c, d, x[1], 3)
            round2(&d, a, b, c, x[5], 5)
            round2(&c, d, a, b, x[9], 9)
            round2(&b, c, d, a, x[13], 13)
            round2(&a, b, c, d, x[2], 3)
            round2(&d, a, b, c, x[6], 5)
            round2(&c, d, a, b, x[10], 9)
            round2(&b, c, d, a, x[14], 13)
            round2(&a, b, c, d, x[3], 3)
            round2(&d, a, b, c, x[7], 5)
            round2(&c, d, a, b, x[11], 9)
            round2(&b, c, d, a, x[15], 13)

            for index in [0, 2, 1, 3] {
                round3(&a, b, c, d, x[index], 3)
                round3(&d, a, b, c, x[index + 8], 9)
                round3(&c, d, a, b, x[index + 4], 11)
                round3(&b, c, d, a, x[index + 12], 15)
            }

            a = a &+ aa
            b = b &+ bb
            c = c &+ cc
            d = d &+ dd
        }

        var digest: [UInt8] = []
        digest.reserveCapacity(16)
        for word in [a, b, c, d] {
            digest.append(UInt8(word & 0xff))
            digest.append(UInt8((word >> 8) & 0xff))
            digest.append(UInt8((word >> 16) & 0xff))
            digest.append(UInt8((word >> 24) & 0xff))
        }
        return digest
    }

    private static func f(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        (x & y) | (~x & z)
    }

    private static func g(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        (x & y) | (x & z) | (y & z)
    }

    private static func h(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        x ^ y ^ z
    }

    private static func rotateLeft(_ value: UInt32, by bits: UInt32) -> UInt32 {
        (value << bits) | (value >> (32 - bits))
    }

    private static func round1(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ x: UInt32, _ s: UInt32) {
        a = rotateLeft(a &+ f(b, c, d) &+ x, by: s)
    }

    private static func round2(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ x: UInt32, _ s: UInt32) {
        a = rotateLeft(a &+ g(b, c, d) &+ x &+ 0x5a82_7999, by: s)
    }

    private static func round3(_ a: inout UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, _ x: UInt32, _ s: UInt32) {
        a = rotateLeft(a &+ h(b, c, d) &+ x &+ 0x6ed9_eba1, by: s)
    }
}
