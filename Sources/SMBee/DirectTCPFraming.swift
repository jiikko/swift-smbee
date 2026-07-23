import Foundation

enum DirectTCPFraming {
    // Keep direct-TCP framing in the SMB layer so transports remain plain byte streams.
    // This preserves the architecture rule that SMB logic depends only on SMBTransport.
    static func frame(_ message: [UInt8]) throws -> [UInt8] {
        let framed = try segments([message])
        var bytes: [UInt8] = []
        bytes.reserveCapacity(message.count + 4)
        for segment in framed { bytes.append(contentsOf: segment) }
        return bytes
    }

    /// Produces a framing header and payload buffers without joining the payload into
    /// another allocation. Vectored transports can send these buffers directly.
    static func segments(_ payload: [[UInt8]]) throws -> [[UInt8]] {
        let length = payload.reduce(0) { $0 + $1.count }
        guard length <= 0x00ff_ffff else {
            throw SMBCodecError.invalidValue("SMB direct-TCP frame too large")
        }
        let header: [UInt8] = [
            0,
            UInt8((length >> 16) & 0xff),
            UInt8((length >> 8) & 0xff),
            UInt8(length & 0xff)
        ]
        return [header] + payload
    }

    static func length(from header: [UInt8]) throws -> Int {
        guard header.count == 4 else { throw SMBCodecError.truncated }
        guard header[0] == 0 else {
            throw SMBCodecError.invalidValue(
                "NetBIOS direct-TCP reserved byte must be zero: header=\(SMBDebug.hex(header))"
            )
        }
        return (Int(header[1]) << 16) | (Int(header[2]) << 8) | Int(header[3])
    }
}
