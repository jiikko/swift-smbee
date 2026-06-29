import Foundation

enum DirectTCPFraming {
    // Keep direct-TCP framing in the SMB layer so transports remain plain byte streams.
    // This preserves the architecture rule that SMB logic depends only on SMBTransport.
    static func frame(_ message: [UInt8]) throws -> [UInt8] {
        guard message.count <= 0x00ff_ffff else {
            throw SMBCodecError.invalidValue("SMB direct-TCP frame too large")
        }
        return [
            0,
            UInt8((message.count >> 16) & 0xff),
            UInt8((message.count >> 8) & 0xff),
            UInt8(message.count & 0xff),
        ] + message
    }

    static func length(from header: [UInt8]) throws -> Int {
        guard header.count == 4 else { throw SMBCodecError.truncated }
        guard header[0] == 0 else {
            throw SMBCodecError.invalidValue("NetBIOS direct-TCP reserved byte must be zero")
        }
        return (Int(header[1]) << 16) | (Int(header[2]) << 8) | Int(header[3])
    }
}
