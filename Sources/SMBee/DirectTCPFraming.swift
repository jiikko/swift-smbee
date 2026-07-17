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
            throw SMBCodecError.invalidValue(
                "NetBIOS direct-TCP reserved byte must be zero: header=\(SMBDebug.hex(header))"
            )
        }
        return (Int(header[1]) << 16) | (Int(header[2]) << 8) | Int(header[3])
    }

    // A transport is a byte stream, while SMB sessions share one wire. Once a
    // direct-TCP frame has started, cancellation must not cancel the transport
    // operation: doing so can leave the remainder of the frame in the stream.
    // The detached task is intentionally not cancellation-inheriting. The
    // caller observes cancellation only after the complete frame is consumed.
    static func send(_ message: [UInt8], via transport: SMBTransport) async throws {
        try Task.checkCancellation()
        let bytes = try frame(message)
        try await Task.detached(priority: Task.currentPriority) {
            try await transport.send(bytes)
        }.value
        // Once the frame is on the wire, sending has succeeded and must return
        // normally. Throwing here would skip SMBClient.markRequestSent even
        // though the peer can observe the request, reintroducing credit/refund
        // and response-loop desynchronization. Cancellation is observed at the
        // next caller boundary before another operation begins.
    }

    static func receive(from transport: SMBTransport) async throws -> ([UInt8], [UInt8]) {
        try Task.checkCancellation()
        let frame = try await Task.detached(priority: Task.currentPriority) {
            let header = try await receiveExactly(4, from: transport)
            let body = try await receiveExactly(try length(from: header), from: transport)
            return (header, body)
        }.value
        // Unlike send, the frame is fully consumed and the stream is aligned,
        // so observing cancellation here cannot desynchronize subsequent reads.
        try Task.checkCancellation()
        return frame
    }

    private static func receiveExactly(_ count: Int, from transport: SMBTransport) async throws -> [UInt8] {
        var bytes: [UInt8] = []
        while bytes.count < count {
            let chunk = try await transport.receive(maxLength: count - bytes.count)
            guard !chunk.isEmpty else { throw SMBTransportError.connectionClosed }
            bytes += chunk
        }
        return bytes
    }
}
