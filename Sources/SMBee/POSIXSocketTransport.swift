import Foundation

#if os(Linux)
import Glibc
#else
import Darwin
#endif

public enum SMBTransportError: Error, Equatable {
    case connectionClosed
    case invalidAddress
    case socketFailure(String)
}

public final class POSIXSocketTransport: SMBTransport, @unchecked Sendable {
    private var socketFileDescriptor: Int32 = -1

    // POSIX is used instead of SwiftNIO for Phase 0 to keep the transport dependency-free
    // while still providing the Linux path required by the E2E plan.
    public init() {}

    public func connect(host: String, port: UInt16) async throws {
        try await Task.detached {
            try self.connectBlocking(host: host, port: port)
        }.value
    }

    public func send(_ bytes: [UInt8]) async throws {
        try await Task.detached {
            try self.sendBlocking(bytes)
        }.value
    }

    public func receive(maxLength: Int) async throws -> [UInt8] {
        try await Task.detached {
            try self.receiveBlocking(maxLength: maxLength)
        }.value
    }

    public func close() {
        if socketFileDescriptor >= 0 {
            #if os(Linux)
            _ = Glibc.close(socketFileDescriptor)
            #else
            _ = Darwin.close(socketFileDescriptor)
            #endif
            socketFileDescriptor = -1
        }
    }

    deinit {
        close()
    }

    private func connectBlocking(host: String, port: UInt16) throws {
        // `addrinfo` のメンバ順は Darwin と glibc で異なる (Linux は ai_addr が
        // ai_canonname より前) ため、memberwise initializer は使わず zero 初期化 +
        // 個別代入でプラットフォーム非依存にする。
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        // glibc では `SOCK_STREAM` が `__socket_type` enum なので Int32 へ変換が要る。
        #if os(Linux)
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #else
        hints.ai_socktype = SOCK_STREAM
        #endif
        // glibc では `IPPROTO_TCP` が `Int`、Darwin では `Int32`。両対応で Int32 に包む。
        hints.ai_protocol = Int32(IPPROTO_TCP)
        var result: UnsafeMutablePointer<addrinfo>?
        let service = String(port)
        guard getaddrinfo(host, service, &hints, &result) == 0, let first = result else {
            throw SMBTransportError.invalidAddress
        }
        defer { freeaddrinfo(result) }

        var current: UnsafeMutablePointer<addrinfo>? = first
        while let candidate = current {
            let descriptor = socket(candidate.pointee.ai_family, candidate.pointee.ai_socktype, candidate.pointee.ai_protocol)
            if descriptor >= 0 {
                if DarwinOrGlibc.connect(descriptor, candidate.pointee.ai_addr, candidate.pointee.ai_addrlen) == 0 {
                    socketFileDescriptor = descriptor
                    return
                }
                DarwinOrGlibc.close(descriptor)
            }
            current = candidate.pointee.ai_next
        }
        throw SMBTransportError.socketFailure("connect failed")
    }

    private func sendBlocking(_ bytes: [UInt8]) throws {
        guard socketFileDescriptor >= 0 else { throw SMBTransportError.connectionClosed }
        var sent = 0
        while sent < bytes.count {
            let count = bytes.withUnsafeBytes { buffer in
                DarwinOrGlibc.send(
                    socketFileDescriptor,
                    buffer.baseAddress!.advanced(by: sent),
                    bytes.count - sent,
                    0
                )
            }
            guard count > 0 else { throw SMBTransportError.socketFailure("send failed") }
            sent += count
        }
    }

    private func receiveBlocking(maxLength: Int) throws -> [UInt8] {
        guard socketFileDescriptor >= 0 else { throw SMBTransportError.connectionClosed }
        var buffer = [UInt8](repeating: 0, count: maxLength)
        let count = buffer.withUnsafeMutableBytes { rawBuffer in
            DarwinOrGlibc.recv(socketFileDescriptor, rawBuffer.baseAddress, maxLength, 0)
        }
        guard count > 0 else { throw SMBTransportError.connectionClosed }
        return Array(buffer.prefix(count))
    }
}

private enum DarwinOrGlibc {
    static func close(_ fd: Int32) {
        #if os(Linux)
        _ = Glibc.close(fd)
        #else
        _ = Darwin.close(fd)
        #endif
    }

    static func connect(_ fd: Int32, _ address: UnsafePointer<sockaddr>?, _ length: socklen_t) -> Int32 {
        #if os(Linux)
        Glibc.connect(fd, address, length)
        #else
        Darwin.connect(fd, address, length)
        #endif
    }

    static func send(_ fd: Int32, _ buffer: UnsafeRawPointer?, _ length: Int, _ flags: Int32) -> Int {
        #if os(Linux)
        Glibc.send(fd, buffer, length, flags)
        #else
        Darwin.send(fd, buffer, length, flags)
        #endif
    }

    static func recv(_ fd: Int32, _ buffer: UnsafeMutableRawPointer?, _ length: Int, _ flags: Int32) -> Int {
        #if os(Linux)
        Glibc.recv(fd, buffer, length, flags)
        #else
        Darwin.recv(fd, buffer, length, flags)
        #endif
    }
}
