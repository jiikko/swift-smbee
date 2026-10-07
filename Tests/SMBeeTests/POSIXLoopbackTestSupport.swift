import Foundation
@testable import SMBee

#if os(Linux)
import Glibc
#else
import Darwin
#endif

var streamSocketType: Int32 {
    #if os(Linux)
    Int32(SOCK_STREAM.rawValue)
    #else
    Int32(SOCK_STREAM)
    #endif
}

func saFamily(_ value: Int32) -> sa_family_t {
    sa_family_t(value)
}

func closeFD(_ fd: Int32) {
    #if os(Linux)
    _ = Glibc.close(fd)
    #else
    _ = Darwin.close(fd)
    #endif
}

final class POSIXLoopbackServer: @unchecked Sendable {
    enum Mode {
        case echoOnce
        case acceptAndHold
        /// Reads Direct-TCP frames until the peer closes and writes the frames the responder
        /// returns for each request body.
        case serveFrames(@Sendable ([UInt8]) throws -> [[UInt8]])
    }

    let port: UInt16
    private let listenFD: Int32
    private let mode: Mode
    private let lock = NSLock()
    private var acceptedFD: Int32 = -1

    init(mode: Mode) throws {
        self.mode = mode
        let listenDescriptor = socket(AF_INET, streamSocketType, Int32(IPPROTO_TCP))
        guard listenDescriptor >= 0 else { throw SMBTransportError.socketFailure("socket failed") }

        var reuse: Int32 = 1
        _ = setsockopt(
            listenDescriptor,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            socklen_t(MemoryLayout<Int32>.size)
        )

        var address = sockaddr_in()
        address.sin_family = saFamily(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                bind(listenDescriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            closeFD(listenDescriptor)
            throw SMBTransportError.socketFailure("bind failed")
        }
        guard listen(listenDescriptor, 1) == 0 else {
            closeFD(listenDescriptor)
            throw SMBTransportError.socketFailure("listen failed")
        }

        var boundAddress = sockaddr_in()
        var boundAddressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &boundAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getsockname(listenDescriptor, sockaddrPointer, &boundAddressLength)
            }
        }
        guard nameResult == 0 else {
            closeFD(listenDescriptor)
            throw SMBTransportError.socketFailure("getsockname failed")
        }
        listenFD = listenDescriptor
        port = UInt16(bigEndian: boundAddress.sin_port)
    }

    func start() {
        DispatchQueue.global().async { [self] in
            let clientFD = accept(listenFD, nil, nil)
            guard clientFD >= 0 else { return }
            lock.lock()
            acceptedFD = clientFD
            lock.unlock()

            switch mode {
            case .echoOnce:
                var buffer = [UInt8](repeating: 0, count: 64)
                let bufferCount = buffer.count
                let count = buffer.withUnsafeMutableBytes { recv(clientFD, $0.baseAddress, bufferCount, 0) }
                if count > 0 {
                    _ = buffer.withUnsafeBytes { send(clientFD, $0.baseAddress, count, 0) }
                }
                closeAccepted()
            case .acceptAndHold:
                break
            case .serveFrames(let responder):
                serveFrames(clientFD, responder: responder)
            }
        }
    }

    func close() {
        closeFD(listenFD)
        closeAccepted()
    }

    private func serveFrames(_ clientFD: Int32, responder: @Sendable ([UInt8]) throws -> [[UInt8]]) {
        while let header = receiveExactly(clientFD, count: 4),
              let length = try? DirectTCPFraming.length(from: header),
              let body = receiveExactly(clientFD, count: length),
              let responses = try? responder(body) {
            for response in responses {
                guard let frame = try? DirectTCPFraming.frame(response),
                      sendAll(clientFD, frame) else { return }
            }
        }
    }

    private func receiveExactly(_ descriptor: Int32, count: Int) -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let received = bytes.withUnsafeMutableBytes { buffer in
                recv(descriptor, buffer.baseAddress! + offset, count - offset, 0)
            }
            guard received > 0 else { return nil }
            offset += received
        }
        return bytes
    }

    private func sendAll(_ descriptor: Int32, _ bytes: [UInt8]) -> Bool {
        var offset = 0
        while offset < bytes.count {
            let sent = bytes.withUnsafeBytes { buffer in
                send(descriptor, buffer.baseAddress! + offset, bytes.count - offset, 0)
            }
            guard sent > 0 else { return false }
            offset += sent
        }
        return true
    }

    private func closeAccepted() {
        lock.lock()
        let descriptor = acceptedFD
        acceptedFD = -1
        lock.unlock()
        if descriptor >= 0 { closeFD(descriptor) }
    }
}
