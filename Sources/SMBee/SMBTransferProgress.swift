import Foundation

public struct SMBTransferProgress: Sendable {
    public let bytesTransferred: UInt64
    public let totalBytes: UInt64?
    public let bytesPerSecond: Double

    public init(bytesTransferred: UInt64, totalBytes: UInt64?, bytesPerSecond: Double) {
        self.bytesTransferred = bytesTransferred
        self.totalBytes = totalBytes
        self.bytesPerSecond = bytesPerSecond
    }
}
