import Foundation
import XCTest
@testable import SMBee

final class SMBeeSourceCompatibilityTests: XCTestCase {
    func testLegacyCredentialProviderOverloadsAcceptNonescapingForwarding() {
        _ = forwardLegacyDownloadDirectory
        _ = forwardLegacyRead
        _ = forwardLegacyDataUpload
        _ = forwardLegacyFileURLUpload
        _ = forwardLegacyUploadDirectory
        _ = forwardLegacyLocalFileUpload
        _ = forwardLegacyCopyDirectory
        _ = forwardLegacyDelete
    }
}

private func forwardLegacyRead(_ provider: SMBCredentialProvider) async throws {
    _ = try await SMBee.read(
        host: "server",
        credentialProvider: provider,
        share: "share",
        path: "remote.txt"
    )
}

private func forwardLegacyDownloadDirectory(_ provider: SMBCredentialProvider) async throws {
    try await SMBee.downloadDirectory(
        host: "server",
        credentialProvider: provider,
        share: "share",
        path: "remote",
        localDirectory: URL(fileURLWithPath: "/tmp/download")
    )
}

private func forwardLegacyDataUpload(_ provider: SMBCredentialProvider) async throws {
    try await SMBee.upload(
        host: "server",
        credentialProvider: provider,
        share: "share",
        path: "remote.txt",
        data: []
    )
}

private func forwardLegacyFileURLUpload(_ provider: SMBCredentialProvider) async throws {
    try await SMBee.upload(
        host: "server",
        credentialProvider: provider,
        share: "share",
        path: "remote.txt",
        fileURL: URL(fileURLWithPath: "/tmp/upload")
    )
}

private func forwardLegacyUploadDirectory(_ provider: SMBCredentialProvider) async throws {
    try await SMBee.uploadDirectory(
        host: "server",
        credentialProvider: provider,
        share: "share",
        path: "remote",
        localDirectory: URL(fileURLWithPath: "/tmp/upload")
    )
}

private func forwardLegacyLocalFileUpload(_ provider: SMBCredentialProvider) async throws {
    try await SMBee.upload(
        host: "server",
        credentialProvider: provider,
        share: "share",
        path: "remote.txt",
        localFile: URL(fileURLWithPath: "/tmp/upload")
    )
}

private func forwardLegacyCopyDirectory(_ provider: SMBCredentialProvider) async throws {
    try await SMBee.copyDirectory(
        host: "server",
        credentialProvider: provider,
        share: "share",
        fromPath: "source",
        toPath: "destination"
    )
}

private func forwardLegacyDelete(_ provider: SMBCredentialProvider) async throws {
    try await SMBee.delete(
        host: "server",
        credentialProvider: provider,
        share: "share",
        path: "remote"
    )
}
