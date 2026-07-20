import Foundation
import XCTest
@testable import SMBee

final class SMBeeOperationDeadlineE2ETests: XCTestCase {
    // swiftlint:disable:next function_body_length
    func testRecursiveFacadeOperationsWithOperationTimeout() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        guard let port = UInt16(environment["SMBEE_E2E_PORT"] ?? "445") else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16")
            return
        }
        let credential = SMBCredential(
            username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
            password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        )
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let suffix = UUID().uuidString
        let uploaded = "smbee-deadline-uploaded-\(suffix)"
        let copied = "smbee-deadline-copied-\(suffix)"
        let localSource = FileManager.default.temporaryDirectory
            .appendingPathComponent("smbee-deadline-source-\(suffix)")
        let localDownload = FileManager.default.temporaryDirectory
            .appendingPathComponent("smbee-deadline-download-\(suffix)")
        try FileManager.default.createDirectory(at: localSource, withIntermediateDirectories: true)
        let payload = Data("recursive deadline\n".utf8)
        try payload.write(to: localSource.appendingPathComponent("file.txt"))
        defer {
            try? FileManager.default.removeItem(at: localSource)
            try? FileManager.default.removeItem(at: localDownload)
        }

        do {
            try await SMBee.uploadDirectory(
                host: host, port: port, credential: credential, share: share,
                path: uploaded, localDirectory: localSource, operationTimeout: .seconds(10)
            )
            try await SMBee.downloadDirectory(
                host: host, port: port, credential: credential, share: share,
                path: uploaded, localDirectory: localDownload, operationTimeout: .seconds(10)
            )
            XCTAssertEqual(try Data(contentsOf: localDownload.appendingPathComponent("file.txt")), payload)
            try await SMBee.copyDirectory(
                host: host, port: port, credential: credential, share: share,
                fromPath: uploaded, toPath: copied, operationTimeout: .seconds(10)
            )
            let copiedPayload = try await SMBee.read(
                host: host, port: port, credential: credential, share: share,
                path: "\(copied)\\file.txt", operationTimeout: .seconds(10)
            )
            XCTAssertEqual(Data(copiedPayload), payload)
            try await SMBee.delete(
                host: host, port: port, credential: credential, share: share,
                path: copied, directory: true, recursive: true, operationTimeout: .seconds(10)
            )
            try await SMBee.delete(
                host: host, port: port, credential: credential, share: share,
                path: uploaded, directory: true, recursive: true, operationTimeout: .seconds(10)
            )
            let rootEntries = try await SMBee.list(
                host: host, port: port, credential: credential, share: share
            )
            XCTAssertFalse(rootEntries.contains { $0.name == copied })
            XCTAssertFalse(rootEntries.contains { $0.name == uploaded })
        } catch {
            try? await SMBee.delete(
                host: host, port: port, credential: credential, share: share,
                path: copied, directory: true, recursive: true, operationTimeout: .seconds(10)
            )
            try? await SMBee.delete(
                host: host, port: port, credential: credential, share: share,
                path: uploaded, directory: true, recursive: true, operationTimeout: .seconds(10)
            )
            throw error
        }
    }
}
