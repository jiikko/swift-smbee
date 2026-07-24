import XCTest
@testable import SMBee

final class SMBReparsePointE2ETests: XCTestCase {
    func testReadlinkAndRecursiveOperationsUseTheReparseEntry() async throws {
        let details = try connectionDetails()
        let root = "reparse-e2e-\(UUID().uuidString)"
        let targetPath = "reparse-target-\(UUID().uuidString).txt"
        let linkPath = "\(root)/target-link"
        let copiedRoot = "\(root)-copy"
        let payload = Array("reparse target remains intact\n".utf8)
        let session = try await SMBee.connect(
            host: details.host,
            port: details.port,
            credential: details.credential,
            share: details.share
        )

        do {
            try await session.upload(path: targetPath, data: payload)
            try await session.makeDirectory(path: root)
            try await session.upload(path: linkPath, data: [])
            try await session.installSymbolicLinkReparsePointForTesting(
                path: linkPath,
                target: "../\(targetPath)"
            )

            let stat = try await session.stat(path: linkPath)
            XCTAssertTrue(stat.isReparsePoint)
            XCTAssertEqual(stat.reparseTag, SMBReparseTags.symlink)
            XCTAssertEqual(stat.reparseKind, .symlink)

            let link = try await session.readlink(path: linkPath)
            XCTAssertEqual(link.kind, .symlink)
            XCTAssertEqual(link.substituteName, "../\(targetPath)")
            XCTAssertEqual(link.printName, "../\(targetPath)")
            XCTAssertEqual(link.flags, 1)

            let copiedActions = RecursiveActionRecorder()
            try await session.copyDirectory(
                fromPath: root,
                toPath: copiedRoot,
                onAction: { copiedActions.record($0) }
            )
            XCTAssertTrue(copiedActions.snapshot().contains {
                $0.kind == .skip && $0.path == "\(copiedRoot)/target-link"
            })

            try await session.delete(path: root, directory: true, recursive: true)
            let targetAfterDeletingLink = try await session.read(path: targetPath)
            XCTAssertEqual(targetAfterDeletingLink, payload)
            try await session.delete(path: copiedRoot, directory: true, recursive: true)
            try await session.delete(path: targetPath)
            await session.close()
        } catch {
            try? await session.delete(path: root, directory: true, recursive: true)
            try? await session.delete(path: copiedRoot, directory: true, recursive: true)
            try? await session.delete(path: targetPath)
            await session.close()
            throw error
        }
    }

    private func connectionDetails() throws -> ConnectionDetails {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_PROFILE"] == "smb422-reparse" else {
            throw XCTSkip("Reparse E2E requires the Samba 4.22 profile")
        }
        guard let port = UInt16(environment["SMBEE_E2E_PORT"] ?? "445") else {
            throw ReparseE2EConfigurationError.invalidPort
        }
        return ConnectionDetails(
            host: environment["SMBEE_E2E_HOST"] ?? "127.0.0.1",
            port: port,
            credential: SMBCredential(
                username: environment["SMBEE_E2E_USERNAME"] ?? "smbee",
                password: environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
            ),
            share: environment["SMBEE_E2E_SHARE"] ?? "public"
        )
    }
}

private struct ConnectionDetails {
    let host: String
    let port: UInt16
    let credential: SMBCredential
    let share: String
}

private enum ReparseE2EConfigurationError: Error {
    case invalidPort
}

private final class RecursiveActionRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var actions: [SMBRecursiveAction] = []

    func record(_ action: SMBRecursiveAction) {
        lock.lock()
        actions.append(action)
        lock.unlock()
    }

    func snapshot() -> [SMBRecursiveAction] {
        lock.lock()
        defer { lock.unlock() }
        return actions
    }
}
