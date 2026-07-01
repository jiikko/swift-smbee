import XCTest
@testable import SMBee

final class SMBeeE2ETests: XCTestCase {
    func testProbeNegotiatesExpectedProfile() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }

        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }

        let result = try await SMBProbe.probe(host: host, port: port)
        switch environment["SMBEE_E2E_PROFILE"] ?? "smb302-encrypted-required" {
        case "smb302-encrypted-required":
            XCTAssertEqual(result.dialect, SMBNegotiateConstants.dialect302)
            XCTAssertTrue(result.signingRequired)
            XCTAssertNil(result.signingAlgorithm)
            XCTAssertNil(result.cipher)
            XCTAssertNil(result.preauthHashAlgorithm)
        case "smb311-signing-required":
            XCTAssertEqual(result.dialect, SMBNegotiateConstants.dialect311)
            XCTAssertTrue(result.signingRequired)
            XCTAssertEqual(result.signingAlgorithm, SMBNegotiateConstants.aesGMAC)
            XCTAssertNil(result.cipher)
            XCTAssertEqual(result.preauthHashAlgorithm, SMBNegotiateConstants.sha512)
        case "smb311-encrypted-required":
            XCTAssertEqual(result.dialect, SMBNegotiateConstants.dialect311)
            XCTAssertTrue(result.signingRequired)
            XCTAssertEqual(result.signingAlgorithm, SMBNegotiateConstants.aesGMAC)
            XCTAssertEqual(result.cipher, SMBNegotiateConstants.aes128GCM)
            XCTAssertEqual(result.preauthHashAlgorithm, SMBNegotiateConstants.sha512)
        default:
            XCTFail("Unknown SMBEE_E2E_PROFILE")
        }
    }

    func testAuthenticatedTreeConnectAndListShowsKnownFile() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }

        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }
        let username = environment["SMBEE_E2E_USERNAME"] ?? "smbee"
        let password = environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"

        let entries = try await SMBee.list(
            host: host,
            port: port,
            credential: SMBCredential(username: username, password: password),
            share: share
        )
        XCTAssertTrue(entries.contains { $0.name == "known.txt" && !$0.isDirectory })

        let credential = SMBCredential(username: username, password: password)
        let session = try await SMBee.connect(host: host, port: port, credential: credential, share: share)
        let sessionEntries = try await session.list()
        await session.close()
        XCTAssertTrue(sessionEntries.contains { $0.name == "known.txt" && !$0.isDirectory })

        let streamedEntryNames = DirectoryNameAccumulator()
        try await SMBee.withDirectoryStream(
            host: host,
            port: port,
            credential: credential,
            share: share
        ) { entry in
            await streamedEntryNames.record(entry.name)
        }
        let streamContainsKnownFile = await streamedEntryNames.contains("known.txt")
        XCTAssertTrue(streamContainsKnownFile)

        let stat = try await SMBee.stat(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "known.txt"
        )
        XCTAssertEqual(stat.size, 21)
        XCTAssertFalse(stat.isDirectory)

        let securityInfo = try await SMBee.securityInfo(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "known.txt"
        )
        XCTAssertNotNil(securityInfo.ownerSID)
        XCTAssertGreaterThan(securityInfo.dacl?.count ?? 0, 0)
        if let originalDACL = securityInfo.dacl, originalDACL.allSatisfy({ $0.trusteeSID != nil }) {
            let addedACE = SMBAccessControlEntry(type: 0, flags: 0, accessMask: 0x0002_0000, trusteeSID: "S-1-1-0")
            let replacementDACL = originalDACL + [addedACE]
            do {
                try await SMBee.setSecurityInfo(
                    host: host,
                    port: port,
                    credential: credential,
                    share: share,
                    path: "known.txt",
                    dacl: replacementDACL
                )
                let updatedSecurityInfo = try await SMBee.securityInfo(
                    host: host,
                    port: port,
                    credential: credential,
                    share: share,
                    path: "known.txt"
                )
                // Samba is POSIX-ACL backed and normalizes the NT access mask on write
                // (observed: requested 0x00020000 stored as 0x00120089), so the round-trip is
                // not mask-exact. Assert the added trustee gained an ACCESS_ALLOWED (type 0) ACE.
                XCTAssertTrue(
                    updatedSecurityInfo.dacl?.contains { $0.trusteeSID == "S-1-1-0" && $0.type == 0 } == true,
                    "expected an ACCESS_ALLOWED ACE for the added trustee after SET_SECURITY"
                )
                try await SMBee.setSecurityInfo(
                    host: host,
                    port: port,
                    credential: credential,
                    share: share,
                    path: "known.txt",
                    dacl: originalDACL
                )
            } catch {
                try? await SMBee.setSecurityInfo(
                    host: host,
                    port: port,
                    credential: credential,
                    share: share,
                    path: "known.txt",
                    dacl: originalDACL
                )
                throw error
            }
        }

        let volumeInfo = try await SMBee.volumeInfo(
            host: host,
            port: port,
            credential: credential,
            share: share
        )
        XCTAssertGreaterThan(volumeInfo.totalBytes, 0)
        XCTAssertGreaterThanOrEqual(volumeInfo.totalBytes, volumeInfo.availableBytes)
        XCTAssertFalse(volumeInfo.filesystemName.isEmpty)

        let data = try await SMBee.read(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "known.txt"
        )
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "hello from SMBee E2E\n")

        let rangeData = try await SMBee.read(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "known.txt",
            range: SMBReadRange(offset: 6, length: 4)
        )
        XCTAssertEqual(String(decoding: rangeData, as: UTF8.self), "from")
    }

    func testShareDiscoveryListsPublicShare() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }

        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }
        let username = environment["SMBEE_E2E_USERNAME"] ?? "smbee"
        let password = environment["SMBEE_E2E_PASSWORD"] ?? "smbee"

        let shares = try await SMBee.listShares(
            host: host,
            port: port,
            credential: SMBCredential(username: username, password: password)
        )

        XCTAssertTrue(shares.contains { $0.name == "public" })
    }

    func testAuthenticatedWriteOperations() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }

        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }
        let username = environment["SMBEE_E2E_USERNAME"] ?? "smbee"
        let password = environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let credential = SMBCredential(username: username, password: password)
        let suffix = UUID().uuidString
        let directory = "smbee-e2e-\(suffix)"
        let original = "\(directory)\\upload.txt"
        let copied = "\(directory)\\copied.txt"
        let renamed = "\(directory)\\renamed.txt"
        let large = "\(directory)\\large.bin"
        let nested = "\(directory)\\nested"
        let nestedChild = "\(nested)\\child"
        let nestedFile = "\(nestedChild)\\delete-me.txt"
        let uploadedDirectory = "\(directory)\\uploaded-dir"
        let copiedDirectory = "\(directory)\\copied-dir"
        let payload = Array("hello write path \(suffix)\n".utf8)

        try await SMBee.makeDirectory(host: host, port: port, credential: credential, share: share, path: directory)
        var entries = try await SMBee.list(host: host, port: port, credential: credential, share: share)
        XCTAssertTrue(entries.contains { $0.name == directory && $0.isDirectory })

        try await SMBee.upload(host: host, port: port, credential: credential, share: share, path: original, data: payload)
        let data = try await SMBee.read(host: host, port: port, credential: credential, share: share, path: original)
        XCTAssertEqual(data, payload)
        let updatedModifiedTime = Date(timeIntervalSince1970: 1_704_067_200)
        try await SMBee.updateMetadata(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: original,
            update: SMBFileMetadataUpdate(modifiedTime: updatedModifiedTime)
        )
        let updatedStat = try await SMBee.stat(host: host, port: port, credential: credential, share: share, path: original)
        XCTAssertEqual(updatedStat.modifiedTime?.timeIntervalSince1970 ?? 0, updatedModifiedTime.timeIntervalSince1970, accuracy: 2)
        try await SMBee.copy(
            host: host,
            port: port,
            credential: credential,
            share: share,
            fromPath: original,
            toPath: copied
        )
        let copiedData = try await SMBee.read(host: host, port: port, credential: credential, share: share, path: copied)
        XCTAssertEqual(copiedData, payload)
        let localDownloadFile = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-e2e-download-\(suffix).txt")
        defer { try? FileManager.default.removeItem(at: localDownloadFile) }
        try await SMBee.download(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: original,
            localFile: localDownloadFile
        )
        XCTAssertEqual(try Data(contentsOf: localDownloadFile), Data(payload))

        let largePayload = (0..<(1024 * 1024)).map { UInt8($0 & 0xff) }
        let localLargeFile = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-e2e-\(suffix).bin")
        try Data(largePayload).write(to: localLargeFile)
        defer { try? FileManager.default.removeItem(at: localLargeFile) }
        try await SMBee.upload(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: large,
            localFile: localLargeFile
        )
        let largeData = try await SMBee.read(host: host, port: port, credential: credential, share: share, path: large)
        XCTAssertEqual(largeData, largePayload)

        try await SMBee.rename(
            host: host,
            port: port,
            credential: credential,
            share: share,
            fromPath: original,
            toPath: renamed
        )
        entries = try await SMBee.list(host: host, port: port, credential: credential, share: share, path: directory)
        XCTAssertFalse(entries.contains { $0.name == "upload.txt" })
        XCTAssertTrue(entries.contains { $0.name == "renamed.txt" })

        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: renamed)
        entries = try await SMBee.list(host: host, port: port, credential: credential, share: share, path: directory)
        XCTAssertFalse(entries.contains { $0.name == "renamed.txt" })
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: copied)

        try await SMBee.makeDirectory(host: host, port: port, credential: credential, share: share, path: nested)
        try await SMBee.makeDirectory(host: host, port: port, credential: credential, share: share, path: nestedChild)
        try await SMBee.upload(host: host, port: port, credential: credential, share: share, path: nestedFile, data: payload)
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: nested, directory: true, recursive: true)
        entries = try await SMBee.list(host: host, port: port, credential: credential, share: share, path: directory)
        XCTAssertFalse(entries.contains { $0.name == "nested" })

        let localUploadDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-e2e-upload-dir-\(suffix)")
        let localUploadChildDirectory = localUploadDirectory.appendingPathComponent("child")
        try FileManager.default.createDirectory(at: localUploadChildDirectory, withIntermediateDirectories: true)
        try Data(payload).write(to: localUploadChildDirectory.appendingPathComponent("file.txt"))
        defer { try? FileManager.default.removeItem(at: localUploadDirectory) }
        try await SMBee.uploadDirectory(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: uploadedDirectory,
            localDirectory: localUploadDirectory
        )
        let uploadedPayload = try await SMBee.read(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "\(uploadedDirectory)\\child\\file.txt"
        )
        XCTAssertEqual(uploadedPayload, payload)

        let localDownloadDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("smbee-e2e-download-dir-\(suffix)")
        defer { try? FileManager.default.removeItem(at: localDownloadDirectory) }
        try await SMBee.downloadDirectory(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: uploadedDirectory,
            localDirectory: localDownloadDirectory
        )
        XCTAssertEqual(
            try Data(contentsOf: localDownloadDirectory.appendingPathComponent("child/file.txt")),
            Data(payload)
        )
        try await SMBee.copyDirectory(
            host: host,
            port: port,
            credential: credential,
            share: share,
            fromPath: uploadedDirectory,
            toPath: copiedDirectory
        )
        let copiedDirectoryPayload = try await SMBee.read(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "\(copiedDirectory)\\child\\file.txt"
        )
        XCTAssertEqual(copiedDirectoryPayload, payload)
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: copiedDirectory, directory: true, recursive: true)
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: uploadedDirectory, directory: true, recursive: true)

        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: large)
        try await SMBee.delete(host: host, port: port, credential: credential, share: share, path: directory, directory: true)
    }

    func testReadStreamCountsFileLargerThan4GiB() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }
        guard environment["SMBEE_E2E_LARGE"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E_LARGE=1 to run the >4GiB read-stream E2E test")
        }

        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }
        let username = environment["SMBEE_E2E_USERNAME"] ?? "smbee"
        let password = environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let path = environment["SMBEE_E2E_LARGE_PATH"] ?? "large-4gib-plus.bin"
        let credential = SMBCredential(username: username, password: password)

        // Prepare this file manually; do not store it in git or require it in CI.
        // With test/e2e/start-local-samba.sh:
        //   docker exec smbee-samba-local truncate -s 4294967297 /srv/smbee/public/large-4gib-plus.bin
        //
        // This test validates that the streaming read path keeps offsets and
        // lengths on the UInt64 route while crossing the 4GiB boundary. It only
        // keeps a running byte count, never the full file contents in memory.
        let stat = try await SMBee.stat(host: host, port: port, credential: credential, share: share, path: path)
        XCTAssertFalse(stat.isDirectory)
        XCTAssertGreaterThan(stat.size, UInt64(UInt32.max))

        let accumulator = LargeReadAccumulator()
        try await SMBee.withReadStream(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: path
        ) { chunk in
            XCTAssertFalse(chunk.isEmpty)
            await accumulator.record(byteCount: chunk.count)
        }

        let total = await accumulator.total
        XCTAssertEqual(total, stat.size)
    }

    func testChangeNotifyReceivesFileCreation() async throws {
        guard ProcessInfo.processInfo.environment["SMBEE_E2E"] == "1" else {
            throw XCTSkip("Set SMBEE_E2E=1 to run Samba-backed E2E tests")
        }

        let environment = ProcessInfo.processInfo.environment
        let host = environment["SMBEE_E2E_HOST"] ?? "127.0.0.1"
        let portString = environment["SMBEE_E2E_PORT"] ?? "445"
        guard let port = UInt16(portString) else {
            XCTFail("SMBEE_E2E_PORT must be a valid UInt16, got \(portString)")
            return
        }
        let username = environment["SMBEE_E2E_USERNAME"] ?? "smbee"
        let password = environment["SMBEE_E2E_PASSWORD"] ?? "smbee"
        let share = environment["SMBEE_E2E_SHARE"] ?? "public"
        let credential = SMBCredential(username: username, password: password)
        let directory = "smbee-e2e-watch-\(UUID().uuidString)"
        let watchedFile = "created.txt"

        try await SMBee.makeDirectory(host: host, port: port, credential: credential, share: share, path: directory)

        let accumulator = DirectoryNameAccumulator()
        let watcher = Task {
            try await SMBee.withChangeNotifications(
                host: host,
                port: port,
                credential: credential,
                share: share,
                path: directory
            ) { event in
                if case .changes(let changes) = event {
                    for change in changes {
                        await accumulator.record(change.name)
                    }
                }
            }
        }

        // Let the watcher subscribe (CHANGE_NOTIFY must be registered before the create).
        try await Task.sleep(nanoseconds: 1_500_000_000)
        try await SMBee.upload(
            host: host,
            port: port,
            credential: credential,
            share: share,
            path: "\(directory)\\\(watchedFile)",
            data: Array("watch me\n".utf8)
        )

        // Bounded wait for the ADDED notification (do not block indefinitely).
        var observed = false
        for _ in 0..<40 {
            if await accumulator.contains(watchedFile) {
                observed = true
                break
            }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        watcher.cancel()

        XCTAssertTrue(observed, "expected a CHANGE_NOTIFY notification for \(watchedFile)")
    }
}

private actor LargeReadAccumulator {
    private var byteCount: UInt64 = 0

    var total: UInt64 {
        byteCount
    }

    func record(byteCount: Int) {
        self.byteCount += UInt64(byteCount)
    }
}

private actor DirectoryNameAccumulator {
    private var names: [String] = []

    func record(_ name: String) {
        names.append(name)
    }

    func contains(_ name: String) -> Bool {
        names.contains(name)
    }
}
