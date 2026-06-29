import Foundation

public enum SMBError: Error, Equatable, Sendable {
    case notFound(status: UInt32, operation: String)
    case accessDenied(status: UInt32, operation: String)
    case sharingViolation(status: UInt32, operation: String)
    case nameCollision(status: UInt32, operation: String)
    case directoryNotEmpty(status: UInt32, operation: String)
    case fileIsADirectory(status: UInt32, operation: String)
    case notADirectory(status: UInt32, operation: String)
    case diskFull(status: UInt32, operation: String)
    case networkNameDeleted(status: UInt32, operation: String)
    case logonFailure(status: UInt32, operation: String)
    case objectNameInvalid(status: UInt32, operation: String)
    case endOfFile(status: UInt32, operation: String)
    case unsupported(status: UInt32, operation: String)
    case connectionLost(operation: String)
    case transport(String)
    case protocolError(String)
}

enum SMBErrorMapper {
    static func map(status: UInt32, operation: String) -> SMBError {
        switch status {
        case SMB2Status.objectNameNotFound, SMB2Status.objectPathNotFound:
            .notFound(status: status, operation: operation)
        case SMB2Status.accessDenied:
            .accessDenied(status: status, operation: operation)
        case SMB2Status.sharingViolation:
            .sharingViolation(status: status, operation: operation)
        case SMB2Status.objectNameCollision:
            .nameCollision(status: status, operation: operation)
        case SMB2Status.directoryNotEmpty:
            .directoryNotEmpty(status: status, operation: operation)
        case SMB2Status.fileIsADirectory:
            .fileIsADirectory(status: status, operation: operation)
        case SMB2Status.notADirectory:
            .notADirectory(status: status, operation: operation)
        case SMB2Status.diskFull:
            .diskFull(status: status, operation: operation)
        case SMB2Status.networkNameDeleted:
            .networkNameDeleted(status: status, operation: operation)
        case SMB2Status.logonFailure:
            .logonFailure(status: status, operation: operation)
        case SMB2Status.objectNameInvalid:
            .objectNameInvalid(status: status, operation: operation)
        case SMB2Status.endOfFile:
            .endOfFile(status: status, operation: operation)
        default:
            .unsupported(status: status, operation: operation)
        }
    }

    static func throwIfFailure(status: UInt32, operation: String) throws {
        guard status == SMB2Status.success else {
            throw map(status: status, operation: operation)
        }
    }
}
