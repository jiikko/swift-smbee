# smbcli exit codes

| Code | Meaning | SMBError mapping |
| ---: | --- | --- |
| 0 | Success | Command completed successfully |
| 1 | Other failure | `sharingViolation`, `nameCollision`, `directoryNotEmpty`, `fileIsADirectory`, `notADirectory`, `diskFull`, `objectNameInvalid`, `endOfFile`, `unsupported`, `protocolError`, and uncategorized non-usage errors |
| 2 | Usage or arguments | ArgumentParser validation and parse failures, including `ValidationError` |
| 3 | Authentication or authorization | `logonFailure`, `accessDenied` |
| 4 | Not found | `notFound` |
| 5 | Connection or transport | `connectionLost`, `transport`, `networkNameDeleted` |

ⓥ `networkNameDeleted` is classified as connection/transport because SMB servers commonly return it when a tree connection or network share disappears mid-operation.
