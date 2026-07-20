# ``SMBee``

A Swift SMB 3.x client library for file operations, persistent sessions, and
command-line workflows on macOS and Linux.

## Overview

Use the high-level ``SMBee`` facade for one-shot operations. Use
``SMBClientSession`` when several operations should reuse one authenticated
session, and ``SMBClientSession/withTree(share:operation:)`` when that session
must access more than one share.

Authenticated operations support SMB 3.0, 3.0.2, and 3.1.1. Kerberos, durable
handles, SMB1, and the optional protocol features listed in the project README
are not currently supported.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:SessionsAndTrees>
- <doc:ErrorsAndCancellation>

### Main API

- ``SMBCredential``
- ``SMBClientSession``
- ``SMBClientTreeSession``
- ``SMBError``
- ``SMBTransportError``
- ``SMBCodecError``
