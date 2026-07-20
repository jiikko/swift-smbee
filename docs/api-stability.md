# API stability policy

SMBee is currently a pre-1.0 SwiftPM package (`0.0.1`). Consumers are expected to
build it from source together with their application.

## Current guarantees

- Ordinary named public API calls receive best-effort source compatibility within
  the pre-1.0 series.
- Existing nonescaping `SMBCredentialProvider` forwarding calls are covered by a
  compile regression test. Deadline-enabled provider overloads require an explicit
  `operationTimeout` argument so the legacy overload remains selectable.
- Error and timeout behavior documented in the public API is treated as a source
  contract and changes should be called out in release notes.

## Not currently guaranteed

- ABI or module stability for previously compiled clients.
- Compatibility of references to overloaded methods as function values when a
  public signature gains parameters.
- A stable binary framework or other binary release artifact.

Consumers should rebuild after updating the package and use an exact version or
revision when they need a frozen pre-1.0 API. Stronger SemVer and binary artifact
guarantees must be defined before a 1.0 release.
