# 063: Deprecate direct `SMBCredential.password` access before 1.0

## Problem

`SMBCredential` must retain password material until authentication completes, but its
mutable public `password` property lets consumers read and replace that material. This
widens the accidental API surface and makes secret lifetime harder to reason about.

Removing or restricting the property immediately would break pre-1.0 source users.

## Migration plan

1. Keep `SMBCredential(username:password:domain:)` and credential-provider APIs as the
   supported ways to supply a password during the 0.1 series.
2. Add a replacement credential representation whose secret storage is not publicly
   readable. It must continue to support password, NT hash, and anonymous credentials
   without exposing plaintext through reflection-oriented descriptions or debug output.
3. Deprecate direct reads and writes of `SMBCredential.password` only after that
   replacement ships, with a compiler message naming the migration API.
4. Remove the public property at 1.0 at the earliest. Keep initializer/provider source
   migration documented in release notes.
5. Retain the regression that an authenticated session releases its credential material
   after setup, and keep debug/wire output redaction tests green.

## Compatibility decision

The property is frozen for 0.1 source compatibility but is not part of the intended 1.0
surface. A deprecation attribute without a usable replacement is explicitly disallowed.
