# smbcli JSON output

`smbcli` keeps stdout machine-readable when `--json` is supported. Diagnostics,
progress, and errors remain on stderr unless a command documents otherwise.

Commands with stable JSON output:

- `probe --json`
- `ls --json`
- `shares --json`
- `stat --json`
- `readlink --json`
- `df --json`
- `acl --json`
- `dfs --json`
- `watch --json`

`watch --json` prints newline-delimited JSON. Each line is either a `changes`
event with file change entries or an `overflow` event with `rescanRequired`.

Mutating commands currently do not have success JSON output:

- `mkdir`
- `put`
- `get`
- `cp`
- `mv`
- `rm`
- `setacl`

These commands use process exit status as the stable success/failure signal.
Future JSON support for mutating commands should use explicit success objects
rather than parsing human stdout.
