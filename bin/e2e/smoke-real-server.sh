#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  SMB_PASSWORD=... bin/e2e/smoke-real-server.sh smb://user@host[:port]/share

Runs a representative smbcli smoke against an existing SMB server. The script
creates and deletes a temporary directory under the target share.

Environment:
  SMBCLI              Path to smbcli (default: .build/debug/smbcli)
  SMBEE_SMOKE_ROOT    Remote temp directory name
  SMB_PASSWORD        Password used by smbcli unless URL/other auth is supplied
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -ne 1 ]]; then
  usage
  exit 2
fi

SMBCLI="${SMBCLI:-.build/debug/smbcli}"
TARGET="${1%/}"
SMBEE_SMOKE_ROOT="${SMBEE_SMOKE_ROOT:-smbee-real-smoke-$(date +%Y%m%d%H%M%S)-$$}"

if [[ ! -x "${SMBCLI}" ]]; then
  echo "smbcli not found or not executable: ${SMBCLI}" >&2
  echo "Run: swift build --product smbcli" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
  "${SMBCLI}" rm -r "${TARGET}/${SMBEE_SMOKE_ROOT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf 'hello from SMBee real-server smoke\n' > "${tmpdir}/upload.txt"

echo "== probe"
"${SMBCLI}" probe "${TARGET}"

echo "== shares"
"${SMBCLI}" shares "${TARGET}"

echo "== mkdir / put / ls"
"${SMBCLI}" mkdir "${TARGET}/${SMBEE_SMOKE_ROOT}"
"${SMBCLI}" put "${tmpdir}/upload.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"
"${SMBCLI}" ls "${TARGET}/${SMBEE_SMOKE_ROOT}"

echo "== stat / cat / get"
"${SMBCLI}" stat "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"
"${SMBCLI}" cat "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" > "${tmpdir}/cat.txt"
"${SMBCLI}" get "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" "${tmpdir}/download.txt"
cmp "${tmpdir}/upload.txt" "${tmpdir}/cat.txt"
cmp "${tmpdir}/upload.txt" "${tmpdir}/download.txt"

echo "== df / acl"
"${SMBCLI}" df "${TARGET}" >/dev/null
"${SMBCLI}" acl "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" >/dev/null

echo "== cp / mv / rm"
"${SMBCLI}" cp "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/copied.txt"
"${SMBCLI}" mv "${TARGET}/${SMBEE_SMOKE_ROOT}/copied.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/renamed.txt"
"${SMBCLI}" rm "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"
"${SMBCLI}" rm "${TARGET}/${SMBEE_SMOKE_ROOT}/renamed.txt"
"${SMBCLI}" rm -r "${TARGET}/${SMBEE_SMOKE_ROOT}"

trap - EXIT
rm -rf "${tmpdir}"
echo "real-server smoke passed: ${TARGET}"
