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
target_authority="${TARGET#smb://}"
if [[ "${target_authority}" == "${TARGET}" || "${target_authority}" != */* ]]; then
  echo "target must be smb://user@host[:port]/share" >&2
  exit 2
fi
SERVER_TARGET="smb://${target_authority%%/*}"
SMBEE_SMOKE_ROOT="${SMBEE_SMOKE_ROOT:-smbee-real-smoke-$(date +%Y%m%d%H%M%S)-$$}"

if [[ ! -x "${SMBCLI}" ]]; then
  echo "smbcli not found or not executable: ${SMBCLI}" >&2
  echo "Run: swift build --product smbcli" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
watch_pid=""
cleanup() {
  if [[ -n "${watch_pid}" ]]; then
    kill "${watch_pid}" >/dev/null 2>&1 || true
    wait "${watch_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${tmpdir}"
  "${SMBCLI}" rm -r "${TARGET}/${SMBEE_SMOKE_ROOT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf 'hello from SMBee real-server smoke\n' > "${tmpdir}/upload.txt"

echo "== probe"
"${SMBCLI}" probe "${SERVER_TARGET}"

echo "== shares"
"${SMBCLI}" shares "${SERVER_TARGET}"

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

echo "== ping / lock"
"${SMBCLI}" ping "${TARGET}"
"${SMBCLI}" lock \
  --offset 0 \
  --length 1 \
  "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"

echo "== watch"
"${SMBCLI}" watch --json "${TARGET}/${SMBEE_SMOKE_ROOT}" > "${tmpdir}/watch.jsonl" &
watch_pid="$!"
# Give CHANGE_NOTIFY time to reach the server before creating the event.
sleep 2
"${SMBCLI}" put "${tmpdir}/upload.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/watched.txt"
watch_observed=false
for _ in {1..40}; do
  if grep -Fq '"name":"watched.txt"' "${tmpdir}/watch.jsonl"; then
    watch_observed=true
    break
  fi
  if ! kill -0 "${watch_pid}" >/dev/null 2>&1; then
    echo "watch exited before observing the change" >&2
    wait "${watch_pid}"
    exit 1
  fi
  sleep 0.25
done
kill "${watch_pid}" >/dev/null 2>&1 || true
wait "${watch_pid}" >/dev/null 2>&1 || true
watch_pid=""
if [[ "${watch_observed}" != true ]]; then
  echo "watch did not report watched.txt within 10 seconds" >&2
  exit 1
fi

echo "== cp / mv / rm"
"${SMBCLI}" cp "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/copied.txt"
"${SMBCLI}" mv "${TARGET}/${SMBEE_SMOKE_ROOT}/copied.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/renamed.txt"
"${SMBCLI}" rm "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"
"${SMBCLI}" rm "${TARGET}/${SMBEE_SMOKE_ROOT}/watched.txt"
"${SMBCLI}" rm "${TARGET}/${SMBEE_SMOKE_ROOT}/renamed.txt"
"${SMBCLI}" rm -r "${TARGET}/${SMBEE_SMOKE_ROOT}"

trap - EXIT
rm -rf "${tmpdir}"
echo "real-server smoke passed: ${TARGET}"
