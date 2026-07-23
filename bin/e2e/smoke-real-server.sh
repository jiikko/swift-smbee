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
  SMBEE_SMOKE_REPORT  Optional Markdown report output path
  SMBEE_SMOKE_SERVER  Server product/configuration description for the report
  SMBEE_SMOKE_VERSION Server OS/firmware/version for the report
  SMBEE_SMOKE_AUTH    Auth mode description for the report
  SMBEE_SMOKE_NOTES   Additional compatibility notes for the report
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
SMBEE_SMOKE_REPORT="${SMBEE_SMOKE_REPORT:-}"
SMBEE_SMOKE_SERVER="${SMBEE_SMOKE_SERVER:-not recorded}"
SMBEE_SMOKE_VERSION="${SMBEE_SMOKE_VERSION:-not recorded}"
SMBEE_SMOKE_AUTH="${SMBEE_SMOKE_AUTH:-not recorded}"
SMBEE_SMOKE_NOTES="${SMBEE_SMOKE_NOTES:-}"
smoke_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
smoke_step="initialization"
probe_json=""

if [[ ! -x "${SMBCLI}" ]]; then
  echo "smbcli not found or not executable: ${SMBCLI}" >&2
  echo "Run: swift build --product smbcli" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
watch_pid=""
markdown_value() {
  local value="$1"
  value="${value//$'\n'/ }"
  value="${value//|/\\|}"
  printf '%s' "${value}"
}

write_report() {
  local exit_code="$1"
  if [[ -z "${SMBEE_SMOKE_REPORT}" ]]; then
    return
  fi

  local result="failed"
  if [[ "${exit_code}" -eq 0 ]]; then
    result="passed"
  fi
  {
    echo "# SMBee real-server smoke report"
    echo
    echo "| Field | Value |"
    echo "|---|---|"
    printf '| Result | %s |\n' "${result}"
    printf '| Exit code | %s |\n' "${exit_code}"
    printf '| Last step | %s |\n' "$(markdown_value "${smoke_step}")"
    printf '| Started (UTC) | %s |\n' "${smoke_started_at}"
    printf '| Finished (UTC) | %s |\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '| Client | %s |\n' "$(markdown_value "$(uname -srm)")"
    printf '| Target | %s |\n' "$(markdown_value "${TARGET}")"
    printf '| Server | %s |\n' "$(markdown_value "${SMBEE_SMOKE_SERVER}")"
    printf '| Server version | %s |\n' "$(markdown_value "${SMBEE_SMOKE_VERSION}")"
    printf '| Auth | %s |\n' "$(markdown_value "${SMBEE_SMOKE_AUTH}")"
    printf '| Notes | %s |\n' "$(markdown_value "${SMBEE_SMOKE_NOTES}")"
    echo
    echo "## Probe"
    echo
    echo '```json'
    if [[ -n "${probe_json}" ]]; then
      printf '%s\n' "${probe_json}"
    else
      echo '{}'
    fi
    echo '```'
    echo
    echo "Commands: probe, shares, mkdir, put, ls, stat, cat, get, df, acl,"
    echo "ping, lock, watch, cp, mv, rm."
  } > "${SMBEE_SMOKE_REPORT}"
}

cleanup() {
  local exit_code="$?"
  if [[ -n "${watch_pid}" ]]; then
    kill "${watch_pid}" >/dev/null 2>&1 || true
    wait "${watch_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${tmpdir}"
  "${SMBCLI}" rm -r "${TARGET}/${SMBEE_SMOKE_ROOT}" >/dev/null 2>&1 || true
  write_report "${exit_code}"
}
trap cleanup EXIT

printf 'hello from SMBee real-server smoke\n' > "${tmpdir}/upload.txt"

smoke_step="probe"
echo "== probe"
probe_json="$("${SMBCLI}" probe --json "${SERVER_TARGET}")"
printf '%s\n' "${probe_json}"

smoke_step="shares"
echo "== shares"
"${SMBCLI}" shares "${SERVER_TARGET}"

smoke_step="mkdir / put / ls"
echo "== mkdir / put / ls"
"${SMBCLI}" mkdir "${TARGET}/${SMBEE_SMOKE_ROOT}"
"${SMBCLI}" put "${tmpdir}/upload.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"
"${SMBCLI}" ls "${TARGET}/${SMBEE_SMOKE_ROOT}"

smoke_step="stat / cat / get"
echo "== stat / cat / get"
"${SMBCLI}" stat "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"
"${SMBCLI}" cat "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" > "${tmpdir}/cat.txt"
"${SMBCLI}" get "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" "${tmpdir}/download.txt"
cmp "${tmpdir}/upload.txt" "${tmpdir}/cat.txt"
cmp "${tmpdir}/upload.txt" "${tmpdir}/download.txt"

smoke_step="df / acl"
echo "== df / acl"
"${SMBCLI}" df "${TARGET}" >/dev/null
"${SMBCLI}" acl "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" >/dev/null

smoke_step="ping / lock"
echo "== ping / lock"
"${SMBCLI}" ping "${TARGET}"
"${SMBCLI}" lock \
  --offset 0 \
  --length 1 \
  "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"

smoke_step="watch"
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

smoke_step="cp / mv / rm"
echo "== cp / mv / rm"
"${SMBCLI}" cp "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/copied.txt"
"${SMBCLI}" mv "${TARGET}/${SMBEE_SMOKE_ROOT}/copied.txt" "${TARGET}/${SMBEE_SMOKE_ROOT}/renamed.txt"
"${SMBCLI}" rm "${TARGET}/${SMBEE_SMOKE_ROOT}/upload.txt"
"${SMBCLI}" rm "${TARGET}/${SMBEE_SMOKE_ROOT}/watched.txt"
"${SMBCLI}" rm "${TARGET}/${SMBEE_SMOKE_ROOT}/renamed.txt"
"${SMBCLI}" rm -r "${TARGET}/${SMBEE_SMOKE_ROOT}"

smoke_step="complete"
echo "real-server smoke passed: ${TARGET}"
