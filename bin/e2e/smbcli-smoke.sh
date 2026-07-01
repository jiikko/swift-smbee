#!/usr/bin/env bash
unset CDPATH
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

SMBCLI="${SMBCLI:-.build/debug/smbcli}"
SMBEE_E2E_HOST="${SMBEE_E2E_HOST:-127.0.0.1}"
SMBEE_E2E_PORT="${SMBEE_E2E_PORT:-445}"
SMBEE_E2E_USERNAME="${SMBEE_E2E_USERNAME:-smbee}"
SMBEE_E2E_PASSWORD="${SMBEE_E2E_PASSWORD:-${SMB_PASSWORD:-smbee}}"
SMBEE_E2E_SHARE="${SMBEE_E2E_SHARE:-public}"
SMBEE_E2E_SMOKE_ROOT="${SMBEE_E2E_SMOKE_ROOT:-smbee-cli-smoke-$$}"

SMB_URL="smb://${SMBEE_E2E_USERNAME}@${SMBEE_E2E_HOST}:${SMBEE_E2E_PORT}/${SMBEE_E2E_SHARE}"
SMB_SERVER_URL="smb://${SMBEE_E2E_USERNAME}@${SMBEE_E2E_HOST}:${SMBEE_E2E_PORT}"
local_dir="$(mktemp -d)"

cleanup() {
  SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" rm -r "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}" >/dev/null 2>&1 || true
  rm -rf "${local_dir}"
}
trap cleanup EXIT

mkdir -p "${local_dir}/dir/child"
printf "hello smbee command smoke\n" > "${local_dir}/file.txt"
printf "nested payload\n" > "${local_dir}/dir/child/nested.txt"

SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" ls "${SMB_URL}"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" shares "${SMB_SERVER_URL}" | grep -Fx "${SMBEE_E2E_SHARE}"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" mkdir "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" put "${local_dir}/file.txt" "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/file.txt"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" stat "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/file.txt" | grep -Fx "size: 26"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" cat "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/file.txt" | cmp "${local_dir}/file.txt" -
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" cat --range 6-10 "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/file.txt" | cmp <(printf "smbee") -
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" get "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/file.txt" "${local_dir}/downloaded.txt"
cmp "${local_dir}/file.txt" "${local_dir}/downloaded.txt"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" cp "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/file.txt" "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/copied.txt"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" cat "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/copied.txt" | cmp "${local_dir}/file.txt" -
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" mv "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/copied.txt" "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/moved.txt"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" cat "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/moved.txt" | cmp "${local_dir}/file.txt" -
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" rm "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/moved.txt"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" mkdir "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/empty-dir"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" rm --directory "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/empty-dir"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" put -r "${local_dir}/dir" "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/uploaded-dir"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" ls "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/uploaded-dir/child"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" get -r "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/uploaded-dir" "${local_dir}/downloaded-dir"
cmp "${local_dir}/dir/child/nested.txt" "${local_dir}/downloaded-dir/child/nested.txt"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" cp -r "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/uploaded-dir" "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/copied-dir"
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" cat "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}/copied-dir/child/nested.txt" | cmp "${local_dir}/dir/child/nested.txt" -
SMB_PASSWORD="${SMBEE_E2E_PASSWORD}" "${SMBCLI}" rm -r "${SMB_URL}/${SMBEE_E2E_SMOKE_ROOT}"
