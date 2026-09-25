#!/usr/bin/env bash
unset CDPATH
set -euxo pipefail

# Resolve paths from the script location, not from ${PWD}: the container init body
# and the Samba config both live in the repo, and every caller used to have to be
# standing in the repo root. BASH_SOURCE is not symlink-resolved, so invoking this
# script through a symlink or process substitution derives the wrong REPO_ROOT — that
# fails loudly on the config/init existence checks below rather than starting a wrong
# container, so it is left unsupported instead of carrying symlink-resolution code.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

SAMBA_CONTAINER="${SAMBA_CONTAINER:-smbee-samba}"
SAMBA_BASE_IMAGE="${SAMBA_BASE_IMAGE:-ubuntu:24.04}"
SAMBA_CONFIG="${SAMBA_CONFIG:-test/e2e/smb.conf}"
SMBEE_E2E_HOST="${SMBEE_E2E_HOST:-127.0.0.1}"
SMBEE_E2E_PORT="${SMBEE_E2E_PORT:-445}"

# shellcheck source=test/e2e/launcher-common.sh
source "${SCRIPT_DIR}/launcher-common.sh"
smbee_e2e_resolve_samba_config "${REPO_ROOT}" "${SAMBA_CONFIG}" || exit 1
smbee_e2e_load_container_init "${REPO_ROOT}" || exit 1

# Make reruns on the same runner idempotent. GitHub-hosted runners are normally
# fresh, but local reproduction and self-hosted runners benefit from cleanup.
docker rm -f "${SAMBA_CONTAINER}" >/dev/null 2>&1 || true

docker run -d --name "${SAMBA_CONTAINER}" -p "${SMBEE_E2E_PORT}:445" \
  -v "${SAMBA_CONFIG_PATH}:/tmp/smbee-smb.conf:ro" \
  "${SAMBA_BASE_IMAGE}" \
  bash -lc "${CONTAINER_INIT}"

# shellcheck disable=SC2329  # invoked indirectly by smbee_e2e_wait_until_ready.
samba_port_open() {
  (exec 3<>"/dev/tcp/${SMBEE_E2E_HOST}/${SMBEE_E2E_PORT}") 2>/dev/null
}

if smbee_e2e_wait_until_ready samba_port_open; then
  echo "SMB ${SMBEE_E2E_HOST}:${SMBEE_E2E_PORT} open"
  exit 0
fi

echo "Samba did not become ready on ${SMBEE_E2E_HOST}:${SMBEE_E2E_PORT}" >&2
docker logs "${SAMBA_CONTAINER}" || true
exit 1
