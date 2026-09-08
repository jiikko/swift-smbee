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

if [[ ! -f "${SAMBA_CONFIG}" ]]; then
  echo "Samba config not found: ${SAMBA_CONFIG}" >&2
  exit 1
fi

# An absolute SAMBA_CONFIG must not get REPO_ROOT prefixed onto it.
case "${SAMBA_CONFIG}" in
  /*) SAMBA_CONFIG_PATH="${SAMBA_CONFIG}" ;;
  *)  SAMBA_CONFIG_PATH="${REPO_ROOT}/${SAMBA_CONFIG}" ;;
esac

CONTAINER_INIT_PATH="${REPO_ROOT}/test/e2e/container-init.sh"
if [[ ! -f "${CONTAINER_INIT_PATH}" || ! -r "${CONTAINER_INIT_PATH}" ]]; then
  printf 'Container init payload is missing or unreadable: %s\n' "${CONTAINER_INIT_PATH}" >&2
  exit 1
fi
if ! CONTAINER_INIT="$(<"${CONTAINER_INIT_PATH}")"; then
  printf 'Failed to read container init payload: %s\n' "${CONTAINER_INIT_PATH}" >&2
  exit 1
fi
if [[ -z "${CONTAINER_INIT}" ]]; then
  printf 'Container init payload is empty: %s\n' "${CONTAINER_INIT_PATH}" >&2
  exit 1
fi
# Threat model: catch an empty / truncated / stale fragment (a container that starts
# and exits silently is the expensive failure). This does NOT defend against a
# deliberately crafted payload — anyone who can edit the file can run anything.
if ! grep -qE '^[[:space:]]*exec smbd' "${CONTAINER_INIT_PATH}"; then
  printf 'Container init payload must end in an "exec smbd" command: %s\n' "${CONTAINER_INIT_PATH}" >&2
  exit 1
fi

# Make reruns on the same runner idempotent. GitHub-hosted runners are normally
# fresh, but local reproduction and self-hosted runners benefit from cleanup.
docker rm -f "${SAMBA_CONTAINER}" >/dev/null 2>&1 || true

docker run -d --name "${SAMBA_CONTAINER}" -p "${SMBEE_E2E_PORT}:445" \
  -v "${SAMBA_CONFIG_PATH}:/tmp/smbee-smb.conf:ro" \
  "${SAMBA_BASE_IMAGE}" \
  bash -lc "${CONTAINER_INIT}"

for _ in $(seq 1 120); do
  if (exec 3<>"/dev/tcp/${SMBEE_E2E_HOST}/${SMBEE_E2E_PORT}") 2>/dev/null; then
    echo "SMB ${SMBEE_E2E_HOST}:${SMBEE_E2E_PORT} open"
    exit 0
  fi
  sleep 1
done

echo "Samba did not become ready on ${SMBEE_E2E_HOST}:${SMBEE_E2E_PORT}" >&2
docker logs "${SAMBA_CONTAINER}" || true
exit 1
