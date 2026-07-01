#!/usr/bin/env bash
unset CDPATH
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CONTAINER_NAME="${SMBEE_E2E_CONTAINER_NAME:-smbee-samba-container-e2e}"
SAMBA_BASE_IMAGE="${SAMBA_BASE_IMAGE:-ubuntu:24.04}"
SAMBA_CONFIG="${SAMBA_CONFIG:-test/e2e/smb/smb302-encrypted-required.conf}"
SMBEE_E2E_HOST="${SMBEE_E2E_HOST:-127.0.0.1}"
SMBEE_E2E_PORT="${SMBEE_E2E_PORT:-1445}"
SMBEE_E2E_PROFILE="${SMBEE_E2E_PROFILE:-smb302-encrypted-required}"
SMBEE_E2E_USERNAME="${SMBEE_E2E_USERNAME:-smbee}"
SMBEE_E2E_PASSWORD="${SMBEE_E2E_PASSWORD:-smbee}"
SMBEE_E2E_SHARE="${SMBEE_E2E_SHARE:-public}"
SMBEE_E2E_KEEP_CONTAINER="${SMBEE_E2E_KEEP_CONTAINER:-0}"

cd "${REPO_ROOT}"

if ! command -v container >/dev/null 2>&1; then
  printf 'Apple container CLI is required but was not found in PATH.\n' >&2
  printf 'Install it with: brew install container\n' >&2
  exit 1
fi

if ! [[ "${SMBEE_E2E_PORT}" =~ ^[0-9]+$ ]] || [ "${SMBEE_E2E_PORT}" -lt 1 ] || [ "${SMBEE_E2E_PORT}" -gt 65535 ]; then
  printf 'SMBEE_E2E_PORT must be a TCP port from 1 to 65535; got %s\n' "${SMBEE_E2E_PORT}" >&2
  exit 1
fi

if [ ! -f "${SAMBA_CONFIG}" ]; then
  printf 'Missing Samba config: %s\n' "${SAMBA_CONFIG}" >&2
  exit 1
fi

if ! container system status >/dev/null 2>&1; then
  printf 'Starting Apple container system service...\n'
  if ! container system start; then
    printf 'container system start failed. Complete container first-run setup, then retry.\n' >&2
    exit 1
  fi
fi

cleanup() {
  if [ "${SMBEE_E2E_KEEP_CONTAINER}" = "1" ]; then
    printf 'Keeping container %s because SMBEE_E2E_KEEP_CONTAINER=1\n' "${CONTAINER_NAME}"
    return
  fi
  container rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

container rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

printf 'Starting Samba container %s on %s:%s -> container:445\n' "${CONTAINER_NAME}" "${SMBEE_E2E_HOST}" "${SMBEE_E2E_PORT}"
container run -d --name "${CONTAINER_NAME}" -p "${SMBEE_E2E_HOST}:${SMBEE_E2E_PORT}:445" \
  -v "${REPO_ROOT}/${SAMBA_CONFIG}:/tmp/smbee-smb.conf:ro" \
  "${SAMBA_BASE_IMAGE}" \
  bash -lc '
    set -euxo pipefail
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba
    cp /tmp/smbee-smb.conf /etc/samba/smb.conf
    mkdir -p /srv/smbee/public
    useradd -M -s /usr/sbin/nologin smbee
    printf "smbee\nsmbee\n" | smbpasswd -a -s smbee
    printf "hello from SMBee E2E\n" > /srv/smbee/public/known.txt
    chown -R smbee:smbee /srv/smbee
    smbd --version
    testparm -s
    exec smbd --foreground --no-process-group --debug-stdout --debuglevel=3
  ' >/dev/null

printf 'Waiting for SMB port %s:%s' "${SMBEE_E2E_HOST}" "${SMBEE_E2E_PORT}"
for _ in $(seq 1 120); do
  if nc -z "${SMBEE_E2E_HOST}" "${SMBEE_E2E_PORT}" >/dev/null 2>&1 &&
      container logs "${CONTAINER_NAME}" 2>/dev/null | grep -q 'waiting for connections'; then
    printf '\nSamba is ready.\n'
    break
  fi
  printf '.'
  sleep 1
done

if ! nc -z "${SMBEE_E2E_HOST}" "${SMBEE_E2E_PORT}" >/dev/null 2>&1 ||
    ! container logs "${CONTAINER_NAME}" 2>/dev/null | grep -q 'waiting for connections'; then
  printf '\nSamba did not become ready. Recent logs:\n' >&2
  container logs "${CONTAINER_NAME}" 2>/dev/null | tail -n 120 >&2 || true
  exit 1
fi

export SMBEE_E2E=1
export SMBEE_E2E_HOST
export SMBEE_E2E_PORT
export SMBEE_E2E_PROFILE
export SMBEE_E2E_USERNAME
export SMBEE_E2E_PASSWORD
export SMBEE_E2E_SHARE

printf '\n== Probe negotiated parameters ==\n'
SMBEE_DEBUG=1 swift run smbcli probe "smb://${SMBEE_E2E_HOST}:${SMBEE_E2E_PORT}"

printf '\n== Samba-backed API E2E tests ==\n'
SMBEE_DEBUG=1 swift test --filter SMBeeE2ETests

printf '\n== Build smbcli ==\n'
swift build --product smbcli

printf '\n== smbcli command smoke ==\n'
SMBEE_E2E_SMOKE_ROOT="smbee-local-container-cli-$$" bin/e2e/smbcli-smoke.sh

printf '\nLocal container E2E completed successfully.\n'
