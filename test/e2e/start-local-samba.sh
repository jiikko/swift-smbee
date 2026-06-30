#!/usr/bin/env bash
unset CDPATH
set -euo pipefail

# Manual local E2E helper. CI starts Samba directly in .github/workflows/e2e.yml
# and must not depend on this script.
#
# Requires Docker with permission to run Linux containers. On hosts where Docker
# is unavailable or the daemon is not running, this script exits with a clear
# message instead of attempting host-specific Samba setup.
#
# Usage:
#   test/e2e/start-local-samba.sh [port]
#   SMBEE_E2E_PORT=1445 test/e2e/start-local-samba.sh
#
# Then run tests from the repository root:
#   export SMBEE_E2E=1
#   export SMBEE_E2E_HOST=127.0.0.1
#   export SMBEE_E2E_PORT=1445
#   export SMBEE_E2E_USERNAME=smbee
#   export SMBEE_E2E_PASSWORD=smbee
#   export SMBEE_E2E_SHARE=public
#   swift test --filter SMBeeE2ETests
#
# Optional >4GiB read-stream test preparation:
#   docker exec smbee-samba-local truncate -s 4294967297 /srv/smbee/public/large-4gib-plus.bin
#   export SMBEE_E2E_LARGE=1
#   export SMBEE_E2E_LARGE_PATH=large-4gib-plus.bin
#   swift test --filter SMBeeE2ETests/testReadStreamCountsFileLargerThan4GiB

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SMB_CONF="${REPO_ROOT}/${SMBEE_E2E_SAMBA_CONFIG:-test/e2e/smb/smb302-encrypted-required.conf}"

PORT="${1:-${SMBEE_E2E_PORT:-1445}}"
CONTAINER_NAME="${SMBEE_E2E_CONTAINER_NAME:-smbee-samba-local}"

if ! command -v docker >/dev/null 2>&1; then
  printf 'Docker is required for %s, but docker was not found in PATH.\n' "$0" >&2
  printf 'Install/start Docker, or use another Samba server and set SMBEE_E2E_* manually.\n' >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  printf 'Docker is installed, but the Docker daemon is not reachable.\n' >&2
  printf 'Start Docker, or use another Samba server and set SMBEE_E2E_* manually.\n' >&2
  exit 1
fi

if ! [[ "${PORT}" =~ ^[0-9]+$ ]] || [ "${PORT}" -lt 1 ] || [ "${PORT}" -gt 65535 ]; then
  printf 'SMBEE_E2E_PORT/port argument must be a TCP port from 1 to 65535; got %s\n' "${PORT}" >&2
  exit 1
fi

if [ ! -f "${SMB_CONF}" ]; then
  printf 'Missing Samba config: %s\n' "${SMB_CONF}" >&2
  exit 1
fi

if docker ps -a --format '{{.Names}}' | grep -Fxq "${CONTAINER_NAME}"; then
  printf 'Removing existing container %s\n' "${CONTAINER_NAME}"
  docker rm -f "${CONTAINER_NAME}" >/dev/null
fi

printf 'Starting Samba container %s on 127.0.0.1:%s -> container:445\n' "${CONTAINER_NAME}" "${PORT}"
docker run -d --name "${CONTAINER_NAME}" -p "127.0.0.1:${PORT}:445" \
  -v "${SMB_CONF}:/tmp/smbee-smb.conf:ro" \
  ubuntu:24.04 \
  bash -lc '
    set -euo pipefail
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba
    # smb.conf is copied after package install because samba-common postinst may
    # need to write /etc/samba/smb.conf.
    cp /tmp/smbee-smb.conf /etc/samba/smb.conf
    mkdir -p /srv/smbee/public
    useradd -M -s /usr/sbin/nologin smbee
    printf "%s\n%s\n" "smbee" "smbee" | smbpasswd -a -s smbee >/dev/null
    printf "hello from SMBee E2E\n" > /srv/smbee/public/known.txt
    chown -R smbee:smbee /srv/smbee
    testparm -s
    exec smbd --foreground --no-process-group --debug-stdout --debuglevel=3
  ' >/dev/null

printf 'Waiting for SMB port %s' "${PORT}"
for _ in $(seq 1 120); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
    printf '\nSamba is ready.\n'
    printf 'Export these variables before running E2E tests:\n'
    printf '  export SMBEE_E2E=1\n'
    printf '  export SMBEE_E2E_HOST=127.0.0.1\n'
    printf '  export SMBEE_E2E_PORT=%s\n' "${PORT}"
    printf '  export SMBEE_E2E_USERNAME=smbee\n'
    printf '  export SMBEE_E2E_PASSWORD=smbee\n'
    printf '  export SMBEE_E2E_SHARE=public\n'
    printf 'For >4GiB read-stream coverage, create large-4gib-plus.bin as described in this script and set SMBEE_E2E_LARGE=1.\n'
    exit 0
  fi
  printf '.'
  sleep 1
done

printf '\nSamba did not become ready on 127.0.0.1:%s. Recent container logs:\n' "${PORT}" >&2
docker logs --tail 80 "${CONTAINER_NAME}" >&2 || true
exit 1
