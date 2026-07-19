#!/usr/bin/env bash
set -euxo pipefail

SAMBA_CONTAINER="${SAMBA_CONTAINER:-smbee-samba}"
SAMBA_BASE_IMAGE="${SAMBA_BASE_IMAGE:-ubuntu:24.04}"
SAMBA_CONFIG="${SAMBA_CONFIG:-test/e2e/smb.conf}"
SMBEE_E2E_HOST="${SMBEE_E2E_HOST:-127.0.0.1}"
SMBEE_E2E_PORT="${SMBEE_E2E_PORT:-445}"

if [[ ! -f "${SAMBA_CONFIG}" ]]; then
  echo "Samba config not found: ${SAMBA_CONFIG}" >&2
  exit 1
fi

# Make reruns on the same runner idempotent. GitHub-hosted runners are normally
# fresh, but local reproduction and self-hosted runners benefit from cleanup.
docker rm -f "${SAMBA_CONTAINER}" >/dev/null 2>&1 || true

docker run -d --name "${SAMBA_CONTAINER}" -p "${SMBEE_E2E_PORT}:445" \
  -v "${PWD}/${SAMBA_CONFIG}:/tmp/smbee-smb.conf:ro" \
  "${SAMBA_BASE_IMAGE}" \
  bash -lc '
    set -euxo pipefail
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba
    # smb.conf を /etc/samba にbind-mountすると samba-common の postinst が
    # read-only ファイルに書けず失敗するため、install 後に書き込み可能な場所へ cp する。
    cp /tmp/smbee-smb.conf /etc/samba/smb.conf
    mkdir -p /srv/smbee/public
    mkdir -p /srv/smbee/dfsroot
    useradd -M -s /usr/sbin/nologin smbee
    printf "smbee\nsmbee\n" | smbpasswd -a -s smbee
    printf "hello from SMBee E2E\n" > /srv/smbee/public/known.txt
    # Samba msdfs links are symlinks whose target uses the msdfs: prefix.
    ln -s "msdfs:127.0.0.1\\public" /srv/smbee/dfsroot/public-link
    # Keep the boundary-range smoke fixture sparse; SMBee never uploads 4GiB.
    truncate -s 4295032833 /srv/smbee/public/large-4gib-plus.bin
    chown -R smbee:smbee /srv/smbee
    smbd --version
    testparm -s
    exec smbd --foreground --no-process-group --debug-stdout --debuglevel=3
  '

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
