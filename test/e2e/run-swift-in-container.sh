#!/usr/bin/env bash
# Run a command inside the official swift image with --network host so it reaches
# the Samba container started by start-samba-ci.sh on 127.0.0.1:445.
#
# This is the shared body for every CI E2E job (e2e.yml e2e-api / e2e-cli,
# samba-compat.yml). It replaces swift-actions/setup-swift@v3, whose Swiftly
# install currently fails GPG verification ("Can't check signature: No public
# key"). Keep the container invocation in one place so the workflows stay thin.
#
# Env:
#   SWIFT_VERSION            required — swift image tag (e.g. "6.2")
#   SMBEE_E2E_HOST/PORT      forwarded to the container (default 127.0.0.1/445)
#   SMBEE_E2E_PROFILE        forwarded (probe/profile assertions)
#   DOCKER_RUN_ENV           optional — space-separated extra `-e NAME` names to
#                            forward (e.g. "SMB_PASSWORD SMBEE_E2E_SMOKE_ROOT")
# Args: the command to run inside the container (bash -c body).
set -euxo pipefail

: "${SWIFT_VERSION:?SWIFT_VERSION is required}"
SMBEE_E2E_HOST="${SMBEE_E2E_HOST:-127.0.0.1}"
SMBEE_E2E_PORT="${SMBEE_E2E_PORT:-445}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <command-run-in-container>" >&2
  exit 2
fi

extra_env_args=()
for name in ${DOCKER_RUN_ENV:-}; do
  extra_env_args+=(-e "${name}")
done

docker run --rm --network host \
  -e SMBEE_E2E_HOST -e SMBEE_E2E_PORT -e SMBEE_E2E_PROFILE \
  "${extra_env_args[@]}" \
  -v "${PWD}:/work" -w /work \
  "swift:${SWIFT_VERSION}" \
  bash -euxo pipefail -c "swift --version
$1"
