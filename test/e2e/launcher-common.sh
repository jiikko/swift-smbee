# shellcheck shell=bash
# Host-side helpers shared by the two Samba launchers (issue 087):
#   bin/e2e/container-samba.sh  (Apple container / macOS local)
#   test/e2e/start-samba-ci.sh  (docker / CI)
# Sourced, not executed. Only the parts both launchers implement identically live
# here; the readiness predicate, teardown lifecycle and container start command stay
# in each launcher because they depend on the runtime (see issue 087 "runtime 固有").
# Regression tests: bin/ci/test-e2e-launchers.

# smbee_e2e_resolve_samba_config <repo_root> <samba_config>
# Sets SAMBA_CONFIG_PATH to the absolute host path to bind-mount. The existence check
# resolves a relative path from ${PWD}, so callers must `cd` to the repo root first.
# shellcheck disable=SC2034  # SAMBA_CONFIG_PATH is this function's output.
smbee_e2e_resolve_samba_config() {
  local repo_root="$1"
  local samba_config="$2"
  if [[ ! -f "${samba_config}" ]]; then
    printf 'Missing Samba config: %s\n' "${samba_config}" >&2
    return 1
  fi
  # An absolute SAMBA_CONFIG must not get REPO_ROOT prefixed onto it.
  case "${samba_config}" in
    /*) SAMBA_CONFIG_PATH="${samba_config}" ;;
    *)  SAMBA_CONFIG_PATH="${repo_root}/${samba_config}" ;;
  esac
}

# smbee_e2e_load_container_init <repo_root>
# Sets CONTAINER_INIT to the body of test/e2e/container-init.sh (passed to `bash -lc`).
smbee_e2e_load_container_init() {
  local init_path="$1/test/e2e/container-init.sh"
  if [[ ! -f "${init_path}" || ! -r "${init_path}" ]]; then
    printf 'Container init payload is missing or unreadable: %s\n' "${init_path}" >&2
    return 1
  fi
  if ! CONTAINER_INIT="$(<"${init_path}")"; then
    printf 'Failed to read container init payload: %s\n' "${init_path}" >&2
    return 1
  fi
  if [[ -z "${CONTAINER_INIT}" ]]; then
    printf 'Container init payload is empty: %s\n' "${init_path}" >&2
    return 1
  fi
  # Threat model: catch an empty / truncated / stale fragment (a container that starts
  # and exits silently is the expensive failure). This does NOT defend against a
  # deliberately crafted payload — anyone who can edit the file can run anything.
  if ! grep -qE '^[[:space:]]*exec smbd' "${init_path}"; then
    printf 'Container init payload must end in an "exec smbd" command: %s\n' "${init_path}" >&2
    return 1
  fi
}

# smbee_e2e_wait_until_ready <predicate> [tick]
# Retry envelope: up to 120 attempts one second apart, then one final check.
# Returns 0 as soon as <predicate> succeeds, 1 on timeout. [tick] runs after each
# failed attempt (progress output). Log dumping on timeout is the caller's job.
smbee_e2e_wait_until_ready() {
  local predicate="$1"
  local tick="${2:-}"
  local _
  for _ in $(seq 1 120); do
    if "${predicate}"; then
      return 0
    fi
    if [[ -n "${tick}" ]]; then
      "${tick}"
    fi
    sleep 1
  done
  "${predicate}"
}
