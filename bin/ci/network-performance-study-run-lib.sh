#!/usr/bin/env bash

# Append an arm's JSONL only after its post-measurement boundary guard passes.
append_guarded_sample() {
  local rtt_target="$1" arm_jsonl="$2" samples_jsonl="$3"
  if [ "${rtt_target}" != 0 ]; then
    run_rtt_shaper guard "${rtt_target}" >/dev/null || return $?
  fi
  cat "${arm_jsonl}" >>"${samples_jsonl}"
}
