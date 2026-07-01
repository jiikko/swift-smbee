#!/usr/bin/env bash
set -euo pipefail

MIN_LINE_COVERAGE="${MIN_LINE_COVERAGE:-50}"
MIN_FUNCTION_COVERAGE="${MIN_FUNCTION_COVERAGE:-0}"
COVERAGE_JSON="${COVERAGE_JSON:-.build/code-coverage.json}"
COVERAGE_REPORT="${COVERAGE_REPORT:-.build/code-coverage-report.txt}"
COVERAGE_MD="${COVERAGE_MD:-.build/code-coverage.md}"
IGNORE_FILENAME_REGEX="${IGNORE_FILENAME_REGEX:-(/Tests/|/.build/)}"
LLVM_COV="${LLVM_COV:-llvm-cov}"

if ! command -v "$LLVM_COV" >/dev/null 2>&1; then
  swift_bin=$(command -v swift)
  toolchain_llvm_cov="$(dirname "$swift_bin")/llvm-cov"
  if [[ -x "$toolchain_llvm_cov" ]]; then
    LLVM_COV="$toolchain_llvm_cov"
  else
    echo "CODE_COVERAGE_ERROR llvm-cov not found in PATH or Swift toolchain" >&2
    exit 1
  fi
fi

mkdir -p "$(dirname "$COVERAGE_JSON")"

# Keep E2E/Samba-backed tests in their dedicated workflows. Coverage should measure
# deterministic unit/vector coverage for the package code.
echo "CODE_COVERAGE_INFO command=swift test --enable-code-coverage --skip SMBeeE2ETests"
swift test --enable-code-coverage --skip SMBeeE2ETests

profdata=""
# NOTE: `swift test --show-codecov-path` on recent SwiftPM prints the path to the exported
# coverage JSON (e.g. .build/.../codecov/<Package>.json), NOT the llvm `default.profdata`.
# Passing that JSON to `llvm-cov -instr-profile` fails with "invalid instrumentation profile
# data (bad magic)". Only trust the reported path when it is actually a *.profdata file;
# otherwise fall back to locating default.profdata directly.
if codecov_path=$(swift test --show-codecov-path 2>/dev/null | tail -n 1 | tr -d '[:space:]'); then
  if [[ -n "$codecov_path" && "$codecov_path" == *.profdata && -f "$codecov_path" ]]; then
    profdata="$codecov_path"
  fi
fi

if [[ -z "$profdata" ]]; then
  profdata=$(find .build -path '*codecov*default.profdata' -type f | sort | tail -n 1 || true)
fi

if [[ -z "$profdata" || ! -f "$profdata" ]]; then
  echo "CODE_COVERAGE_ERROR coverage profdata not found" >&2
  exit 1
fi

# Linux SwiftPM usually emits an executable file ending in .xctest. macOS emits an
# .xctest bundle with Contents/MacOS/<binary>. Keep both paths for local reuse.
test_binary=$(find .build -type f -name '*PackageTests.xctest' -perm -111 | sort | tail -n 1 || true)
if [[ -z "$test_binary" ]]; then
  test_binary=$(find .build -path '*.xctest/Contents/MacOS/*' -type f -perm -111 | sort | tail -n 1 || true)
fi

if [[ -z "$test_binary" || ! -f "$test_binary" ]]; then
  echo "CODE_COVERAGE_ERROR XCTest binary not found" >&2
  exit 1
fi

echo "CODE_COVERAGE_INFO llvm_cov=$LLVM_COV"
echo "CODE_COVERAGE_INFO profdata=$profdata"
echo "CODE_COVERAGE_INFO test_binary=$test_binary"

"$LLVM_COV" report "$test_binary" \
  -instr-profile "$profdata" \
  -ignore-filename-regex "$IGNORE_FILENAME_REGEX" \
  | tee "$COVERAGE_REPORT"

# `llvm-cov export` emits JSON via `-format=text` (the confusingly-named default). The value
# `json` is NOT a valid `-format` option ("Cannot find option named 'json'") on the toolchain's
# llvm-cov, so use `text` which produces the JSON payload the python parser below expects.
"$LLVM_COV" export "$test_binary" \
  -format=text \
  -instr-profile "$profdata" \
  -ignore-filename-regex "$IGNORE_FILENAME_REGEX" \
  > "$COVERAGE_JSON"

python3 - "$COVERAGE_JSON" "$MIN_LINE_COVERAGE" "$MIN_FUNCTION_COVERAGE" "$COVERAGE_MD" <<'PY'
import json
import os
import sys

coverage_json, min_line_raw, min_function_raw, markdown_path = sys.argv[1:5]
min_line = float(min_line_raw)
min_function = float(min_function_raw)

with open(coverage_json, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

data = payload.get("data") or []
if not data:
    print("CODE_COVERAGE_ERROR llvm-cov export returned no data", file=sys.stderr)
    sys.exit(1)

totals = data[0].get("totals", {})
lines = totals.get("lines", {})
functions = totals.get("functions", {})
regions = totals.get("regions", {})

line_percent = float(lines.get("percent", 0.0))
function_percent = float(functions.get("percent", 0.0))
region_percent = float(regions.get("percent", 0.0))

covered_lines = int(lines.get("covered", 0))
counted_lines = int(lines.get("count", 0))
covered_functions = int(functions.get("covered", 0))
counted_functions = int(functions.get("count", 0))

print(
    "CODE_COVERAGE_METRIC "
    f"line_coverage_percent value={line_percent:.2f} min={min_line:.2f} "
    f"covered={covered_lines} count={counted_lines}"
)
print(
    "CODE_COVERAGE_METRIC "
    f"function_coverage_percent value={function_percent:.2f} min={min_function:.2f} "
    f"covered={covered_functions} count={counted_functions}"
)
print(f"CODE_COVERAGE_METRIC region_coverage_percent value={region_percent:.2f}")

# Render a Markdown report for the GitHub Actions job summary + an uploadable artifact.
def short_name(path):
    # Strip everything up to and including the last "Sources/" so the table shows
    # repo-relative module paths (e.g. SMBee/SMBClient.swift) instead of runner-absolute paths.
    marker = "Sources/"
    idx = path.rfind(marker)
    return path[idx + len(marker):] if idx >= 0 else os.path.basename(path)

status = "✅ pass" if line_percent >= min_line else "❌ below threshold"
md = []
md.append("## Code coverage")
md.append("")
md.append(f"**Line coverage: {line_percent:.2f}%** (min {min_line:.2f}%) — {status}")
md.append("")
md.append(f"- Lines: {covered_lines}/{counted_lines} ({line_percent:.2f}%)")
md.append(f"- Functions: {covered_functions}/{counted_functions} ({function_percent:.2f}%)")
md.append(f"- Regions: {region_percent:.2f}%")
md.append("")
md.append("| File | Lines % | Functions % | Regions % |")
md.append("| --- | ---: | ---: | ---: |")
files = data[0].get("files", []) or []
for entry in sorted(files, key=lambda f: float(f.get("summary", {}).get("lines", {}).get("percent", 0.0))):
    summary = entry.get("summary", {})
    fl = float(summary.get("lines", {}).get("percent", 0.0))
    ff = float(summary.get("functions", {}).get("percent", 0.0))
    fr = float(summary.get("regions", {}).get("percent", 0.0))
    md.append(f"| {short_name(entry.get('filename', '?'))} | {fl:.2f} | {ff:.2f} | {fr:.2f} |")
md.append(f"| **TOTAL** | **{line_percent:.2f}** | **{function_percent:.2f}** | **{region_percent:.2f}** |")
md_text = "\n".join(md) + "\n"

with open(markdown_path, "w", encoding="utf-8") as handle:
    handle.write(md_text)

# GitHub Actions renders $GITHUB_STEP_SUMMARY as Markdown on the job details page.
summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
if summary_path:
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(md_text)

print(f"CODE_COVERAGE_INFO markdown={markdown_path}")

failed = False
if counted_lines <= 0:
    print("CODE_COVERAGE_ERROR no source lines were counted", file=sys.stderr)
    failed = True
if line_percent < min_line:
    print(
        f"CODE_COVERAGE_ERROR line coverage {line_percent:.2f}% is below threshold {min_line:.2f}%",
        file=sys.stderr,
    )
    failed = True
if min_function > 0 and function_percent < min_function:
    print(
        f"CODE_COVERAGE_ERROR function coverage {function_percent:.2f}% is below threshold {min_function:.2f}%",
        file=sys.stderr,
    )
    failed = True

if failed:
    sys.exit(1)

print("CODE_COVERAGE_OK")
PY
