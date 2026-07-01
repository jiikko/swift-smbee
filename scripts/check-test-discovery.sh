#!/usr/bin/env bash
set -euo pipefail

TEST_ROOT="${TEST_ROOT:-Tests/SMBeeTests}"
MIN_DISCOVERED_TESTS="${MIN_DISCOVERED_TESTS:-1}"
LIST_FILE="${LIST_FILE:-.build/discovered-tests.txt}"

if [[ ! -d "$TEST_ROOT" ]]; then
  echo "TEST_DISCOVERY_ERROR test root not found: $TEST_ROOT" >&2
  exit 1
fi

mkdir -p "$(dirname "$LIST_FILE")"

echo "TEST_DISCOVERY_INFO command=swift test --list-tests"
swift test --list-tests | tee "$LIST_FILE"

# SwiftPM has used slightly different separators across XCTest / toolchain versions:
#   Module.Class/testMethod
#   Module.Class.testMethod
# Keep the parser tolerant and only treat lines under SMBeeTests as discovered tests.
discovered_count=$(grep -E '(^|[[:space:]])SMBeeTests[./][A-Za-z0-9_]+[./][A-Za-z0-9_]+' "$LIST_FILE" | wc -l | tr -d '[:space:]')

# Source-side XCTest discovery lower bound. This intentionally counts only XCTest-style
# `func test...()` methods because the package currently uses XCTest, not swift-testing.
source_test_count=$(find "$TEST_ROOT" -name '*Tests.swift' -print0 \
  | xargs -0 grep -hE '^[[:space:]]*(public[[:space:]]+|internal[[:space:]]+|private[[:space:]]+)?func[[:space:]]+test[A-Za-z0-9_]*[[:space:]]*\(' \
  | wc -l \
  | tr -d '[:space:]')

# Every XCTestCase class in a *Tests.swift file should appear at least once in --list-tests.
# This catches newly added files/classes that compile but are not discovered by SwiftPM/XCTest.
mapfile -t source_test_classes < <(
  find "$TEST_ROOT" -name '*Tests.swift' -print0 \
    | xargs -0 grep -hE '^[[:space:]]*(final[[:space:]]+)?class[[:space:]]+[A-Za-z0-9_]+[[:space:]]*:[^{]*XCTestCase' \
    | sed -E 's/.*class[[:space:]]+([A-Za-z0-9_]+)[[:space:]]*:.*/\1/' \
    | sort -u
)

missing_classes=()
for class_name in "${source_test_classes[@]}"; do
  if ! grep -Eq "(^|[./])${class_name}([./]|$)" "$LIST_FILE"; then
    missing_classes+=("$class_name")
  fi
done

echo "TEST_DISCOVERY_METRIC discovered_tests actual=${discovered_count} source_lower_bound=${source_test_count} min=${MIN_DISCOVERED_TESTS}"
echo "TEST_DISCOVERY_METRIC discovered_classes actual=${#source_test_classes[@]} missing=${#missing_classes[@]}"

if (( discovered_count < MIN_DISCOVERED_TESTS )); then
  echo "TEST_DISCOVERY_ERROR discovered test count ${discovered_count} is below MIN_DISCOVERED_TESTS=${MIN_DISCOVERED_TESTS}" >&2
  exit 1
fi

if (( discovered_count < source_test_count )); then
  echo "TEST_DISCOVERY_ERROR discovered test count ${discovered_count} is below source XCTest method count ${source_test_count}" >&2
  echo "TEST_DISCOVERY_ERROR this usually means a new XCTest method/file is not being discovered" >&2
  exit 1
fi

if (( ${#missing_classes[@]} > 0 )); then
  printf 'TEST_DISCOVERY_ERROR missing XCTestCase classes in --list-tests:' >&2
  printf ' %s' "${missing_classes[@]}" >&2
  printf '\n' >&2
  exit 1
fi

echo "TEST_DISCOVERY_OK discovered=${discovered_count} source_lower_bound=${source_test_count} classes=${#source_test_classes[@]}"
