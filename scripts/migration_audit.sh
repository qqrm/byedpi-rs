#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "# Migration audit"
printf 'C translation units: '
find original -maxdepth 1 -type f -name '_*.c' | wc -l
printf 'C headers: '
find original -maxdepth 1 -type f -name '_*.h' | wc -l
printf 'Rust modules: '
find src -maxdepth 1 -type f -name '*.rs' | wc -l

echo
echo "# Porting gaps (comments with explicit stubs / not ported)"
rg -n "stub|not ported yet|Windows-first|left as stubs" src/*.rs || true

echo
echo "# Test coverage snapshot"
TEST_COUNT=$(rg -n "#\[test\]" src tests 2>/dev/null | wc -l || true)
echo "Rust #[test] count: ${TEST_COUNT}"

echo
echo "# Build-and-compare smoke run"
if scripts/e2e_compare.sh; then
  echo "e2e_compare: PASS"
else
  echo "e2e_compare: FAIL"
  exit 1
fi
