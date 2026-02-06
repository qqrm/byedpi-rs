#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ORIG_BUILD_DIR="$TMP_DIR/original"
cp -a original "$ORIG_BUILD_DIR"

# The upstream sources are stored with a leading underscore to avoid name clashes.
# Recreate classic names expected by the upstream Makefile.
while IFS= read -r path; do
  base="$(basename "$path")"
  plain="${base#_}"
  ln -sf "$base" "$(dirname "$path")/$plain"
done < <(find "$ORIG_BUILD_DIR" -maxdepth 1 -type f \( -name '_*.c' -o -name '_*.h' \))

echo "== Building original C implementation =="
make -C "$ORIG_BUILD_DIR" -s
ORIG_BIN="$ORIG_BUILD_DIR/ciadpi"

echo "== Building Rust port =="
RUST_BUILD_LOG="$TMP_DIR/rust_build.log"
if cargo build >"$RUST_BUILD_LOG" 2>&1; then
  RUST_BIN="$ROOT_DIR/target/debug/byedpi-rs"
  echo "Rust build: OK"
else
  echo "Rust build: FAILED"
  sed -n '1,120p' "$RUST_BUILD_LOG"
  exit 1
fi

compare_cmd() {
  local label="$1"; shift
  local args=("$@")

  local c_out="$TMP_DIR/c_${label}.txt"
  local rs_out="$TMP_DIR/rs_${label}.txt"

  set +e
  "$ORIG_BIN" "${args[@]}" >"$c_out" 2>&1
  local c_rc=$?
  "$RUST_BIN" "${args[@]}" >"$rs_out" 2>&1
  local rs_rc=$?
  set -e

  echo "-- case: $label --"
  echo "original rc=$c_rc, rust rc=$rs_rc"
  if diff -u "$c_out" "$rs_out"; then
    echo "output: identical"
  else
    echo "output: differs"
  fi
}

compare_cmd version --version
compare_cmd help --help
compare_cmd bad_arg --definitely-unknown-flag
