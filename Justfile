# justfile (Windows-first)

set shell := ["pwsh", "-NoProfile", "-Command"]
set dotenv-load := false

default: help

help:
  @just --list

# ---------- Toolchain ----------
toolchain:
  rustup show
  rustup toolchain list

fmt:
  cargo fmt

clippy:
  cargo clippy --all-targets --all-features -- -D warnings

check:
  cargo check

check-all:
  cargo check --all-targets --all-features

fix:
  cargo fix --allow-dirty

clean:
  cargo clean

# ---------- Builds ----------
build:
  cargo build

build-release:
  cargo build --release

build-win-service:
  cargo build --features windows-service

build-win-service-release:
  cargo build --release --features windows-service

build-win-msvc:
  cargo build --target x86_64-pc-windows-msvc

build-win-msvc-release:
  cargo build --release --target x86_64-pc-windows-msvc

# ---------- Run (placeholder until main.c is fully ported) ----------
run:
  cargo run

run-release:
  cargo run --release

# ---------- CI-ish ----------
ci:
  just fmt
  just check-all
