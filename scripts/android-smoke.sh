#!/usr/bin/env bash
set -euo pipefail

# Android/Termux smoke runner for proot-rs
# - Builds examples
# - Ensures a guest rootfs exists (uses scripts/mkrootfs.sh if missing and PROOT_TEST_ROOTFS not set)
# - Runs bats integration tests

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

export RUST_LOG=${RUST_LOG:-info}
export PROOT_ANDROID_COMPAT=${PROOT_ANDROID_COMPAT:-1}

cd "$root"

echo "[smoke] Building examples"
cargo build --examples

if [[ -z "${PROOT_TEST_ROOTFS:-}" ]]; then
  if [[ ! -d "$root/rootfs" ]]; then
    echo "[smoke] No PROOT_TEST_ROOTFS set and ./rootfs missing; creating test rootfs"
    bash scripts/mkrootfs.sh
  fi
fi

if ! command -v bats >/dev/null 2>&1; then
  echo "[smoke] bats not found in PATH; please install bats to run integration tests" >&2
  exit 2
fi

echo "[smoke] Running bats integration tests"
bats -r tests

