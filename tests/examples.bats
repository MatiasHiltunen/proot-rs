#!/usr/bin/env bats

load helper.bash

@test "examples: build (skippable)" {
  # Build examples if cargo is present; otherwise skip example tests.
  if ! command -v cargo >/dev/null 2>&1; then
    skip "cargo not available to build examples";
  fi
  runp cargo build --examples
  [ "$status" -eq 0 ]
}

@test "examples: remap_smoke runs under proot" {
  EXE="$PROJECT_ROOT/target/debug/examples/remap_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  PROOT_ANDROID_COMPAT=1 RUST_LOG=debug runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
}

@test "examples: accept_smoke (AF_UNIX) runs under proot" {
  EXE="$PROJECT_ROOT/target/debug/examples/accept_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  PROOT_ANDROID_COMPAT=1 RUST_LOG=debug runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
}

@test "examples: exec_smoke runs under proot" {
  EXE="$PROJECT_ROOT/target/debug/examples/exec_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  # Prefer busybox sh inside the guest rootfs
  PROOT_ANDROID_COMPAT=1 RUST_LOG=debug runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
}

@test "examples: remap_smoke logs statfs emulated event under proot" {
  EXE="$PROJECT_ROOT/target/debug/examples/remap_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  LOG_FILE="$(mktemp)"
  PROOT_ANDROID_REMAP_LOG="$LOG_FILE" PROOT_ANDROID_COMPAT=1 RUST_LOG=info runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
  grep -q '"msg":"statfs emulated"' "$LOG_FILE"
}

@test "examples: accept_smoke logs accept->accept4 remap when applicable" {
  EXE="$PROJECT_ROOT/target/debug/examples/accept_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  LOG_FILE="$(mktemp)"
  PROOT_ANDROID_REMAP_LOG="$LOG_FILE" PROOT_ANDROID_COMPAT=1 RUST_LOG=info runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
  if grep -q '"msg":"accept->accept4"' "$LOG_FILE"; then
    : # success
  else
    skip "No accept->accept4 remap observed (device policy may allow accept)"
  fi
}

@test "examples: shebang_smoke runs under proot" {
  EXE="$PROJECT_ROOT/target/debug/examples/shebang_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  PROOT_ANDROID_COMPAT=1 RUST_LOG=debug runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
}
