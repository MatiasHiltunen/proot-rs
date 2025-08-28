#!/usr/bin/env bats

load helper.bash

@test "at-family: build example" {
  if ! command -v cargo >/dev/null 2>&1; then
    skip "cargo not available to build examples";
  fi
  runp cargo build --examples
  [ "$status" -eq 0 ]
}

@test "at-family: openat/readlinkat/renameat/unlinkat work under proot" {
  EXE="$PROJECT_ROOT/target/debug/examples/at_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  PROOT_ANDROID_COMPAT=1 RUST_LOG=debug runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
}

@test "at-family: O_NOFOLLOW and faccessat work under proot" {
  EXE="$PROJECT_ROOT/target/debug/examples/at_edges_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  PROOT_ANDROID_COMPAT=1 RUST_LOG=debug runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
}

@test "at-family: faccessat2/renameat2 (or fallbacks) under proot" {
  EXE="$PROJECT_ROOT/target/debug/examples/at_new_smoke"
  if [ ! -x "$EXE" ]; then
    skip "example binary not found: $EXE"
  fi
  PROOT_ANDROID_COMPAT=1 RUST_LOG=debug runp proot-rs -r "$ROOTFS" -- "$EXE"
  [ "$status" -eq 0 ]
}
