Implementation Plan: Android/Termux Compatibility

Completed
- Build stabilization on stable Rust and Termux.
- Local `sc/` syscall shim with Android aarch64 constants.
- Android compat mode: swallow SIGSYS, accept→accept4, statfs emulation, statx ENOSYS fallback.
- Exec bootstrap: direct host resolution + configurable trampoline.
- New remaps (with structure conversions) under SIGSYS handling:
  - select→pselect6: convert `timeval`→`timespec`, set `sigmask=NULL`.
  - poll→ppoll: convert `timeout ms`→`timespec`, set `sigmask=NULL`, `sigsetsize=0`.
  - epoll_wait→epoll_pwait: set `sigmask=NULL`, `sigsetsize=0`.
  - utimes→utimensat: convert `timeval[2]`→`timespec[2]`, `flags=0`, `dirfd=AT_FDCWD`.
  - utime→utimensat: convert `utimbuf`→`timespec[2]`, `flags=0`, `dirfd=AT_FDCWD`.
  - epoll_create→epoll_create1: force `flags=0`.
- Legacy remaps: `_newselect`→`pselect6`; `futimesat`→`utimensat`.
- Shebang exec diagnostics: detect `#!` in intended guest target and log a hint.
- Optional JSON remap-event log (`PROOT_ANDROID_REMAP_LOG`) for deterministic test assertions.
- Examples: `remap_smoke`, `accept_smoke` (AF_UNIX default), `at_smoke`, `at_edges_smoke`, `at_new_smoke`, `shebang_smoke`.
- Bats integration tests: run examples under proot; assert remap-events for `statfs` emulation and `accept→accept4` when applicable.
- Smoke runner: `scripts/android-smoke.sh` (builds examples, ensures rootfs, runs bats).
- Guarded tests for newer at-family syscalls (added):
  - `faccessat2` with `AT_EACCESS` (fallback to `faccessat` on ENOSYS).
  - `renameat2` with `RENAME_NOREPLACE` negative path (skips on ENOSYS).
  - `renameat2` with `RENAME_EXCHANGE` (skips on ENOSYS).

Next
- Expand at-family edge cases: relative `dirfd` paths, additional symlink no-follow cases, and verify rename exchange results (read-back assertions).
- Exec trampoline hardening for interpreter resolution in corner cases.
- Optional: synthesize minimal `statx` replies from `newfstatat` where libc does not fall back.
- Optional: extend remap-event assertions (e.g., select/poll/epoll) where deterministic on target devices.
