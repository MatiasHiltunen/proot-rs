Implementation Plan: Android Compatibility Remaps

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

Next
- Expand remaps where safe (e.g., additional time-related fallbacks) and guard by arch.
- Optional: synthesize minimal `statx` replies from `newfstatat` where libc does not fall back.
- Improve diagnostics around remaps in debug logs.
- Add Android-friendly smoke tests or instrumentation examples.

