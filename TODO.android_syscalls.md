Android/Termux Syscalls TODO (Prioritized)

Legend: [P1] highest priority, [P2] medium, [P3] lower; [T] needs unit/integration tests

Remap/Compat Survival (SIGSYS fixes)
- [P1][T] epoll_create → epoll_create1 (flags=0) (done)
- [P1][T] utime → utimensat (utimbuf→timespec[2], flags=0, AT_FDCWD) (done)
- [P1][T] select → pselect6 (done)
- [P1][T] poll → ppoll (done)
- [P1][T] epoll_wait → epoll_pwait (done)
- [P1][T] utimes → utimensat (done)
- [P1][T] statfs emulation (done)
- [P1][T] statx → ENOSYS fallback (done); optional minimal emulation later

Path/at-family correctness
- [P1][T] openat, newfstatat, readlinkat, unlinkat, linkat, symlinkat, renameat, renameat2
- [P1][T] faccessat, faccessat2
- [P1][T] fchmodat, fchownat

Exec/Loader
- [P1][T] Trampoline-first exec hardening (shebang/interpreter resolution)
- [P2][T] Optional loader binary support via PROOT_LOADER_SHIM

Networking basics
- [P2][T] accept, accept4 (remap accept→accept4 done; AF_UNIX smoke)
- [P2][T] bind, connect, getsockname, getpeername, listen, shutdown, getsockopt/setsockopt

Time/Timers
- [P2][T] clock_gettime* / gettimeofday / nanosleep / clock_nanosleep*
- [P2][T] pselect6_time64 / ppoll_time64
- [P3][T] timerfd*, timer_* family

File/IO core
- [P1][T] read, write, readv, writev, pread*, pwrite*, fsync, fdatasync, ftruncate
- [P2][T] copy_file_range, splice, vmsplice, tee, syncfs, sync_file_range

Xattr/Namespacing
- [P2][T] getxattr*, setxattr*, listxattr*

Inotify/Fanotify
- [P3][T] inotify_*; fanotify_mark

Proc/Signals/Sched
- [P2][T] wait4, waitid, waitpid
- [P2][T] rt_sig* family (mask/action)
- [P3][T] prctl, seccomp (pass-through)

Futex
- [P2][T] futex*, futex_time64, futex_waitv

Misc
- [P3][T] getrandom, uname, sysinfo, getrlimit/prlimit64
- [P3][T] memfd_create, mlock*, mprotect/mmap/munmap/mremap

Testing Plan
- Android-friendly unit tests: pure conversions (timeval/utimbuf/ms→timespec), syscall number availability.
- Examples: exercise remapped syscalls (select/poll/utimes/accept/statfs), AF_UNIX preferred.
- Bats integration: run examples under proot with android-compat enabled.
- Optional: remap event sink (JSON log) to assert remaps happened.
