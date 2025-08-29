use std::cell::RefCell;
use std::ffi::CString;

use std::process;
use std::rc::Rc;
use std::{collections::HashMap, convert::TryFrom};
use std::os::unix::ffi::OsStrExt;

use libc::{c_int, c_void, pid_t, siginfo_t};
use nix::sys::ptrace::{self, Event as PtraceEvent};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{self, WaitPidFlag, WaitStatus::*};
use nix::unistd::{self, ForkResult, Pid};

use crate::kernel::execve::loader::LoaderFile;
use crate::process::event::EventHandler;
use crate::process::tracee::{SigStopStatus, Tracee};
use crate::{
    errors::*,
    filesystem::{temp::TempFile, FileSystem},
};
use crate::filesystem::Translator;

/// Used to store global info common to all tracees. Rename into
/// `Configuration`?
#[derive(Debug)]
pub struct InfoBag {
    /// Used to know if the ptrace options is already set.
    pub options_already_set: bool,
    /// Binary loader, used by `execve`.
    /// The content of the binary is actually inlined in `proot-rs`
    /// (see `src/kernel/execve/loader`), and is extracted into a temporary file
    /// before use. This temporary file struct makes sure the file is
    /// deleted when it's dropped.
    pub loader: TempFile,
}

impl InfoBag {
    pub fn new() -> InfoBag {
        InfoBag {
            options_already_set: false,
            loader: TempFile::new("prooted"),
        }
    }
}

pub struct PRoot {
    info_bag: InfoBag,
    tracees: HashMap<Pid, Tracee>,
    alive_tracees: Vec<Pid>,
    /// The `pid` of init process (i.e. the first tracee)
    pub init_pid: Option<Pid>,
    /// The exit code of the init process (i.e. the first tracee)
    pub init_exit_code: Option<i32>,
    /// A pointer to a function used to check the running status of Proot.
    /// For each syscall-stop, it will be called four times (at the beginning
    /// and end of both syscall-enter-stop and syscall-exit-stop).
    ///
    /// Note: Since its purpose is to check, it should not produce any effect on
    /// the running of Proot.
    #[cfg(test)]
    pub func_syscall_hook: Option<Box<dyn Fn(&Tracee, bool, bool)>>,
}

impl PRoot {
    pub fn new() -> PRoot {
        PRoot {
            info_bag: InfoBag::new(),
            tracees: HashMap::new(),
            alive_tracees: vec![],
            init_pid: None,
            init_exit_code: None,
            #[cfg(test)]
            func_syscall_hook: None,
        }
    }

    /// Some initialization is required before proot can generate tracee, and it
    /// only needs to be initialized once
    pub fn init(&mut self) -> Result<()> {
        // we need to prepare the loader here
        self.info_bag
            .loader
            .prepare_loader()
            .context("Error while prepare loader file")?;
        Ok(())
    }

    /// Main process where proot splits into two threads:
    /// - a tracer, the parent thread.
    /// - a (first) tracee, the child thread, that will declare itself as
    ///   ptrace-able before executing the program.
    ///
    /// The `fork()` done here implies that the OS will apply copy-on-write
    /// on all the shared memory of the parent and child processes
    /// (heap, libraries...), so both of them will have their own (owned)
    /// version of the PRoot memory.
    pub fn launch_process(&mut self, initial_fs: FileSystem, command: Vec<String>) -> Result<()> {
        debug!(
            "launch_process with fs:\n{:#?}\ncommand: {:?}",
            initial_fs, command
        );

        // parse command
        let args = command
            .iter()
            .map(|arg| {
                CString::new(arg.as_bytes()).with_context(|| {
                    format!("Illegal parameters, should not contain \0 bytes: {}", arg)
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let filename = &args[0];
        match unsafe { unistd::fork() }.context("Failed to fork() when starting process")? {
            ForkResult::Parent { child } => {
                // create the first tracee
                self.create_tracee(
                    child,
                    Rc::new(RefCell::new(initial_fs)),
                    SigStopStatus::EventloopSync,
                );
                self.init_pid = Some(child);
            }
            ForkResult::Child => {
                let init_child_func = || -> Result<()> {
                    // Declare the tracee as ptraceable
                    ptrace::traceme()
                        .context("Failed to execute ptrace::traceme() in a child process")?;
                    // Synchronise with the parent's event loop by waiting until it's ready
                    // (otherwise the execvp is executed too quickly)
                    signal::kill(unistd::getpid(), Signal::SIGSTOP)
                        .context("Child process failed to synchronize with parent process")?;
                    //TODO: seccomp
                    //if (getenv("PROOT_NO_SECCOMP") == NULL)
                    //    (void) enable_syscall_filtering(tracee);
                    // Prefer direct resolution of argv[0] to a real host executable to make the
                    // first exec succeed on Android/Termux.
                    {
                        let arg0_bytes = args[0].as_bytes();
                        let mut host_exec_path: Option<std::path::PathBuf> = None;
                        if arg0_bytes.contains(&b'/') {
                            let guest_os = std::ffi::OsStr::from_bytes(arg0_bytes);
                            let guest_path = std::path::Path::new(guest_os);
                            if guest_path.is_absolute() {
                                let mut host_path = initial_fs.get_root().to_path_buf();
                                if let Ok(stripped) = guest_path.strip_prefix("/") {
                                    host_path.push(stripped);
                                }
                                if host_path.exists() {
                                    host_exec_path = Some(host_path);
                                }
                            }
                        } else {
                            let name = std::ffi::OsStr::from_bytes(arg0_bytes);
                            let mut candidates = vec![
                                initial_fs.get_root().join("bin").join(name),
                                initial_fs.get_root().join("usr/bin").join(name),
                                std::path::PathBuf::from("/system/bin").join(name),
                            ];
                            for c in candidates.drain(..) {
                                if c.exists() { host_exec_path = Some(c); break; }
                            }
                        }
                        if let Some(host_exec) = host_exec_path {
                            let host_c = std::ffi::CString::new(host_exec.as_os_str().as_bytes())
                                .with_context(|| format!("Bad exec path bytes: {:?}", host_exec))?;
                            unistd::execv(&host_c, &args).with_context(|| {
                                format!(
                                    "Failed to execv resolved host path {:?} for command {:?}",
                                    host_exec, command
                                )
                            })?;
                            unreachable!();
                        }
                    }
                    // Optional: detect shebang on the intended guest target to aid diagnostics
                    // on Android. This does not change behavior, only logs a hint.
                    {
                        use std::io::Read;
                        let arg0_bytes = args[0].as_bytes();
                        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
                        if arg0_bytes.contains(&b'/') {
                            let guest_os = std::ffi::OsStr::from_bytes(arg0_bytes);
                            let guest_path = std::path::Path::new(guest_os);
                            if guest_path.is_absolute() {
                                let mut host_path = initial_fs.get_root().to_path_buf();
                                if let Ok(stripped) = guest_path.strip_prefix("/") {
                                    host_path.push(stripped);
                                }
                                candidates.push(host_path);
                            }
                        } else {
                            let name = std::ffi::OsStr::from_bytes(arg0_bytes);
                            candidates.push(initial_fs.get_root().join("bin").join(name));
                            candidates.push(initial_fs.get_root().join("usr/bin").join(name));
                        }
                        for c in candidates.into_iter() {
                            if c.exists() {
                                if let Ok(mut f) = std::fs::File::open(&c) {
                                    let mut magic = [0u8; 2];
                                    if f.read(&mut magic).ok() == Some(2) && magic == *b"#!" {
                                        debug!("android-compat: shebang detected in {:?}", c);
                                    }
                                }
                                break;
                            }
                        }
                    }
                    // Trampoline strategy: Always exec a safe host shell first, passing a tiny
                    // script that re-execs the intended command. This ensures the first exec
                    // succeeds on Android/Termux and our ptrace translation can take over on the
                    // subsequent exec.
                    // Allow explicit trampoline path via env (CLI flag). Otherwise try common shells.
                    let mut trampoline = std::env::var_os("PROOT_TRAMPOLINE")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| initial_fs.get_root().join("bin/sh"));
                    if !trampoline.exists() {
                        trampoline = initial_fs.get_root().join("bin/dash");
                    }
                    if !trampoline.exists() {
                        trampoline = std::path::PathBuf::from("/system/bin/sh");
                    }

                    let tramp_bytes = trampoline.as_os_str().as_bytes();
                    let tramp = std::ffi::CString::new(tramp_bytes)
                        .with_context(|| format!("No suitable shell found for trampoline at {:?}", trampoline))?;

                    // Build argv for: sh -c 'exec "$@"' -- <original argv>
                    let dash_c = std::ffi::CString::new("-c").unwrap();
                    let script = std::ffi::CString::new("exec \"$@\"").unwrap();
                    let sep = std::ffi::CString::new("--").unwrap();

                    // Compose: [tramp, -c, script, --, orig0, orig1, ...]
                    let mut new_argv: Vec<std::ffi::CString> = Vec::with_capacity(4 + args.len());
                    new_argv.push(tramp.clone());
                    new_argv.push(dash_c);
                    new_argv.push(script);
                    new_argv.push(sep);
                    for a in &args {
                        new_argv.push(a.clone());
                    }

                    let argv_refs: Vec<&std::ffi::CStr> = new_argv.iter().map(|c| c.as_c_str()).collect();
                    unistd::execv(&tramp, &argv_refs).with_context(|| {
                        format!(
                            "Failed to call execv() trampoline {:?} for command: {:?}",
                            trampoline, command
                        )
                    })?;
                    unreachable!()
                };

                if let Err(e) = init_child_func() {
                    error!("Failed to initialize the child process: {}", e);
                    // Ensure that child processes will not return to the main function
                    process::exit(1);
                }
            }
        };
        Ok(())
    }

    /// Infinite loop where PRoot will wait for tracees signals with `waitpid`.
    /// Tracees will be stopped when they use a system call.
    /// The tracer will be notified through `waitpid` and will be able to alter
    /// the parameters of the system call, before restarting the tracee.
    pub fn event_loop(&mut self) -> Result<()> {
        // TODO: what should we do if there is a terrible error in eventloop?
        while !self.alive_tracees.is_empty() {
            match wait::waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL))
                .context("Error calling waitpid() in event loop")?
            {
                Exited(pid, exit_status) => {
                    trace!("-- {}, Exited with status: {}", pid, exit_status);
                    self.register_tracee_finished(pid);
                    if Some(pid) == self.init_pid {
                        // The "init" process was exited. We need to record the exit code.
                        debug!("init process exited with exit code: {}", exit_status);
                        self.init_exit_code = Some(exit_status);
                        // TODO: maybe we also need to take care of all the
                        // "orphans" process?
                    }
                }
                Signaled(pid, term_signal, dumped_core) => {
                    trace!(
                        "-- {}, Killed by signal: {:?}, and dump core: {}",
                        pid,
                        term_signal,
                        dumped_core
                    );
                    self.register_tracee_finished(pid);
                    if Some(pid) == self.init_pid {
                        // The "init" process was killed by a signal, the exit code should be
                        // 128+signal
                        debug!("init process was killed by a signal: {}", term_signal);
                        self.init_exit_code = Some(128 + (term_signal as i32));
                        // TODO: maybe we also need to take care of all the
                        // "orphans" process?
                    }
                }
                // The tracee was stopped by a normal signal (signal-delivery-stop), or was stopped
                // by a system call (syscall-stop) with PTRACE_O_TRACESYSGOOD not effect.
                Stopped(pid, stop_signal) => {
                    trace!(
                        "-- {}, Stopped, {:?}, {}",
                        pid,
                        stop_signal,
                        stop_signal as c_int
                    );

                    let mut signal_to_delivery = Some(stop_signal);

                    let maybe_tracee = self.tracees.get_mut(&pid);

                    let tracee = if maybe_tracee.is_none() {
                        if stop_signal == Signal::SIGSTOP {
                            debug!("-- {}, SIGSTOP arrives before ptrace event but tracee is not initialized, so create a placeholder to record this.", pid);
                            // Get tracee instance of init process, note that at this point
                            // `init_pid` must not be none, so we can unwrap() it safely.
                            let init_tracee = self.tracees.get(&self.init_pid.unwrap()).unwrap();
                            // Create a new tracee instance as placeholder, only for record the pid
                            // and sigstop status of this newly created process.
                            // Since the `fs` field cannot be none value, we'll temporarily use the
                            // value of the init process's fs field in its place, even though it
                            // should be actually derived from the parent process. But please
                            // remember that the `fs` field should not be used until the tracee is
                            // fully initialized in the ptrace event handler function.
                            let mut tracee = Tracee::new(pid, init_tracee.fs.clone());
                            // We are waiting for a ptrace event to initialize this tracee.
                            tracee.sigstop_status = SigStopStatus::WaitForEventClone;
                            self.insert_new_tracee(tracee);
                            signal_to_delivery = None;
                            self.tracees.get_mut(&pid).unwrap()
                        } else {
                            error!("-- {}, Received a signal from an unknown tracee.", pid);
                            // Deliver this SIGSTOP signal to this unknown tracee
                            ptrace::syscall(pid, Some(stop_signal))
                                .expect("deliver stop signal to unknown tracee");
                            // continue the event loop
                            continue;
                        }
                    } else {
                        maybe_tracee.unwrap()
                    };
                    tracee.reset_restart_how();
                    match stop_signal {
                        Signal::SIGSTOP => {
                            if tracee.sigstop_status == SigStopStatus::EventloopSync {
                                // When the first child process starts, it sends a SIGSTOP to
                                // itself. And we need to set ptrace
                                // options at this point.
                                tracee.check_and_set_ptrace_options(&mut self.info_bag)?;
                                signal_to_delivery = None;
                                tracee.sigstop_status = SigStopStatus::AllowDelivery;
                            } else if tracee.sigstop_status == SigStopStatus::WaitForSigStopClone {
                                signal_to_delivery = None;
                                tracee.sigstop_status = SigStopStatus::AllowDelivery;
                            }

                            tracee.handle_sigstop_event();
                        }
                        // Android compat: swallows SIGSYS (seccomp) and forces the
                        // current syscall to fail with ENOSYS to keep the tracee
                        // alive under Android's seccomp policy.
                        Signal::SIGSYS => {
                            // Enable by default on Android, can be disabled by setting
                            // PROOT_ANDROID_COMPAT=0.
                            let android_compat = cfg!(target_os = "android")
                                && std::env::var("PROOT_ANDROID_COMPAT")
                                    .map(|v| v != "0")
                                    .unwrap_or(true);
                            if android_compat {
                                debug!("-- {}, SIGSYS swallowed (android-compat)", pid);
                        // Do not deliver SIGSYS; allow the tracee to continue. Some Android
                        // seccomp policies send SIGSYS but do not kill the process if the
                        // signal is handled/ignored.
                        signal_to_delivery = None;
                        // Opportunistically rewrite some blocked syscalls to their
                        // *at/*p* replacements so the kernel permits them under seccomp.
                        if let Err(e) = (|| -> Result<()> {
                            use crate::register::{Current, SysArg, SysArg1, SysArg2, SysArg3, SysArg4, SysArg5, PtraceReader, PtraceWriter};
                            tracee.regs.fetch_regs()?;
                            let sys = tracee.regs.get_sys_num(Current);
                            match sys {
                                // statx: on Android-compat, report ENOSYS to drive libc fallback
                                x if x == sc::nr::STATX => {
                                    debug!("android-compat: emulate statx as ENOSYS");
                                    crate::android_log::log_remap(sc::nr::STATX, sc::nr::STATX, "statx->ENOSYS", tracee.pid.as_raw());
                                    tracee.regs.cancel_syscall("android-compat: emulate statx ENOSYS");
                                    tracee
                                        .regs
                                        .set(crate::register::SysResult, (-(Errno::ENOSYS as i32)) as u64, "statx ENOSYS");
                                    tracee.regs.set_restore_original_regs(false);
                                    tracee.regs.push_regs()?;
                                }
                                // epoll_create(size) -> epoll_create1(flags=0)
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
                                x if x == sc::nr::EPOLL_CREATE => {
                                    debug!("android-compat: remap epoll_create -> epoll_create1");
                                    crate::android_log::log_remap(sc::nr::EPOLL_CREATE, sc::nr::EPOLL_CREATE1, "epoll_create->epoll_create1", tracee.pid.as_raw());
                                    tracee.regs.set_sys_num(sc::nr::EPOLL_CREATE1, "android-compat: epoll_create->epoll_create1");
                                    tracee.regs.set(SysArg(SysArg1), 0, "flags=0");
                                }
                                // accept -> accept4(..., 0)
                                x if x == sc::nr::ACCEPT => {
                                    debug!("android-compat: remap accept -> accept4");
                                    crate::android_log::log_remap(sc::nr::ACCEPT, sc::nr::ACCEPT4, "accept->accept4", tracee.pid.as_raw());
                                    tracee.regs.set_sys_num(sc::nr::ACCEPT4, "android-compat: accept->accept4");
                                    tracee.regs.set(SysArg(SysArg4), 0, "set flags=0");
                                }
                                // statfs(path, buf) -> emulate in tracer using host statfs
                                x if x == sc::nr::STATFS => {
                                    debug!("android-compat: emulate statfs in tracer");
                                    // Save regs to allow controlled push without restore
                                    tracee.regs.save_current_regs(crate::register::Original);
                                    let guest_path = tracee.regs.get_sysarg_path(SysArg1)?;
                                    // Translate guest path to host path
                                    let host_path = tracee
                                        .fs
                                        .borrow()
                                        .translate_path(&guest_path, true)
                                        .map(|(_, p)| p)
                                        .unwrap_or_else(|_| guest_path.clone());
                                    let host_c = std::ffi::CString::new(host_path.as_os_str().as_bytes())
                                        .map_err(|_| Error::errno_with_msg(Errno::EFAULT, "bad host path bytes"))?;
                                    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
                                    let rc = unsafe { libc::statfs(host_c.as_ptr(), &mut st as *mut _) };
                                    if rc == 0 {
                                        // Write back to tracee buffer
                                        let dest = tracee.regs.get(Current, SysArg(SysArg2)) as *mut _;
                                        let bytes = unsafe {
                                            std::slice::from_raw_parts(
                                                (&st as *const libc::statfs) as *const u8,
                                                std::mem::size_of::<libc::statfs>(),
                                            )
                                        };
                                        tracee.regs.write_data(dest, bytes, false)?;
                                        // Log emulation success for test visibility
                                        crate::android_log::log_remap(sc::nr::STATFS, sc::nr::STATFS, "statfs emulated", tracee.pid.as_raw());
                                        // Cancel syscall and set result 0
                                        tracee.regs.cancel_syscall("android-compat: emulate statfs");
                                        tracee.regs.set(crate::register::SysResult, 0, "statfs ok");
                                        tracee.regs.set_restore_original_regs(false);
                                        tracee.regs.push_regs()?;
                                    } else {
                                        // Return -errno
                                        let err = nix::errno::Errno::last();
                                        tracee.regs.cancel_syscall("android-compat: emulate statfs error");
                                        tracee
                                            .regs
                                            .set(
                                                crate::register::SysResult,
                                                (-(err as i32)) as u64,
                                                "statfs err",
                                            );
                                        tracee.regs.set_restore_original_regs(false);
                                        tracee.regs.push_regs()?;
                                    }
                                }
                                // utimes(path, timeval[2]) -> utimensat(AT_FDCWD, path, timespec[2], 0)
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
                                x if x == sc::nr::UTIMES => {
                                    debug!("android-compat: remap utimes -> utimensat");
                                    crate::android_log::log_remap(sc::nr::UTIMES, sc::nr::UTIMENSAT, "utimes->utimensat", tracee.pid.as_raw());
                                    use std::mem::size_of;
                                    let tv_ptr = tracee.regs.get(Current, SysArg(SysArg2)) as *mut libc::c_void;
                                    if tv_ptr.is_null() {
                                        tracee.regs.set_sys_num(sc::nr::UTIMENSAT, "android-compat: utimes->utimensat");
                                        tracee.regs.set(SysArg(SysArg4), 0, "flags=0");
                                        tracee.regs.set(SysArg(SysArg3), 0, "timespec=NULL");
                                        tracee.regs.set(SysArg(SysArg1), libc::AT_FDCWD as _, "AT_FDCWD");
                                    } else {
                                        let mut buf = vec![0u8; 2 * size_of::<libc::timeval>()];
                                        let word_size = size_of::<crate::register::Word>();
                                        let nb_words = (buf.len() + word_size - 1) / word_size;
                                        for i in 0..nb_words {
                                            let src = unsafe { (tv_ptr as *mut crate::register::Word).offset(i as isize) } as *mut libc::c_void;
                                            let w = nix::sys::ptrace::read(tracee.regs.get_pid(), src)? as crate::register::Word;
                                            let bytes = crate::register::reader::convert_word_to_bytes(w);
                                            let start = i * word_size;
                                            let end = std::cmp::min(start + word_size, buf.len());
                                            buf[start..end].copy_from_slice(&bytes[..end - start]);
                                        }
                                        let tv: &[libc::timeval] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const libc::timeval, 2) };
                                        let ts = [
                                            libc::timespec { tv_sec: tv[0].tv_sec, tv_nsec: tv[0].tv_usec * 1000 },
                                            libc::timespec { tv_sec: tv[1].tv_sec, tv_nsec: tv[1].tv_usec * 1000 },
                                        ];
                                        let ts_bytes = unsafe { std::slice::from_raw_parts((&ts as *const libc::timespec) as *const u8, 2 * size_of::<libc::timespec>()) };
                                        let ts_ptr = tracee.regs.allocate_and_write(ts_bytes, false)?;
                                        tracee.regs.set_sys_num(sc::nr::UTIMENSAT, "android-compat: utimes->utimensat");
                                        tracee.regs.set(SysArg(SysArg4), 0, "flags=0");
                                        tracee.regs.set(SysArg(SysArg3), ts_ptr as u64, "timespec*");
                                        tracee.regs.set(SysArg(SysArg1), libc::AT_FDCWD as _, "AT_FDCWD");
                                    }
                                }
                                // utime(path, utimbuf*) -> utimensat(AT_FDCWD, path, timespec[2], 0)
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
                                x if x == sc::nr::UTIME => {
                                    debug!("android-compat: remap utime -> utimensat");
                                    crate::android_log::log_remap(sc::nr::UTIME, sc::nr::UTIMENSAT, "utime->utimensat", tracee.pid.as_raw());
                                    use std::mem::size_of;
                                    let ub_ptr = tracee.regs.get(Current, SysArg(SysArg2)) as *mut libc::c_void;
                                    if ub_ptr.is_null() {
                                        tracee.regs.set_sys_num(sc::nr::UTIMENSAT, "android-compat: utime->utimensat");
                                        tracee.regs.set(SysArg(SysArg4), 0, "flags=0");
                                        tracee.regs.set(SysArg(SysArg3), 0, "timespec=NULL");
                                        tracee.regs.set(SysArg(SysArg1), libc::AT_FDCWD as _, "AT_FDCWD");
                                    } else {
                                        let mut buf = vec![0u8; size_of::<libc::utimbuf>()];
                                        let word_size = size_of::<crate::register::Word>();
                                        let nb_words = (buf.len() + word_size - 1) / word_size;
                                        for i in 0..nb_words {
                                            let src = unsafe { (ub_ptr as *mut crate::register::Word).offset(i as isize) } as *mut libc::c_void;
                                            let w = nix::sys::ptrace::read(tracee.regs.get_pid(), src)? as crate::register::Word;
                                            let bytes = crate::register::reader::convert_word_to_bytes(w);
                                            let start = i * word_size;
                                            let end = std::cmp::min(start + word_size, buf.len());
                                            buf[start..end].copy_from_slice(&bytes[..end - start]);
                                        }
                                        let ut: libc::utimbuf = unsafe { std::ptr::read(buf.as_ptr() as *const libc::utimbuf) };
                                        let ts = crate::android_compat::utimbuf_to_timespec2(ut);
                                        let ts_bytes = unsafe { std::slice::from_raw_parts((&ts as *const libc::timespec) as *const u8, 2 * size_of::<libc::timespec>()) };
                                        let ts_ptr = tracee.regs.allocate_and_write(ts_bytes, false)?;
                                        tracee.regs.set_sys_num(sc::nr::UTIMENSAT, "android-compat: utime->utimensat");
                                        tracee.regs.set(SysArg(SysArg4), 0, "flags=0");
                                        tracee.regs.set(SysArg(SysArg3), ts_ptr as u64, "timespec*");
                                        tracee.regs.set(SysArg(SysArg1), libc::AT_FDCWD as _, "AT_FDCWD");
                                    }
                                }
                                // futimesat(dirfd, path, timeval[2]) -> utimensat(dirfd, path, timespec[2], 0)
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
                                x if x == sc::nr::FUTIMESAT => {
                                    debug!("android-compat: remap futimesat -> utimensat");
                                    crate::android_log::log_remap(sc::nr::FUTIMESAT, sc::nr::UTIMENSAT, "futimesat->utimensat", tracee.pid.as_raw());
                                    use std::mem::size_of;
                                    let tv_ptr = tracee.regs.get(Current, SysArg(SysArg3)) as *mut libc::c_void;
                                    if tv_ptr.is_null() {
                                        tracee.regs.set_sys_num(sc::nr::UTIMENSAT, "android-compat: futimesat->utimensat");
                                        tracee.regs.set(SysArg(SysArg4), 0, "flags=0");
                                        tracee.regs.set(SysArg(SysArg3), 0, "timespec=NULL");
                                    } else {
                                        let mut buf = vec![0u8; 2 * size_of::<libc::timeval>()];
                                        let word_size = size_of::<crate::register::Word>();
                                        let nb_words = (buf.len() + word_size - 1) / word_size;
                                        for i in 0..nb_words {
                                            let src = unsafe { (tv_ptr as *mut crate::register::Word).offset(i as isize) } as *mut libc::c_void;
                                            let w = nix::sys::ptrace::read(tracee.regs.get_pid(), src)? as crate::register::Word;
                                            let bytes = crate::register::reader::convert_word_to_bytes(w);
                                            let start = i * word_size;
                                            let end = std::cmp::min(start + word_size, buf.len());
                                            buf[start..end].copy_from_slice(&bytes[..end - start]);
                                        }
                                        let tv: &[libc::timeval] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const libc::timeval, 2) };
                                        let ts = [
                                            libc::timespec { tv_sec: tv[0].tv_sec, tv_nsec: tv[0].tv_usec * 1000 },
                                            libc::timespec { tv_sec: tv[1].tv_sec, tv_nsec: tv[1].tv_usec * 1000 },
                                        ];
                                        let ts_bytes = unsafe { std::slice::from_raw_parts((&ts as *const libc::timespec) as *const u8, 2 * size_of::<libc::timespec>()) };
                                        let ts_ptr = tracee.regs.allocate_and_write(ts_bytes, false)?;
                                        tracee.regs.set_sys_num(sc::nr::UTIMENSAT, "android-compat: futimesat->utimensat");
                                        tracee.regs.set(SysArg(SysArg4), 0, "flags=0");
                                        tracee.regs.set(SysArg(SysArg3), ts_ptr as u64, "timespec*");
                                    }
                                }
                                // select -> pselect6 (convert timeval to timespec)
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
                                x if x == sc::nr::SELECT => {
                                    debug!("android-compat: remap select -> pselect6");
                                    crate::android_log::log_remap(sc::nr::SELECT, sc::nr::PSELECT6, "select->pselect6", tracee.pid.as_raw());
                                    use std::mem::size_of;
                                    let tv_ptr = tracee.regs.get(Current, SysArg(SysArg5)) as *mut libc::c_void;
                                    let ts_ptr = if tv_ptr.is_null() { 0 } else {
                                        let mut buf = vec![0u8; size_of::<libc::timeval>()];
                                        let word_size = size_of::<crate::register::Word>();
                                        let nb_words = (buf.len() + word_size - 1) / word_size;
                                        for i in 0..nb_words {
                                            let src = unsafe { (tv_ptr as *mut crate::register::Word).offset(i as isize) } as *mut libc::c_void;
                                            let w = nix::sys::ptrace::read(tracee.regs.get_pid(), src)? as crate::register::Word;
                                            let bytes = crate::register::reader::convert_word_to_bytes(w);
                                            let start = i * word_size;
                                            let end = std::cmp::min(start + word_size, buf.len());
                                            buf[start..end].copy_from_slice(&bytes[..end - start]);
                                        }
                                        let tv: libc::timeval = unsafe { std::ptr::read(buf.as_ptr() as *const libc::timeval) };
                                        let ts = libc::timespec { tv_sec: tv.tv_sec, tv_nsec: tv.tv_usec * 1000 };
                                        let ts_bytes = unsafe { std::slice::from_raw_parts((&ts as *const libc::timespec) as *const u8, size_of::<libc::timespec>()) };
                                        tracee.regs.allocate_and_write(ts_bytes, false)? as u64
                                    };
                                    tracee.regs.set_sys_num(sc::nr::PSELECT6, "android-compat: select->pselect6");
                                    tracee.regs.set(SysArg(SysArg6), 0, "sigmask=NULL");
                                    tracee.regs.set(SysArg(SysArg5), ts_ptr as u64, "timespec*");
                                }
                                // _newselect -> pselect6 (same as select)
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
                                x if x == sc::nr::NEWSELECT => {
                                    debug!("android-compat: remap _newselect -> pselect6");
                                    crate::android_log::log_remap(sc::nr::NEWSELECT, sc::nr::PSELECT6, "_newselect->pselect6", tracee.pid.as_raw());
                                    use std::mem::size_of;
                                    let tv_ptr = tracee.regs.get(Current, SysArg(SysArg5)) as *mut libc::c_void;
                                    let ts_ptr = if tv_ptr.is_null() { 0 } else {
                                        let mut buf = vec![0u8; size_of::<libc::timeval>()];
                                        let word_size = size_of::<crate::register::Word>();
                                        let nb_words = (buf.len() + word_size - 1) / word_size;
                                        for i in 0..nb_words {
                                            let src = unsafe { (tv_ptr as *mut crate::register::Word).offset(i as isize) } as *mut libc::c_void;
                                            let w = nix::sys::ptrace::read(tracee.regs.get_pid(), src)? as crate::register::Word;
                                            let bytes = crate::register::reader::convert_word_to_bytes(w);
                                            let start = i * word_size;
                                            let end = std::cmp::min(start + word_size, buf.len());
                                            buf[start..end].copy_from_slice(&bytes[..end - start]);
                                        }
                                        let tv: libc::timeval = unsafe { std::ptr::read(buf.as_ptr() as *const libc::timeval) };
                                        let ts = libc::timespec { tv_sec: tv.tv_sec, tv_nsec: tv.tv_usec * 1000 };
                                        let ts_bytes = unsafe { std::slice::from_raw_parts((&ts as *const libc::timespec) as *const u8, size_of::<libc::timespec>()) };
                                        tracee.regs.allocate_and_write(ts_bytes, false)? as u64
                                    };
                                    tracee.regs.set_sys_num(sc::nr::PSELECT6, "android-compat: _newselect->pselect6");
                                    tracee.regs.set(SysArg(SysArg6), 0, "sigmask=NULL");
                                    tracee.regs.set(SysArg(SysArg5), ts_ptr as u64, "timespec*");
                                }
                                // poll -> ppoll (convert timeout ms to timespec)
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
                                x if x == sc::nr::POLL => {
                                    debug!("android-compat: remap poll -> ppoll");
                                    crate::android_log::log_remap(sc::nr::POLL, sc::nr::PPOLL, "poll->ppoll", tracee.pid.as_raw());
                                    let timeout_ms = tracee.regs.get(Current, SysArg(SysArg3)) as i64;
                                    if timeout_ms < 0 {
                                        tracee.regs.set(SysArg(SysArg3), 0, "timespec=NULL");
                                    } else {
                                        let ts = libc::timespec { tv_sec: timeout_ms / 1000, tv_nsec: (timeout_ms % 1000) * 1_000_000 };
                                        let ts_bytes = unsafe { std::slice::from_raw_parts((&ts as *const libc::timespec) as *const u8, std::mem::size_of::<libc::timespec>()) };
                                        let ts_ptr = tracee.regs.allocate_and_write(ts_bytes, false)?;
                                        tracee.regs.set(SysArg(SysArg3), ts_ptr as u64, "timespec*");
                                    }
                                    tracee.regs.set_sys_num(sc::nr::PPOLL, "android-compat: poll->ppoll");
                                    tracee.regs.set(SysArg(SysArg4), 0, "sigmask=NULL");
                                    tracee.regs.set(SysArg(SysArg5), 0, "sigsetsize=0");
                                }
                                // epoll_wait -> epoll_pwait
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
                                x if x == sc::nr::EPOLL_WAIT => {
                                    debug!("android-compat: remap epoll_wait -> epoll_pwait");
                                    crate::android_log::log_remap(sc::nr::EPOLL_WAIT, sc::nr::EPOLL_PWAIT, "epoll_wait->epoll_pwait", tracee.pid.as_raw());
                                    tracee.regs.set_sys_num(sc::nr::EPOLL_PWAIT, "android-compat: epoll_wait->epoll_pwait");
                                    tracee.regs.set(SysArg(SysArg5), 0, "sigmask=NULL");
                                    tracee.regs.set(SysArg(SysArg6), 0, "sigsetsize=0");
                                }
                                // NOTE: Legacy syscalls like open/chmod/chown/unlink/access/mkdir/rename do not
                                // exist on aarch64, so no remapping is attempted for them here.
                                _ => {}
                            }
                            Ok(())
                        })() {
                            debug!("android-compat: SIGSYS rewrite skipped: {}", e);
                        }
                            }
                        }
                        Signal::SIGTRAP => {
                            // Since PTRACE_O_TRACESYSGOOD is not supported on older versions of
                            // Linux (version<2.4.6) and some architectures, we need to use
                            // PTRACE_GETSIGINFO to distinguish a real syscall-stop from
                            // signal-delivery-stop on these devices.
                            // NOTE: this may be somewhat expensive.
                            // See ptrace(2): Syscall-stops
                            if let Ok(siginfo) = ptrace::getsiginfo(pid) {
                                if siginfo.si_code == Signal::SIGTRAP as i32
                                    || siginfo.si_code == (Signal::SIGTRAP as i32 | 0x80)
                                {
                                    tracee.handle_syscall_stop_event(
                                        &mut self.info_bag,
                                        #[cfg(test)]
                                        &self.func_syscall_hook,
                                    );
                                }
                            }
                        }
                        _ => {}
                    }

                    // ptrace(2): If the tracer doesn't suppress the signal, it passes the signal to
                    // the tracee in the next ptrace restart request.
                    // TODO: we should deliver this signal(sig) with ptrace(PTRACE_restart, pid, 0,
                    // sig)
                    tracee.restart(signal_to_delivery);
                }
                // The tracee was stopped by a SIGTRAP with additional status (PTRACE_EVENT stops).
                PtraceEvent(pid, signal, status_additional) => {
                    let maybe_event = match status_additional {
                        x if x == PtraceEvent::PTRACE_EVENT_FORK as i32 => {
                            Some(PtraceEvent::PTRACE_EVENT_FORK)
                        }
                        x if x == PtraceEvent::PTRACE_EVENT_VFORK as i32 => {
                            Some(PtraceEvent::PTRACE_EVENT_VFORK)
                        }
                        x if x == PtraceEvent::PTRACE_EVENT_CLONE as i32 => {
                            Some(PtraceEvent::PTRACE_EVENT_CLONE)
                        }
                        x if x == PtraceEvent::PTRACE_EVENT_EXEC as i32 => {
                            Some(PtraceEvent::PTRACE_EVENT_EXEC)
                        }
                        x if x == PtraceEvent::PTRACE_EVENT_VFORK_DONE as i32 => {
                            Some(PtraceEvent::PTRACE_EVENT_VFORK_DONE)
                        }
                        x if x == PtraceEvent::PTRACE_EVENT_EXIT as i32 => {
                            Some(PtraceEvent::PTRACE_EVENT_EXIT)
                        }
                        x if x == PtraceEvent::PTRACE_EVENT_SECCOMP as i32 => {
                            Some(PtraceEvent::PTRACE_EVENT_SECCOMP)
                        }
                        _ => None,
                    };

                    trace!("-- {}, Ptrace event, {:?}, {:?}", pid, signal, maybe_event);
                    let tracee = self.tracees.get_mut(&pid).expect("get stopped tracee");
                    tracee.reset_restart_how();

                    match maybe_event {
                        // handle_new_child_event
                        Some(PtraceEvent::PTRACE_EVENT_FORK)
                        | Some(PtraceEvent::PTRACE_EVENT_VFORK)
                        | Some(PtraceEvent::PTRACE_EVENT_CLONE) => {
                            match tracee.handle_new_child_event() {
                                Ok(mut child_tracee) => {
                                    info!("-- {}, new process with pid {}", pid, child_tracee.pid);
                                    // If a placeholder exists, replace it with fully initialized
                                    // tracee.
                                    if let Some(tracee_placeholder) =
                                        self.tracees.get(&child_tracee.pid)
                                    {
                                        if tracee_placeholder.sigstop_status
                                            == SigStopStatus::WaitForEventClone
                                        {
                                            child_tracee.sigstop_status =
                                                SigStopStatus::AllowDelivery;
                                        }
                                    }
                                    self.insert_new_tracee(child_tracee)
                                }
                                Err(error) => {
                                    error!(
                                    "Error while handling new child process event for pid {}. {}",
                                    tracee.pid, error
                                );
                                }
                            }
                        }
                        // handle_exec_vfork_event
                        Some(PtraceEvent::PTRACE_EVENT_EXEC)
                        | Some(PtraceEvent::PTRACE_EVENT_VFORK_DONE) => {
                            tracee.handle_exec_vfork_event();
                        }
                        // handle_seccomp_event
                        Some(PtraceEvent::PTRACE_EVENT_SECCOMP) => {
                            // TODO: consider PTRACE_EVENT_SECCOMP2
                            tracee.handle_seccomp_event(
                                &mut self.info_bag,
                                PtraceEvent::PTRACE_EVENT_SECCOMP,
                            )
                        }
                        Some(_) | None => {}
                    };
                    // Re-acquire tracee as we cannot borrow `*self` as mutable more than once at a
                    // time in rust.
                    let tracee = self.tracees.get_mut(&pid).expect("get stopped tracee");
                    tracee.restart(None);
                }
                // The tracee was stopped by execution of a system call (syscall-stop), and
                // PTRACE_O_TRACESYSGOOD was effect. PTRACE_O_TRACESYSGOOD is used to make it
                // easy for the tracer to distinguish syscall-stop from signal-delivery-stop.
                PtraceSyscall(pid) => {
                    trace!("-- {}, Syscall", pid);
                    let tracee = self.tracees.get_mut(&pid).expect("get stopped tracee");
                    tracee.reset_restart_how();
                    tracee.handle_syscall_stop_event(
                        &mut self.info_bag,
                        #[cfg(test)]
                        &self.func_syscall_hook,
                    );
                    tracee.restart(None);
                }
                Continued(pid) => {
                    trace!("-- {}, Continued", pid);
                }
                StillAlive => {
                    trace!("-- Still alive");
                }
            }
        }

        Ok(())
    }

    pub fn create_tracee(
        &mut self,
        pid: Pid,
        fs: Rc<RefCell<FileSystem>>,
        sigstop_status: SigStopStatus,
    ) -> Option<&Tracee> {
        let mut tracee = Tracee::new(pid, fs);
        tracee.sigstop_status = sigstop_status;
        self.tracees.insert(pid, tracee);
        self.register_alive_tracee(pid);
        self.tracees.get(&pid)
    }

    pub fn insert_new_tracee(&mut self, tracee: Tracee) {
        let pid = tracee.pid;
        self.tracees.insert(pid, tracee);
        self.register_alive_tracee(pid);
    }

    fn register_alive_tracee(&mut self, pid: Pid) {
        self.alive_tracees.push(pid);
    }

    fn register_tracee_finished(&mut self, finished_pid: Pid) {
        self.alive_tracees.retain(|pid| *pid != finished_pid);
        self.tracees.remove(&finished_pid);
    }
}

/// Proot has received a fatal error from one of the tracee,
/// and must therefore stop the program's execution.
pub extern "C" fn stop_program(sig_num: c_int, _: *mut siginfo_t, _: *mut c_void) {
    let signal = Signal::try_from(sig_num);
    panic!("abnormal signal received: {:?}", signal);
}

pub extern "C" fn show_info(pid: pid_t) {
    println!("showing info pid {}", pid);
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use nix::unistd::Pid;

    #[test]
    fn create_proot_and_tracee() {
        let fs = FileSystem::new();
        let mut proot = PRoot::new();

        // tracee 0 shouldn't exist
        {
            let tracee = proot.tracees.get_mut(&Pid::from_raw(0));
            assert!(tracee.is_none());
        }

        {
            proot.create_tracee(
                Pid::from_raw(0),
                Rc::new(RefCell::new(fs)),
                SigStopStatus::AllowDelivery,
            );
        }

        // tracee 0 should exist
        {
            let tracee = proot.tracees.get_mut(&Pid::from_raw(0));
            assert!(tracee.is_some());
        }
    }
}
