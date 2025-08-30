use std::cell::RefCell;
use std::rc::Rc;

use crate::errors::*;
use std::os::unix::ffi::OsStrExt;
use crate::kernel::execve::binfmt;
use crate::kernel::execve::loader::LoaderFile;
use crate::kernel::execve::params::{self, ExecveParameters};
use crate::process::tracee::Tracee;
use crate::register::PtraceWriter;
use crate::register::{Current, PtraceReader, SysArg, SysArg1, SysArg2};
use crate::register::SysArgIndex::SysArg3;

pub fn translate(tracee: &mut Tracee, loader: &dyn LoaderFile) -> Result<()> {
    //TODO: implement this part for ptrace translation
    //	if (IS_NOTIFICATION_PTRACED_LOAD_DONE(tracee)) {
    //		/* Syscalls can now be reported to its ptracer.  */
    //		tracee->as_ptracee.ignore_loader_syscalls = false;
    //
    //		/* Cancel this spurious kernel.execve, it was only used as a
    // 		 * notification.  */
    //		set_sysnum(tracee, PR_void);
    //		return 0;
    //	}

    // Read required values from tracee (support EXECVE and EXECVEAT)
    let sysnum = tracee.regs.get_sys_num(Current);
    let (path_arg, argv_arg) = if sysnum == sc::nr::EXECVEAT {
        // execveat(dirfd, pathname, argv, envp, flags)
        (SysArg(SysArg2), SysArg(SysArg3))
    } else {
        // execve(filename, argv, envp)
        (SysArg(SysArg1), SysArg(SysArg2))
    };

    let raw_guest_path = tracee.regs.get_sysarg_path(match path_arg { SysArg(i) => i, _ => unreachable!() })?;
    let argv_addr = tracee.regs.get(Current, argv_arg);
    let argv = params::read_argv(tracee.pid, argv_addr as _)?;

    // Android/Termux compatibility: If the tracee is intentionally invoking the
    // system linker as a trampoline (e.g., `/system/bin/linker64 /data/.../sh`),
    // then skip injecting our loader shim and allow the exec to proceed
    // untouched. This is necessary to let the first exec succeed under app-data
    // execute restrictions on Android.
    #[cfg(target_os = "android")]
    {
        use std::borrow::Cow;
        let s: Cow<str> = raw_guest_path.to_string_lossy();
        if s.starts_with("/system/bin/linker") {
            return Ok(());
        }
    }

    //TODO: implement runner for qemu
    //	if (tracee->qemu != NULL) {
    //		status = expand_runner(tracee, host_path, user_path);
    //		if (status < 0)
    //			return status;
    //	}

    let mut parameters = ExecveParameters {
        raw_guest_path: raw_guest_path.clone(),
        canonical_guest_path: Default::default(),
        host_path: Default::default(),
        argv: argv,
    };

    debug!("execve.enter: raw_guest_path={:?}", raw_guest_path);
    // Android: proceed with loader injection (same flow as non-Android), except
    // when the system linker is being invoked explicitly (handled above).

    // Try to parse and load this executable (non-Android flow)
    let load_info = binfmt::load(&tracee.fs.borrow(), &mut parameters)
        .with_context(|| format!("failed to load file {:?}", raw_guest_path))?;

    tracee.new_exe = Some(Rc::new(RefCell::new(parameters.host_path)));
    tracee.load_info = Some(load_info);

    // Save the loader path in the register, so that the loader will be executed
    // instead.
    tracee.regs.set_sysarg_path(
        SysArg1,
        loader.get_loader_path(),
        "during enter execve translation, setting new loader path",
    )?;
    // Update argv of `execve()`
    params::write_argv(tracee, &parameters.argv)
        .map(|addr| {
            tracee.regs.set(
                SysArg(SysArg2),
                addr as _,
                "during enter execve translation, setting new argv",
            )
        })
        .errno(EFAULT)
        .context("failed to write new argv into tracee's memory space")?;

    //TODO: implemented ptracee translation
    //	/* Mask to its ptracer kernel performed by the loader.  */
    //	tracee->as_ptracee.ignore_loader_syscalls = true;
    //
    //	return 0;

    Ok(())
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use crate::utils::tests::fork_test;
    use crate::{
        register::{Current, Original, PtraceReader},
        utils::tests::get_test_rootfs_path,
    };
    use nix::unistd::execvp;
    use sc::nr::{CLOCK_NANOSLEEP, EXECVE, NANOSLEEP};
    use std::ffi::CString;

    #[test]
    fn test_execve_translate_enter() {
        let rootfs_path = get_test_rootfs_path();
        let mut at_least_one_translation_occured = false;

        fork_test(
            rootfs_path,
            // expecting a normal execution
            0,
            // parent
            |tracee, info_bag| {
                tracee.regs.save_current_regs(Original);
                if tracee.regs.get_sys_num(Current) == EXECVE {
                    let dir_path = tracee.regs.get_sysarg_path(SysArg1).unwrap();
                    let file_exists = dir_path.exists();

                    // if the file executed by execve exists, we expect the translation to go well.
                    if file_exists {
                        assert_eq!(Ok(()), translate(tracee, &info_bag.loader));
                        at_least_one_translation_occured = true;
                    }
                    false
                } else if tracee.regs.get_sys_num(Current) == NANOSLEEP
                    || tracee.regs.get_sys_num(Current) == CLOCK_NANOSLEEP
                {
                    // we expect at least one successful translation to have occurred
                    assert!(at_least_one_translation_occured);

                    // we stop when the NANOSLEEP syscall is detected
                    true
                } else {
                    false
                }
            },
            // child
            || {
                // calling the sleep function, which should call the NANOSLEEP syscall
                execvp(
                    &CString::new("/bin/sleep").unwrap(),
                    &[CString::new(".").unwrap(), CString::new("0").unwrap()],
                )
                .expect("failed execvp sleep");
            },
        );
    }
}
