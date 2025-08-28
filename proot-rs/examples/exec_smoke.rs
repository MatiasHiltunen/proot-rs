// Minimal exec smoke: replace current process image with a simple shell command.
// Under proot on Android, the exec path may use a loader shim or trampoline; we
// simply assert that exec completes successfully by exiting with code 0.

use std::ffi::CString;

fn main() {
    // Allow override of target via env (guest path).
    let target = std::env::var("PROOT_EXEC_TARGET").unwrap_or_else(|_| "/bin/sh".to_string());
    let arg0 = std::env::var("PROOT_EXEC_ARG0").unwrap_or_else(|_| "sh".to_string());
    let arg1 = std::env::var("PROOT_EXEC_ARG1").unwrap_or_else(|_| "-c".to_string());
    let arg2 = std::env::var("PROOT_EXEC_ARG2").unwrap_or_else(|_| "true".to_string());

    let prog = CString::new(target).unwrap();
    let a0 = CString::new(arg0).unwrap();
    let a1 = CString::new(arg1).unwrap();
    let a2 = CString::new(arg2).unwrap();
    // Build a null-terminated argv array as required by execv(3)
    let mut argv: Vec<*const libc::c_char> = Vec::with_capacity(5);
    argv.push(a0.as_ptr());
    argv.push(a1.as_ptr());
    argv.push(a2.as_ptr());
    argv.push(std::ptr::null());

    unsafe {
        let rc = libc::execv(prog.as_ptr(), argv.as_ptr());
        // If execv returns, it failed; print errno and exit non-zero.
        eprintln!("execv failed rc={} errno={}", rc, std::io::Error::last_os_error());
        std::process::exit(111);
    }
}
