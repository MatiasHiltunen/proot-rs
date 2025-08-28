// Attempt to use newer at-family syscalls (faccessat2, renameat2) if available;
// otherwise fall back to older counterparts. Validates that proot path mapping
// and Android compat do not break these flows.

use std::ffi::CString;
use std::io;

extern "C" {
    fn syscall(num: libc::c_long, ...) -> libc::c_long;
}

fn try_faccessat2(dirfd: libc::c_int, path: &CString) -> io::Result<()> {
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    unsafe {
        // Prefer AT_EACCESS flag path; if unsupported, fall back to 0
        const AT_EACCESS: libc::c_int = 0x200;
        let rc = syscall(sc::nr::FACCESSAT2 as _, dirfd, path.as_ptr(), libc::F_OK, AT_EACCESS);
        if rc == 0 { return Ok(()); }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOSYS) {
            // Fallback to faccessat
            if libc::faccessat(dirfd, path.as_ptr(), libc::F_OK, 0) == 0 { return Ok(()); }
            return Err(io::Error::last_os_error());
        }
        return Err(e);
    }
    #[allow(unreachable_code)]
    Ok(())
}

fn try_renameat2(dirfd: libc::c_int, old: &CString, newp: &CString) -> io::Result<()> {
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    unsafe {
        // For the main rename, use flags=0; then do a negative test with RENAME_NOREPLACE
        let rc = syscall(sc::nr::RENAMEAT2 as _, dirfd, old.as_ptr(), dirfd, newp.as_ptr(), 0);
        if rc == 0 { return Ok(()); }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOSYS) {
            if libc::renameat(dirfd, old.as_ptr(), dirfd, newp.as_ptr()) == 0 { return Ok(()); }
            return Err(io::Error::last_os_error());
        }
        return Err(e);
    }
    #[allow(unreachable_code)]
    Ok(())
}

fn main() -> io::Result<()> {
    unsafe {
        let base = CString::new("/tmp/at_new_smoke").unwrap();
        let _ = libc::mkdir(base.as_ptr(), 0o755);
        let dirfd = libc::open(base.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0);
        if dirfd < 0 { return Err(io::Error::last_os_error()); }

        // Create a file "a"
        let a = CString::new("a").unwrap();
        let afd = libc::openat(dirfd, a.as_ptr(), libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC, 0o644);
        if afd < 0 { let _ = libc::close(dirfd); return Err(io::Error::last_os_error()); }
        let _ = libc::close(afd);

        // faccessat2 or fallback
        try_faccessat2(dirfd, &a)?;

        // renameat2 or fallback: a -> b
        let b = CString::new("b").unwrap();
        try_renameat2(dirfd, &a, &b)?;

        // Negative test: renameat2(b -> b) with RENAME_NOREPLACE should fail with EEXIST if supported
        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        unsafe {
            let e = syscall(sc::nr::RENAMEAT2 as _, dirfd, b.as_ptr(), dirfd, b.as_ptr(), 1 /* RENAME_NOREPLACE */);
            if e == 0 {
                // Unexpected success; clean up and error
                let _ = libc::unlinkat(dirfd, b.as_ptr(), 0);
                let _ = libc::close(dirfd);
                return Err(io::Error::new(io::ErrorKind::Other, "renameat2 noreplace unexpectedly succeeded"));
            }
        }

        // Cleanup
        let _ = libc::unlinkat(dirfd, b.as_ptr(), 0);
        let _ = libc::close(dirfd);
    }
    Ok(())
}
