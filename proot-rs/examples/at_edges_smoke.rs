// Edge-case exercises for *at syscalls focusing on O_NOFOLLOW semantics and faccessat.
// - Prepare /tmp/at_edges_smoke in guest
// - open dirfd
// - symlinkat("target" -> "link") before creating target
// - openat(dirfd, "link", O_NOFOLLOW|O_PATH) must succeed and be a symlink
// - create target and check faccessat(dirfd, "target", F_OK)
// - cleanup

use std::ffi::CString;
use std::io;

fn main() -> io::Result<()> {
    unsafe {
        let base = CString::new("/tmp/at_edges_smoke").unwrap();
        let _ = libc::mkdir(base.as_ptr(), 0o755);
        let dirfd = libc::open(base.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0);
        if dirfd < 0 { return Err(io::Error::last_os_error()); }

        let link = CString::new("link").unwrap();
        let target = CString::new("target").unwrap();

        // Create symlink before target exists
        if libc::symlinkat(target.as_ptr(), dirfd, link.as_ptr()) < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }

        // Open symlink with O_NOFOLLOW|O_PATH
        let lfd = libc::openat(dirfd, link.as_ptr(), libc::O_NOFOLLOW | libc::O_PATH, 0);
        if lfd < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }
        // Verify it's a symlink
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(lfd, &mut st as *mut _) < 0 {
            let _ = libc::close(lfd);
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }
        if (st.st_mode as libc::mode_t & libc::S_IFMT) != libc::S_IFLNK {
            let _ = libc::close(lfd);
            let _ = libc::close(dirfd);
            return Err(io::Error::new(io::ErrorKind::Other, "link not S_IFLNK"));
        }
        let _ = libc::close(lfd);

        // Create target file now
        let tfd = libc::openat(
            dirfd,
            target.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644,
        );
        if tfd < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }
        let _ = libc::close(tfd);

        // faccessat for target
        if libc::faccessat(dirfd, target.as_ptr(), libc::F_OK, 0) < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }

        // Cleanup
        let _ = libc::unlinkat(dirfd, link.as_ptr(), 0);
        let _ = libc::unlinkat(dirfd, target.as_ptr(), 0);
        let _ = libc::close(dirfd);
    }
    Ok(())
}

