// Exercise a set of *at syscalls to validate guest→host path translation under proot.
// Operations:
// - mkdir("/tmp/at_smoke")
// - dirfd = open("/tmp/at_smoke", O_RDONLY|O_DIRECTORY)
// - openat(dirfd, "file", O_CREAT|O_WRONLY, 0644); write; close
// - symlinkat("file", dirfd, "link")
// - readlinkat(dirfd, "link") == "file"
// - renameat(dirfd, "file", dirfd, "file2")
// - unlinkat(dirfd, "link", 0)
// - unlinkat(dirfd, "file2", 0)

use std::ffi::CString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;

fn main() -> io::Result<()> {
    unsafe {
        let base = CString::new("/tmp/at_smoke").unwrap();
        // Ignore EEXIST
        let _ = libc::mkdir(base.as_ptr(), 0o755);

        let dirfd = libc::open(base.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0);
        if dirfd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Create file via openat
        let name_file = CString::new("file").unwrap();
        let fd = libc::openat(
            dirfd,
            name_file.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }
        let buf = b"hello";
        let wrote = libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
        if wrote < 0 || wrote as usize != buf.len() {
            let _ = libc::close(fd);
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }
        let _ = libc::close(fd);

        // symlinkat("file" -> "link")
        let name_link = CString::new("link").unwrap();
        let target = CString::new("file").unwrap();
        if libc::symlinkat(target.as_ptr(), dirfd, name_link.as_ptr()) < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }

        // readlinkat("link") -> should be "file"
        let mut buf2 = [0u8; 256];
        let n = libc::readlinkat(
            dirfd,
            name_link.as_ptr(),
            buf2.as_mut_ptr() as *mut libc::c_char,
            buf2.len(),
        );
        if n < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }
        let got = &buf2[..(n as usize)];
        if got != b"file" {
            let _ = libc::close(dirfd);
            let mut stderr = io::stderr();
            let _ = writeln!(stderr, "readlinkat returned {:?}", got);
            return Err(io::Error::new(io::ErrorKind::Other, "readlinkat mismatch"));
        }

        // renameat("file" -> "file2")
        let name_file2 = CString::new("file2").unwrap();
        if libc::renameat(dirfd, name_file.as_ptr(), dirfd, name_file2.as_ptr()) < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }

        // unlinkat("link") and unlinkat("file2")
        if libc::unlinkat(dirfd, name_link.as_ptr(), 0) < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }
        if libc::unlinkat(dirfd, name_file2.as_ptr(), 0) < 0 {
            let _ = libc::close(dirfd);
            return Err(io::Error::last_os_error());
        }

        let _ = libc::close(dirfd);
    }
    Ok(())
}

