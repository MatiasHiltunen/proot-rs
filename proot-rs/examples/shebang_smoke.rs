// Create and exec a simple shebang script inside the guest to validate
// exec path and interpreter resolution under proot.

use std::ffi::CString;
use std::io::{self, Write};

fn main() -> io::Result<()> {
    // Guest path for the script
    let guest_path = "/tmp/proot_shebang_smoke.sh";
    // Use a common interpreter inside guest
    let shebang = b"#!/bin/sh\nexit 0\n";

    // Create the script
    std::fs::write(guest_path, shebang)?;
    // Chmod +x
    let cpath = CString::new(guest_path).unwrap();
    unsafe {
        if libc::chmod(cpath.as_ptr(), 0o755) < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // Exec it directly
    let prog = CString::new(guest_path).unwrap();
    // argv: [path, NULL]
    let argv: [*const libc::c_char; 2] = [prog.as_ptr(), std::ptr::null()];
    unsafe {
        let rc = libc::execv(prog.as_ptr(), argv.as_ptr());
        eprintln!("execv failed rc={} errno={}", rc, io::Error::last_os_error());
        std::process::exit(111);
    }
}

