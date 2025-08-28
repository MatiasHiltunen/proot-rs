// Small program to exercise legacy syscalls that our Android-compat layer remaps
// under SIGSYS. It is architecture-aware so it can run on Termux too.
//
// Run under proot-rs with debug logging to observe remaps, e.g.:
//   RUST_LOG=debug PROOT_ANDROID_COMPAT=1 cargo run -- -r <rootfs> -- \ 
//     $(cargo run --quiet --package proot-rs --example remap_smoke -- --print-cmd)
// or simply run the example binary inside your proot guest.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

fn do_select() {
    unsafe {
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 10_000 }; // 10ms
        // nfds=0, NULL fd sets — just a timeout
        let rc = libc::select(0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut tv);
        eprintln!("select rc={}", rc);
    }
}

fn do_poll() {
    unsafe {
        // nfds=0, timeout=5ms; exercises poll timeout path
        let rc = libc::poll(std::ptr::null_mut(), 0, 5);
        eprintln!("poll rc={}", rc);
    }
}

fn do_utimes(tmpfile: &std::path::Path) {
    unsafe {
        let tv = [
            libc::timeval { tv_sec: 1, tv_usec: 2 },
            libc::timeval { tv_sec: 3, tv_usec: 4 },
        ];
        let cpath = CString::new(tmpfile.as_os_str().as_bytes()).unwrap();
        let rc = libc::utimes(cpath.as_ptr(), tv.as_ptr());
        eprintln!("utimes rc={}", rc);
    }
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
fn do_statfs_android() {
    unsafe {
        let cpath = CString::new("/").unwrap();
        let mut st: libc::statfs = std::mem::zeroed();
        let rc = libc::statfs(cpath.as_ptr(), &mut st as *mut _);
        eprintln!("statfs rc={}", rc);
    }
}

fn main() {
    // Optional helper: if invoked as `--print-cmd`, emit a shell snippet to execute inside proot.
    if std::env::args().any(|a| a == "--print-cmd") {
        // Print the absolute path to this example binary so the outer proot can execute it.
        // In many setups, running the example outside and passing command to proot is simpler.
        let me = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"));
        println!("{}", me.display());
        return;
    }

    // Create a temp file for utimes, when available.
    let tmp = std::env::temp_dir().join("remap_smoke.tmp");
    std::fs::write(&tmp, b"x").ok();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
    {
        do_select();
        do_poll();
        do_utimes(&tmp);
    }

    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        // On Android aarch64, legacy syscalls don’t exist; exercise a handled case instead.
        do_statfs_android();
    }

    let _ = std::fs::remove_file(&tmp);
}
