// Small example that exercises an `accept(2)` call so the Android-compat layer
// can remap it to `accept4(2)` if a SIGSYS occurs under seccomp.
//
// By default this uses an AF_UNIX abstract socket (Linux/Android: sun_path[0]=0)
// to avoid network policy issues on devices and CI. To try a TCP loopback
// variant instead, set PROOT_ENABLE_TCP_SMOKE=1 in the environment.
//
// Run under proot-rs with debug logging to observe any remap:
//   RUST_LOG=debug PROOT_ANDROID_COMPAT=1 \
//     cargo run --package=proot-rs -- -r <rootfs> -- \
//     target/debug/examples/accept_smoke

use std::io;
use std::mem;
use std::os::unix::io::RawFd;

fn set_reuseaddr(fd: RawFd) {
    let yes: libc::c_int = 1;
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &yes as *const _ as *const libc::c_void,
            mem::size_of_val(&yes) as libc::socklen_t,
        );
    }
}

fn run_unix_accept() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 { return Err(io::Error::last_os_error()); }

        let mut addr: libc::sockaddr_un = mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        // Abstract namespace name: first byte 0, then unique suffix
        let pid = std::process::id();
        let suffix = format!("proot_rs_accept_smoke_{}", pid);
        let name = [&[0u8][..], suffix.as_bytes()].concat();
        let max = addr.sun_path.len();
        let n = std::cmp::min(name.len(), max);
        for i in 0..n { addr.sun_path[i] = name[i] as libc::c_char; }
        let len = (std::mem::size_of::<libc::sa_family_t>() + n) as libc::socklen_t;

        let rc = libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            len,
        );
        if rc < 0 { let _ = libc::close(fd); return Err(io::Error::last_os_error()); }
        if libc::listen(fd, 1) < 0 { let _ = libc::close(fd); return Err(io::Error::last_os_error()); }

        // Spawn a connector
        let addr_conn = addr;
        std::thread::spawn(move || {
            unsafe {
                let cfd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if cfd >= 0 {
                    let _ = libc::connect(
                        cfd,
                        &addr_conn as *const _ as *const libc::sockaddr,
                        len,
                    );
                    let _ = libc::close(cfd);
                }
            }
        });

        // Accept
        let mut cli: libc::sockaddr_un = mem::zeroed();
        let mut cli_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        let afd = libc::accept(
            fd,
            &mut cli as *mut _ as *mut libc::sockaddr,
            &mut cli_len as *mut _,
        );
        if afd < 0 { eprintln!("accept(unix) rc={} err={:?}", afd, io::Error::last_os_error()); }
        else { eprintln!("accept(unix) rc={} ok", afd); }
        if afd >= 0 { let _ = libc::close(afd); }
        let _ = libc::close(fd);
    }
    Ok(())
}

fn run_tcp_accept() -> io::Result<()> {
    unsafe {
        // Create a TCP IPv4 socket
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 { return Err(io::Error::last_os_error()); }
        set_reuseaddr(fd);

        // Bind to 127.0.0.1:0 (ephemeral port)
        let mut addr: libc::sockaddr_in = mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr = libc::in_addr { s_addr: u32::from_be_bytes([127,0,0,1]) };
        addr.sin_port = 0u16.to_be();
        let rc = libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if rc < 0 { let _ = libc::close(fd); return Err(io::Error::last_os_error()); }

        // Query chosen port
        let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let mut bound: libc::sockaddr_in = mem::zeroed();
        let rc = libc::getsockname(
            fd,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut len as *mut _,
        );
        if rc < 0 { let _ = libc::close(fd); return Err(io::Error::last_os_error()); }

        // Listen
        if libc::listen(fd, 1) < 0 { let _ = libc::close(fd); return Err(io::Error::last_os_error()); }

        // Spawn a connector to trigger accept
        let port_be = bound.sin_port;
        std::thread::spawn(move || {
            let cfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if cfd >= 0 {
                let mut to: libc::sockaddr_in = unsafe { mem::zeroed() };
                to.sin_family = libc::AF_INET as libc::sa_family_t;
                to.sin_addr = libc::in_addr { s_addr: u32::from_be_bytes([127,0,0,1]) };
                to.sin_port = port_be;
                let _ = unsafe {
                    libc::connect(
                        cfd,
                        &to as *const _ as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
                let _ = unsafe { libc::close(cfd) };
            }
        });

        // Call accept and print result
        let mut cli: libc::sockaddr_in = mem::zeroed();
        let mut cli_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let afd = libc::accept(
            fd,
            &mut cli as *mut _ as *mut libc::sockaddr,
            &mut cli_len as *mut _,
        );
        if afd < 0 { eprintln!("accept(tcp) rc={} err={:?}", afd, io::Error::last_os_error()); }
        else { eprintln!("accept(tcp) rc={} ok", afd); }
        if afd >= 0 { let _ = libc::close(afd); }
        let _ = libc::close(fd);
    }
    Ok(())
}

fn main() -> io::Result<()> {
    if std::env::var_os("PROOT_ENABLE_TCP_SMOKE").is_some() {
        run_tcp_accept()
    } else {
        run_unix_accept()
    }
}

