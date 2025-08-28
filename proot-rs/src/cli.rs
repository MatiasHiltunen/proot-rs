use clap::{crate_version, App, Arg};

use crate::errors::*;
use crate::filesystem::validation::{binding_validator, path_validator};
use crate::filesystem::FileSystem;

pub const DEFAULT_ROOTFS: &'static str = "/";
pub const DEFAULT_CWD: &'static str = "/";

pub fn get_args_parser() -> App<'static, 'static> {
    App::new("proot-rs")
        .about("chroot, mount --bind, and binfmt_misc without privilege/setup.")
        .version(crate_version!())
        .arg(Arg::with_name("rootfs")
            .short("r")
            .long("rootfs")
            .help("Use *path* as the new guest root file-system.")
            .takes_value(true)
            .default_value(DEFAULT_ROOTFS)
            .validator(path_validator))
        .arg(Arg::with_name("bind")
            .short("b")
            .long("bind")
            .help("Make the content of *host_path* accessible in the guest rootfs. Format: host_path:guest_path")
            .multiple(true)
            .takes_value(true)
            .validator(binding_validator))
        .arg(Arg::with_name("cwd")
            .short("w")
            .long("cwd")
            .help("Set the initial working directory to *path*.")
            .takes_value(true)
            .default_value(DEFAULT_CWD))
        .arg(Arg::with_name("command")
            .multiple(true))
        // Android compatibility mode: swallow SIGSYS to avoid tracee kills
        // under Android's seccomp policies. Enabled by default on Android.
        .arg(Arg::with_name("android-compat")
            .long("android-compat")
            .help("Enable Android compatibility mode (swallow SIGSYS)."))
        .arg(Arg::with_name("no-android-compat")
            .long("no-android-compat")
            .conflicts_with("android-compat")
            .help("Disable Android compatibility mode."))
        .arg(Arg::with_name("trampoline")
            .long("trampoline")
            .takes_value(true)
            .help("Absolute path to a host-resident trampoline binary to exec first (advanced)."))
}

pub fn parse_config() -> Result<(FileSystem, Vec<String>)> {
    let app = get_args_parser();

    let mut fs: FileSystem = FileSystem::new();

    let matches = app.get_matches();

    debug!("proot-rs startup with args:\n{:#?}", matches);

    // option -r
    let rootfs: &str = matches.value_of("rootfs").unwrap();
    // -r *path* is equivalent to -b *path*:/
    fs.set_root(rootfs)?;

    // Add sensible default binds when a rootfs is specified, so common
    // pseudo filesystems remain visible inside the guest. This especially
    // helps on Termux/Android where /proc access is required by many tools.
    // These are no-ops if the paths don’t exist on the host, or if user adds
    // explicit bindings which will take precedence by order.
    for (host, guest) in [
        ("/proc", "/proc"),
        ("/dev", "/dev"),
        ("/sys", "/sys"),
        // Android-specific roots frequently accessed by bionic/tools
        ("/apex", "/apex"),
        ("/system", "/system"),
        ("/vendor", "/vendor"),
    ] {
        if std::path::Path::new(host).exists() {
            // Ignore errors here; explicit -b bindings may override later.
            let _ = fs.add_binding(host, guest);
        }
    }

    // option(s) -b
    if let Some(bindings) = matches.values_of("bind") {
        let raw_bindings_str: Vec<&str> = bindings.collect::<Vec<&str>>();

        for raw_binding_str in &raw_bindings_str {
            let parts: Vec<&str> = raw_binding_str.split_terminator(':').collect();
            fs.add_binding(parts[0], parts[1])?;
        }
    }

    // option -w
    let cwd: &str = matches.value_of("cwd").unwrap();
    fs.set_cwd(cwd)?;

    // command
    let command: Vec<String> = match matches.values_of("command") {
        Some(values) => values.map(|s| s.into()).collect(),
        None => ["/bin/sh".into()].into(),
    };

    // Configure Android compatibility behavior via environment variable used
    // in the event loop. Default behavior: enabled on Android, disabled otherwise.
    let want_enable = matches.is_present("android-compat");
    let want_disable = matches.is_present("no-android-compat");
    if want_enable {
        std::env::set_var("PROOT_ANDROID_COMPAT", "1");
    } else if want_disable {
        std::env::set_var("PROOT_ANDROID_COMPAT", "0");
    }

    if let Some(path) = matches.value_of("trampoline") {
        std::env::set_var("PROOT_TRAMPOLINE", path);
    }

    Ok((fs, command))
}
