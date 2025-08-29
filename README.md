# proot-rs

**Please take the PRoot Usage Survey for 2023!** [![Survey](https://img.shields.io/badge/survey-2023-green?style=flat-square)](https://www.surveymonkey.com/r/7GVXS7W)

--

[![Tests](https://img.shields.io/github/actions/workflow/status/proot-me/proot-rs/tests.yml?style=flat-square)](https://github.com/proot-me/proot-rs/actions/workflows/tests.yml)
[![Releases](https://img.shields.io/github/v/release/proot-me/proot-rs?sort=semver&style=flat-square)](https://github.com/proot-me/proot-rs/releases)


_Rust implementation of PRoot, a ptrace-based sandbox._

`proot-rs` works by intercepting all Linux system calls that use paths (`execve`, `mkdir`, `ls`, ...)
and translating these with the specified path bindings, in order to simulate `chroot`,
and all this without requiring admin rights (`ptrace` do not require any special rights).

So for instance, this command:

```
proot-rs -R /home/user/ mkdir /myfolder
```

(`-R` defines a new root and adds usual bindings like `/bin`)

will be equivalent to:

```
mkdir /home/user/myfolder/
```

Hence, you can apply `proot-rs` to a whole program in order to sandbox it.
More concretely, you can for instance download a docker image, extract it,
and run it, without needing docker:

```
proot-rs -R ./my-docker-image /bin/sh
```

## Usage

```
proot-rs 0.1.0
chroot, mount --bind, and binfmt_misc without privilege/setup.

USAGE:
    proot-rs [OPTIONS] [--] [command]...

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -b, --bind <bind>...     Make the content of *host_path* accessible in the guest rootfs. Format:
                             host_path:guest_path
    -w, --cwd <cwd>          Set the initial working directory to *path*. [default: /]
    -r, --rootfs <rootfs>    Use *path* as the new guest root file-system. [default: /]

ARGS:
    <command>...  
```

## Requirements

### Cargo

We use _rustup/cargo_ to develop proot-rs, which is a common approach in Rust development. You can install them as shown [here](https://www.rust-lang.org/tools/install).

### cargo-make

We also use [`cargo-make`](https://github.com/sagiegurari/cargo-make) as build tool, which can help you launch complex compilation steps. It works a bit like `make`, and you can install it like this:

> Note: We recommend using the stable toolchain to install `cargo-make` in order to avoid installation failures

```shell
# Install stable rust toolchain
rustup toolchain install stable
# Install cargo-make
cargo +stable install --force cargo-make
```

## Build

The recommended way is to use `cargo-make`:

```shell
cargo make build
```
The command basically consists of the following steps:
- Run `cargo build` on `loader-shim` package to compile the loader executable.
- Copy the loader executable `loader-shim` to `proot-rs/src/kernel/execve/loader-shim`
- Run `cargo build` on `proot-rs` package to  build the final executable.

If the compilation is successful, it should also print out the path to the `proot-rs` executable file.

### Build Release Version

To generate the release binary (it takes longer, but the binary generated is quicker), you can specify `--profile=production`:

```shell
cargo make build --profile=production
```

> Note: This [`--profile` option](https://github.com/sagiegurari/cargo-make#usage-profiles) comes from `cargo-make`, which has a different meaning than [the `profile` in cargo](https://doc.rust-lang.org/cargo/reference/profiles.html). And it is processed by `cargo-make` and will not be passed to `cargo`. 

### Cross Compilation

Currently `proot-rs` supports multiple platforms. You can change the compilation target by setting the environment variable `CARGO_BUILD_TARGET`.

#### With [`cross`](https://github.com/rust-embedded/cross) (Recommended)

The `cross` is a “zero setup” cross compilation and “cross testing” tool, which uses docker to provide an out-of-the-box cross-compilation environment which contains a ready-to-use cross-compilation toolchain. So we don't need to prepare it ourselves.

> Note that `cross` depends on docker, so you need to install docker and start it.

- To use cross, you may need to install it first:

    ```shell
    cargo install cross
    ```

- Run with `USE_CROSS=true`

  Our `Makefile.toml` script contains the integration with `cross`.

  For example, to compile to the `arm-linux-androideabi` target, you can simply run:
  ```shell
  USE_CROSS=true CARGO_BUILD_TARGET=arm-linux-androideabi cargo make build
  ```
  > The `USE_CROSS=true` will indicate the build script to use the `cross` tool to compile.

#### With `cargo` (Native Approach)

You can also use the rust native approach to cross-compile proot-rs.

For example, to compile to the `arm-linux-androideabi` target
- Install this target first:
  ```shell
  rustup target add arm-linux-androideabi
  ```
- Cross compile with `cargo`
  ```shell
  CARGO_BUILD_TARGET=arm-linux-androideabi cargo make build
  ```
  > Note: This command may fail for compiling to some targets because the linker reports some error. In this case, You may need to install an additional gcc/clang toolchain on your computer, and specify the appropriate linker path in the `.cargo/config.toml` file

<!-- TODO: Try to compile and test multiple targets in CI, and crate a table here. -->

## Run

Build and run `proot-rs`:

```shell
cargo make run -- "<args-of-proot-rs>"
```

Build and run release version of `proot-rs`:

```shell
cargo make run --profile=production -- "<args-of-proot-rs>"
```

## Termux/Android Support

This fork adds first-pass Termux/Android (aarch64) support on stable Rust:

- Replaces the nightly-only `japaric/syscall.rs` with a minimal stable shim at `sc/` exposing
  just the syscall numbers needed, sourced from `libc`. On Android, certain legacy syscalls are
  not exported by bionic; we map those to a non-matching sentinel so code compiles and simply
  treats them as unknown at runtime.
- Disables the heavy syscall-name mapping on Android to avoid depending on unavailable numbers;
  logs fall back to numeric identifiers.
- Uses `clang` as the linker for `aarch64-linux-android` in `.cargo/config.toml`, matching Termux
  environments that do not ship NDK wrapper binaries.
- Embeds a small placeholder `loader-shim` at `proot-rs/src/kernel/execve/loader-shim` so builds and
  basic unit tests succeed without a nightly-only loader build. Replace it with a real binary if
  you need traced exec.
- You can override the embedded loader at runtime via `PROOT_LOADER_SHIM=/path/to/loader-shim`.
- Skips ptrace-heavy tests on Android (`#[cfg(all(test, not(target_os = "android")))]`).
- Adds an Android compatibility behavior to swallow `SIGSYS` delivered by seccomp so the tracee
  isn’t killed; enable/disable via `PROOT_ANDROID_COMPAT` (default: enabled on Android). This is a
  pragmatic survival mode; full emulation policies may be expanded over time.
 - CLI flags: `--android-compat` and `--no-android-compat` to toggle the behavior explicitly.
 - When `android-compat` is enabled, selectively remaps legacy syscalls blocked by seccomp to
   their modern counterparts with safe argument conversions (on arches where applicable):
   - `select` → `pselect6` (convert `timeval`→`timespec`, `sigmask=NULL`).
   - `poll` → `ppoll` (convert `timeout(ms)`→`timespec`, `sigmask=NULL`, `sigsetsize=0`).
   - `epoll_wait` → `epoll_pwait` (`sigmask=NULL`, `sigsetsize=0`).
   - `utimes` → `utimensat` (`timeval[2]`→`timespec[2]`, `flags=0`, `dirfd=AT_FDCWD`).
   - `utime` → `utimensat` (`utimbuf`→`timespec[2]`, `flags=0`, `dirfd=AT_FDCWD`).
  - `futimesat` → `utimensat` (`timeval[2]`→`timespec[2]`, `flags=0`).
  - Note: These remaps are compiled only on architectures where the legacy syscalls exist
     (x86/x86_64/arm). aarch64 does not expose these legacy syscalls.

Remap event logging (optional):
- Set `PROOT_ANDROID_REMAP_LOG=/path/to/log.jsonl` to capture remap events as JSON lines:
  `{"pid":123, "from":23, "to":288, "msg":"accept->accept4"}`. Useful in tests for asserting
  that a remap occurred without parsing textual logs.

### Runtime Smoke Example

- A small example program is provided to exercise remapped syscalls and produce debug logs:
  - Path: `proot-rs/examples/remap_smoke.rs`
  - On x86/x86_64/arm: calls `select`, `poll`, and `utimes` to trigger remaps.
  - On Android aarch64: calls `statfs` (handled via tracer emulation).

Run with debug logs enabled to observe remaps:

```shell
# Build the example binary
cargo build --package=proot-rs --example remap_smoke

# Run it under proot-rs with Android-compat mode and debug logs
RUST_LOG=debug PROOT_ANDROID_COMPAT=1 \
  cargo run --package=proot-rs -- -r <rootfs> -- \
  target/debug/examples/remap_smoke
```

To exercise an `accept(2)` call (which may be remapped to `accept4(2)` under SIGSYS), use:

```shell
cargo build --package=proot-rs --example accept_smoke

# Default: AF_UNIX abstract socket (robust across environments)
RUST_LOG=debug PROOT_ANDROID_COMPAT=1 \
  cargo run --package=proot-rs -- -r <rootfs> -- \
  target/debug/examples/accept_smoke

# Optional: TCP loopback variant
PROOT_ENABLE_TCP_SMOKE=1 RUST_LOG=debug PROOT_ANDROID_COMPAT=1 \
  cargo run --package=proot-rs -- -r <rootfs> -- \
  target/debug/examples/accept_smoke
```

Newer at-family smoke (with fallbacks):
- Attempts `faccessat2(AT_EACCESS)` and `renameat2` first; falls back to `faccessat`/`renameat` on ENOSYS.

```shell
cargo build --package=proot-rs --example at_new_smoke
RUST_LOG=debug PROOT_ANDROID_COMPAT=1 \
  cargo run --package=proot-rs -- -r <rootfs> -- \
  target/debug/examples/at_new_smoke
```

Exec shebang smoke:
- Creates a small `#!/bin/sh` script inside guest `/tmp` and execs it.

```shell
cargo build --package=proot-rs --example shebang_smoke
RUST_LOG=debug PROOT_ANDROID_COMPAT=1 \
  cargo run --package=proot-rs -- -r <rootfs> -- \
  target/debug/examples/shebang_smoke
```

Android smoke runner (Termux):

```shell
# Builds examples, ensures a busybox rootfs if needed, runs bats tests
scripts/android-smoke.sh
```


Notes:
- Running end-to-end on Android typically requires ptrace to be permitted for the app; many devices
  restrict this. Expect limited runtime functionality unless the environment allows tracing.

## Tests

### Setup new rootfs for testing

Typically, we need to specify a new rootfs path for testing proot-rs.

This script provided below can be used to create one:

```shell
# This will create a busybox-based temporary rootfs at ./rootfs/
bash scripts/mkrootfs.sh
```
### Unit testing

Start running unit tests:

```shell
export PROOT_TEST_ROOTFS="`realpath ./rootfs/`"
cargo test --package=proot-rs -- --test-threads=1
```

> Note:
> - Since our testing will spawn multiple processes, we need `--test-threads=1` to avoid deadlock caused by `fork()`. The option `--nocapture` may also be needed to show the original panic reason printed out by the child process.
> - Add the option `--profile=production` if you want to test a release build of proot-rs

On Android/Termux:
- Ptrac e-heavy tests are compiled out, but Android-focused unit tests for the conversion helpers and syscall constant shims are enabled. Run:

```shell
cargo test --package=proot-rs
```

### Integration testing

For the section on running integration tests, please read the [Integration Testing documentation](./tests/README.md)

## Contributing

We use git hooks to check files staged for commit to ensure the consistency of Rust code style.

Before you start, please run the following command to setup git hooks:

```shell
git config core.hooksPath .githooks
```

To format code manually:

```shell
cargo fmt
```
