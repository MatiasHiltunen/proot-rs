#![no_std]
#![no_main]

// The compiler may emit a call to the `memset()` function even if there is
// no such call in our code. However, since we use `-nostdlib` or
// `-nodefaultlibs`, this means we will not link to libc, which provides the
// implementation of `memset()`.
//
// In this case, we will get an `undefined reference to \`memset'` error.
// Fortunately, the crate `rlibc` provides an unoptimized implementation of
// `memset()`.
//
// See `-nodefaultlibs` at https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html
extern crate rlibc;

mod script;

use core::{fmt::Write, panic::PanicInfo};
use core::arch::asm;

use crate::script::*;

const O_RDONLY: usize = 00000000;
#[allow(dead_code)]
const AT_FDCWD: isize = -100;
const MAP_PRIVATE: usize = 0x02;
const MAP_FIXED: usize = 0x10;
const MAP_ANONYMOUS: usize = 0x20;

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
const MMAP_OFFSET_SHIFT: usize = 0;
#[cfg(any(target_arch = "arm"))]
const MMAP_OFFSET_SHIFT: usize = 12;

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const PROT_EXEC: usize = 0x4;
const PROT_GROWSDOWN: usize = 0x01000000;

const AT_NULL: usize = 0;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;
const AT_BASE: usize = 7;
const AT_ENTRY: usize = 9;
const AT_EXECFN: usize = 31;

const PR_SET_NAME: usize = 15;

macro_rules! branch {
    ($stack_pointer:expr, $entry_point:expr) => {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let sp = $stack_pointer as u64;
            let ep = $entry_point as u64;
            asm!(
                "mov sp, {sp}\n\
                 mov x0, xzr\n\
                 br {ep}",
                sp = in(reg) sp,
                ep = in(reg) ep,
                options(noreturn)
            );
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let sp = $stack_pointer as u64;
            let ep = $entry_point as u64;
            asm!(
                "mov rsp, {sp}\n\
                 xor edx, edx\n\
                 jmp {ep}",
                sp = in(reg) sp,
                ep = in(reg) ep,
                options(noreturn)
            );
        }
        #[cfg(target_arch = "arm")]
        unsafe {
            let sp = $stack_pointer as u32;
            let ep = $entry_point as u32;
            asm!(
                "mov sp, {sp}\n\
                 mov r0, #0\n\
                 mov pc, {ep}",
                sp = in(reg) sp,
                ep = in(reg) ep,
                options(noreturn)
            );
        }
        #[cfg(target_arch = "x86")]
        unsafe {
            let sp = $stack_pointer as u32;
            let ep = $entry_point as u32;
            asm!(
                "mov esp, {sp}\n\
                 xor edx, edx\n\
                 jmp {ep}",
                sp = in(reg) sp,
                ep = in(reg) ep,
                options(noreturn)
            );
        }
    };
}

#[cfg(target_arch = "aarch64")]
mod sys {
    use core::arch::asm;
    #[inline(always)]
    unsafe fn syscall6(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
        let ret: isize;
        asm!(
            "mov x8, {nr}\n\
             mov x0, {a0}\n\
             mov x1, {a1}\n\
             mov x2, {a2}\n\
             mov x3, {a3}\n\
             mov x4, {a4}\n\
             mov x5, {a5}\n\
             svc 0\n\
             mov {ret}, x0",
            nr=in(reg) nr,
            a0=in(reg) a0, a1=in(reg) a1, a2=in(reg) a2,
            a3=in(reg) a3, a4=in(reg) a4, a5=in(reg) a5,
            ret=out(reg) ret,
            options(nostack)
        );
        ret
    }
    #[inline(always)] unsafe fn syscall5(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize)->isize{ syscall6(nr,a0,a1,a2,a3,a4,0) }
    #[inline(always)] unsafe fn syscall4(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize)->isize{ syscall6(nr,a0,a1,a2,a3,0,0) }
    #[inline(always)] unsafe fn syscall3(nr: usize, a0: usize, a1: usize, a2: usize)->isize{ syscall6(nr,a0,a1,a2,0,0,0) }
    #[inline(always)] unsafe fn syscall2(nr: usize, a0: usize, a1: usize)->isize{ syscall6(nr,a0,a1,0,0,0,0) }
    #[inline(always)] unsafe fn syscall1(nr: usize, a0: usize)->isize{ syscall6(nr,a0,0,0,0,0,0) }

    // aarch64 syscall numbers
    pub const SYS_WRITE: usize = 64;
    pub const SYS_CLOSE: usize = 57;
    pub const SYS_OPENAT: usize = 56;
    pub const SYS_MMAP: usize = 222;
    pub const SYS_MPROTECT: usize = 226;
    pub const SYS_PRCTL: usize = 167;
    pub const SYS_EXECVE: usize = 221;
    pub const SYS_EXIT: usize = 93;

    pub unsafe fn write(fd: usize, buf: usize, len: usize) -> isize { syscall3(SYS_WRITE, fd, buf, len) }
    pub unsafe fn close(fd: usize) -> isize { syscall1(SYS_CLOSE, fd) }
    pub unsafe fn openat(dfd: isize, path: usize, flags: usize, mode: usize) -> isize { syscall4(SYS_OPENAT, dfd as usize, path, flags, mode) }
    pub unsafe fn mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: isize, off: usize) -> isize { syscall6(SYS_MMAP, addr, len, prot, flags, fd as usize, off) }
    pub unsafe fn mprotect(addr: usize, len: usize, prot: usize) -> isize { syscall3(SYS_MPROTECT, addr, len, prot) }
    pub unsafe fn prctl(opt: usize, a1: usize, a2: usize) -> isize { syscall3(SYS_PRCTL, opt, a1, a2) }
    pub unsafe fn execve(path: usize, argv: usize, envp: usize) -> isize { syscall3(SYS_EXECVE, path, argv, envp) }
    pub unsafe fn exit(code: usize) -> ! { let _ = syscall1(SYS_EXIT, code); loop {} }
}


/**
 * Interpret the load script pointed to by @cursor.
 */
#[no_mangle]
pub unsafe extern "C" fn _start(mut cursor: *const ()) {
    let mut traced = false;
    let mut reset_at_base = true;
    let mut at_base: Word = 0;
    let mut fd: Option<isize> = None;

    loop {
        // check if cursor is null
        // TODO: Check LoadStatement flag is vaild: Converting memory regions
        // directly to references to enum in rust is dangerous because invalid
        // tags can lead to undefined behaviors.
        let stmt: &LoadStatement = match (cursor as *const LoadStatement).as_ref() {
            Some(stmt) => stmt,
            None => panic!("Value of cursor is null"),
        };
        match stmt {
            st @ (LoadStatement::OpenNext(open) | LoadStatement::Open(open)) => {
                // debug: announce open path
                let _ = write!(Stderr {}, "loader: OPEN{} @0x{:x}\n",
                    if matches!(st, LoadStatement::OpenNext(_)) { "_NEXT" } else { "" },
                    open.string_address as usize);
                if let LoadStatement::OpenNext(_) = st {
                    // close last fd
                    assert!(sys::close(fd.unwrap() as usize) >= 0);
                }
                // open file
                #[cfg(any(target_arch = "aarch64"))]
                let status = sys::openat(AT_FDCWD, open.string_address as _, O_RDONLY, 0);
                assert!(status >= 0);
                fd = Some(status);
                reset_at_base = true
            }
            LoadStatement::MmapFile(mmap) => {
                // call mmap() with fd
                #[cfg(any(target_arch = "aarch64"))]
                let status = sys::mmap(
                    mmap.addr as _,
                    mmap.length as _,
                    mmap.prot as _,
                    (MAP_PRIVATE | MAP_FIXED) as _,
                    fd.unwrap(),
                    (mmap.offset >> MMAP_OFFSET_SHIFT) as _,
                );
                let _ = write!(Stderr {}, "loader: MMAP file addr=0x{:x} len=0x{:x} prot=0x{:x} off=0x{:x} -> 0x{:x}\n",
                    mmap.addr as usize, mmap.length as usize, mmap.prot as usize, mmap.offset as usize, status as usize);
                assert_eq!(status as usize, mmap.addr as usize);
                // set the end of the space to 0, if needed.
                if mmap.clear_length != 0 {
                    let start = (mmap.addr + mmap.length - mmap.clear_length) as *mut u8;
                    for i in 0..mmap.clear_length {
                        *start.offset(i as isize) = 0u8;
                    }
                }
                // if value of AT_BASE need to be reset
                if reset_at_base {
                    at_base = mmap.addr;
                    reset_at_base = false;
                }
            }
            LoadStatement::MmapAnonymous(mmap) => {
                #[cfg(any(target_arch = "aarch64"))]
                let status = sys::mmap(
                    mmap.addr as _,
                    mmap.length as _,
                    mmap.prot as _,
                    (MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS) as _,
                    -1,
                    0,
                );
                let _ = write!(Stderr {}, "loader: MMAP anon addr=0x{:x} len=0x{:x} prot=0x{:x} -> 0x{:x}\n",
                    mmap.addr as usize, mmap.length as usize, mmap.prot as usize, status as usize);
                assert!(status >= 0);
            }
            LoadStatement::MakeStackExec(stack_exec) => {
                let _ = sys::mprotect(
                    stack_exec.start as _,
                    1,
                    (PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN) as _,
                );
            }
            st @ (LoadStatement::StartTraced(start) | LoadStatement::Start(start)) => {
                if let LoadStatement::StartTraced(_) = st {
                    traced = true;
                }
                // close last fd
                assert!(sys::close(fd.unwrap() as usize) >= 0);

                /* Right after execve, the stack content is as follow:
                 *
                 *   +------+--------+--------+--------+
                 *   | argc | argv[] | envp[] | auxv[] |
                 *   +------+--------+--------+--------+
                 */
                let mut cursor2: *mut Word = start.stack_pointer as _;
                let argc = *cursor2.offset(0);
                let at_execfn = *cursor2.offset(1);

                // skip argv[]
                cursor2 = cursor2.offset((argc + 1 + 1) as _);
                // the last element of argv should be a null pointer
                assert_eq!(*cursor2.offset(-1), 0);

                // skip envp[]
                while *cursor2 != 0 {
                    cursor2 = cursor2.offset(1)
                }
                cursor2 = cursor2.offset(1);

                // adjust auxv[]; track which keys we successfully updated so we
                // can append missing ones if the original auxv (e.g., from a
                // statically linked loader) didn't include them.
                let mut found_phdr = false;
                let mut found_phent = false;
                let mut found_phnum = false;
                let mut found_entry = false;
                let mut found_base = false;
                let mut found_execfn = false;

                while *cursor2.offset(0) as usize != AT_NULL {
                    match *cursor2.offset(0) as usize {
                        AT_PHDR => { *cursor2.offset(1) = start.at_phdr; found_phdr = true; }
                        AT_PHENT => { *cursor2.offset(1) = start.at_phent; found_phent = true; }
                        AT_PHNUM => { *cursor2.offset(1) = start.at_phnum; found_phnum = true; }
                        AT_ENTRY => { *cursor2.offset(1) = start.at_entry; found_entry = true; }
                        AT_BASE => { *cursor2.offset(1) = at_base; found_base = true; }
                        AT_EXECFN => {
                            /* stmt->start.at_execfn can't be used for now since it is
                             * currently stored in a location that will be scratched
                             * by the process (below the final stack pointer).  */
                            *cursor2.offset(1) = at_execfn;
                            found_execfn = true;
                        }
                        _ => {}
                    }

                    cursor2 = cursor2.offset(2);
                }

                // cursor2 now points at the terminating AT_NULL. If some
                // critical auxv entries are absent (common when our loader is
                // statically linked so the kernel didn't provide them), append
                // them just before the final AT_NULL and then re-terminate.
                let mut appended = 0usize;
                let mut append_pair = |tag: usize, val: Word| {
                    unsafe {
                        *cursor2.offset((appended * 2) as isize + 0) = tag as Word;
                        *cursor2.offset((appended * 2) as isize + 1) = val;
                        appended += 1;
                    }
                };

                if !found_phdr { append_pair(AT_PHDR, start.at_phdr); }
                if !found_phent { append_pair(AT_PHENT, start.at_phent); }
                if !found_phnum { append_pair(AT_PHNUM, start.at_phnum); }
                if !found_entry { append_pair(AT_ENTRY, start.at_entry); }
                if !found_base { append_pair(AT_BASE, at_base); }
                if !found_execfn { append_pair(AT_EXECFN, at_execfn); }

                // Re-terminate auxv
                *cursor2.offset((appended * 2) as isize + 0) = AT_NULL as Word;
                *cursor2.offset((appended * 2) as isize + 1) = 0 as Word;

                // get base name of executable path
                let get_basename = |string: *const u8| -> *const u8 {
                    let mut cursor = string;
                    while *cursor != 0 {
                        cursor = cursor.offset(1);
                    }
                    while *cursor != b'/' && cursor > string {
                        cursor = cursor.offset(-1);
                    }
                    if *cursor == b'/' {
                        cursor = cursor.offset(1);
                    }
                    cursor
                };
                let name = get_basename(start.at_execfn as _);
                let _ = sys::prctl(PR_SET_NAME as _, name as usize, 0);
                let _ = write!(Stderr {}, "loader: START sp=0x{:x} entry=0x{:x} phdr=0x{:x} phent={} phnum={} at_base=0x{:x}\n",
                    start.stack_pointer as usize, start.entry_point as usize, start.at_phdr as usize, start.at_phent as usize, start.at_phnum as usize, at_base as usize);

                // jump to new entry point
                // Always branch into the mapped program. The tracer remains attached
                // and continues to observe syscalls after entry.
                branch!(start.stack_pointer, start.entry_point);
                unreachable!()
            }
        }
        // move cursor to next load statement
        cursor = (cursor as *const u8).offset(stmt.as_bytes().len() as _) as _;
    }
}

struct Stderr {}

impl Write for Stderr {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bs = s.as_bytes();
        let mut count = 0;
        while count < bs.len() {
            unsafe {
                let status = sys::write(2, bs.as_ptr().add(count) as _, bs.len() - count);
                if status < 0 {
                    return Err(core::fmt::Error);
                } else {
                    count += status as usize;
                }
            }
        }
        Ok(())
    }
}

#[panic_handler]
fn panic_handler(panic_info: &PanicInfo<'_>) -> ! {
    // If an error occurs, use the exit() system call to exit the program.
    let _ = write!(
        Stderr {},
        "An error occurred in loader-shim:\n{}\n",
        panic_info
    );
    unsafe {
        sys::exit(182);
    }
    unreachable!()
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
