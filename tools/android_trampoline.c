// Minimal Android trampoline that immediately execs the intended program.
// Usage: android_trampoline <prog> [args...]
// Rationale: Ensure the first exec is a host-resident binary so the tracer can
// attach reliably on Android (Termux), then hand off to the actual target.
//
// Build on Termux: clang -O2 -fPIE -pie -o android_trampoline tools/android_trampoline.c

#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "android_trampoline: missing program to exec\n");
        return 127;
    }

    // Exec the intended program. We use execvpe so PATH lookup works when
    // argv[1] is not absolute.
    execvpe(argv[1], &argv[1], environ);
    int err = errno;
    fprintf(stderr, "android_trampoline: execvpe('%s') failed: %s\n", argv[1], strerror(err));
    return (err == ENOENT) ? 127 : 126;
}

