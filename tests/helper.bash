#!/bin/bash

export LC_ALL=C

# The root directory where the integration test files are placed
TEST_ROOT=$(dirname "$(readlink -f "$BASH_SOURCE")")

# The root directory of this project
PROJECT_ROOT="$TEST_ROOT/../"

# Path to the proot-rs binary
if [ -z "${PROOT_RS}" ]; then
    PROOT_RS="$PROJECT_ROOT/target/debug/proot-rs"
fi

# Set the default path to the new rootfs, which is created in advance by `scripts/mkrootfs.sh`
# Note that if `PROOT_TEST_ROOTFS` is set, then the value of `ROOTFS` will the same as it; otherwise, the default value of `ROOTFS` is `$PROJECT_ROOT/rootfs`
[[ -z "${PROOT_TEST_ROOTFS}" ]] && ROOTFS="$PROJECT_ROOT/rootfs" || ROOTFS="${PROOT_TEST_ROOTFS}"

# A wrapper for bats' built-in `run` command.
# This function will first execute the original `run` command, and then print the `$status` and `$output` to the `stderr`.
# One advantage over `run` is that the results of the command will be displayed when the test fails, making it easier for developers to debug.
function runp() {
    run "$@"
    echo "command: $@" >&2
    echo "status:  $status" >&2
    echo "output:  $output" >&2
}

# A wrapper function for proot-rs binary.
function proot-rs() {
    "$PROOT_RS" "$@"
}

# Compile a single C source code file ($2) to statically linked binary ($1)
function compile_c_static() {
    local target_path="$1"
    local source_path="$2"

    # Ensure compiler exists
    command -v gcc 1>&- 2>&- || { skip "gcc is required for this test."; }

    # Some environments (e.g., Termux/Android) do not support static linking.
    # Probe static linking with a tiny program. If it fails, skip gracefully.
    local probe_src
    probe_src="$(mktemp)" || probe_src="/tmp/bats_probe_static_$$.c"
    cat > "$probe_src" <<'EOF'
int main(){return 0;}
EOF
    if ! gcc -static -o /dev/null "$probe_src" 2>/dev/null; then
        rm -f "$probe_src"
        skip "Static linking not supported on this platform."
    fi
    rm -f "$probe_src"

    gcc -std=gnu89 -static -o "$target_path" "$source_path"
}

# Same as `compile_c_static()`, but the final binary is dynamically linked
function compile_c_dynamic() {
    local target_path="$1"
    local source_path="$2"
    command -v gcc 1>&- 2>&- || { skip "gcc is required for this test."; }
    gcc -std=gnu89 -o "$target_path" "$source_path"
}

# Ensure that the command exists, or skip the test
function check_if_command_exists() {
    command -v "$1" 1>&- 2>&- || { skip "The command \`$1\` is required but is not installed."; }
}
