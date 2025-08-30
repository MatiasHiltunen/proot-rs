#!/data/data/com.termux/files/usr/bin/sh
# termux-loader.sh: Minimal Android/Termux loader shim to reroute common guest
# interpreters to Termux binaries so the first exec can succeed under Android.
#
# Usage: termux-loader.sh <guest_prog> [args...]
#
# Notes:
# - This is a pragmatic shim for Termux to get common shells/scripts running.
# - It does not map arbitrary ELF binaries; proot’s real loader should be used
#   for full coverage. This only handles /bin/sh and script shebangs that map
#   to Termux interpreters.

set -eu

PREFIX=${PREFIX:-/data/data/com.termux/files/usr}

if [ $# -lt 1 ]; then
  echo "termux-loader: missing program" >&2
  exit 127
fi

guest_prog="$1"; shift

# If guest program is /bin/sh (most common in tests), map to Termux sh.
if [ "$guest_prog" = "/bin/sh" ] || [ "$(basename "$guest_prog")" = "sh" ]; then
  exec "$PREFIX/bin/sh" "$@"
fi

# If it's a script with a shebang, try to map common interpreters to Termux.
if [ -f "$guest_prog" ]; then
  # Read first 2 bytes to detect shebang
  if head -c 2 "$guest_prog" 2>/dev/null | grep -q '^#!'; then
    shebang="$(head -n 1 "$guest_prog" | tr -d '\r' | sed -e 's/^#!\s*//')"
    # Split interpreter and optional arg
    interp_path="$(printf %s "$shebang" | awk '{print $1}')"
    interp_arg="$(printf %s "$shebang" | cut -d ' ' -f 2-)"
    # Map common interpreter paths to Termux
    case "$interp_path" in
      /bin/sh|sh)
        exec "$PREFIX/bin/sh" $interp_arg "$guest_prog" "$@"
        ;;
      /usr/bin/env)
        # env shebang: use Termux env
        exec "$PREFIX/bin/env" $interp_arg "$guest_prog" "$@"
        ;;
    esac
  fi
fi

echo "termux-loader: unsupported target: $guest_prog" >&2
exit 127

