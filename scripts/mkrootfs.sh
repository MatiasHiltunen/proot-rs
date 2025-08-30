#!/bin/sh

#!/bin/sh

# Create a minimal guest rootfs for testing proot-rs.
#
# What changed:
# - Default rootfs switched to Alpine (was BusyBox-only).
# - Robust downloads using either curl or wget (whichever exists).
# - Keeps BusyBox support as a compatibility option and falls back to
#   Alpine if a BusyBox tarball cannot be located.
#
# Usage examples:
#   scripts/mkrootfs.sh                       # creates ./rootfs (alpine by default)
#   scripts/mkrootfs.sh -t alpine -d ./root   # explicitly pick Alpine and directory
#   scripts/mkrootfs.sh -t busybox            # try BusyBox; falls back to Alpine
#
# Notes:
# - If the target directory exists and is not empty, generation is skipped.
# - Set PROOT_TEST_ROOTFS to point tests at the generated rootfs.

PROOT_TEST_ROOTFS="./rootfs"

# Choose Alpine by default because it provides a fuller minimal system
# while staying tiny and fast to download and unpack for tests.
rootfs_type="alpine"

# Optional: allow pinning a specific Alpine version by setting
# ALPINE_VERSION, e.g. "3.14.0" or "3.20.3". When empty, we use the
# conservative (older but stable) URLs below to avoid flaky CI.
ALPINE_VERSION="${ALPINE_VERSION:-}"

# Small helpers -------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# download URL OUTPUT
download() {
  url="$1"; out="$2"
  if have curl; then
    # -f: fail on HTTP errors; -L: follow redirects; --retry for flaky nets
    curl -fL --retry 3 --retry-delay 1 -o "$out" "$url"
  elif have wget; then
    wget -O "$out" "$url"
  else
    echo "Neither curl nor wget found; please install one." >&2
    return 127
  fi
}

# probe URL (return 0 if reachable)
probe() {
  url="$1"
  if have curl; then
    curl -fIsL "$url" >/dev/null 2>&1
  elif have wget; then
    wget -q --spider "$url" >/dev/null 2>&1
  else
    return 127
  fi
}

while getopts "d:t:" opt; do
  case $opt in
    d)
      PROOT_TEST_ROOTFS="${OPTARG}"
      ;;
    t)
      rootfs_type="${OPTARG}"
      ;;
    *)
      echo "Invalid option"
      exit 1
  esac
done

echo "Preparing rootfs...   type: ${rootfs_type}  path: ${PROOT_TEST_ROOTFS}"

rootfs_url=""
case ${rootfs_type} in
  busybox)
    # NOTE:
    #   Upstream docker-library/busybox occasionally reorganizes tarball paths
    #   under dist-* branches. To be resilient, we probe several well-known
    #   locations and pick the first available. If all fail, we fall back to
    #   an Alpine minirootfs, which includes BusyBox and is sufficient for tests.
    #   This makes the script robust across Termux and CI without manual edits.

    # Map current machine arch to docker-library dist branch suffix.
    case $(uname -m) in
      i386|i686)  dist_branch="dist-i386" ;;
      x86_64)     dist_branch="dist-amd64" ;;
      armv7l)     dist_branch="dist-arm32v7" ;;
      aarch64)    dist_branch="dist-arm64v8" ;;
      *)          echo "Unsupported architecture $(uname -m)"; exit 1 ;;
    esac

    # Candidate locations (newest-first) to probe for busybox rootfs tarball.
    # We avoid fetching content by using --spider to check existence quickly.
    candidates="
https://github.com/docker-library/busybox/raw/${dist_branch}/stable-glibc/busybox.tar.xz
https://github.com/docker-library/busybox/raw/${dist_branch}/stable/busybox.tar.xz
https://github.com/docker-library/busybox/raw/${dist_branch}/stable/uclibc/busybox.tar.xz
https://github.com/docker-library/busybox/raw/${dist_branch}/latest-glibc/busybox.tar.xz
https://github.com/docker-library/busybox/raw/${dist_branch}/latest/busybox.tar.xz
https://github.com/docker-library/busybox/raw/${dist_branch}/latest/uclibc/busybox.tar.xz
"

    # Try each candidate until one is reachable.
    for u in ${candidates}; do
      if probe "${u}"; then
        rootfs_url="${u}"
        break
      fi
    done

    if [ -n "${rootfs_url}" ]; then
      echo "Selected busybox rootfs: ${rootfs_url}"
    else
      echo "Failed to locate busybox rootfs upstream; falling back to Alpine minirootfs..."
      # Fallback: choose an Alpine minirootfs URL matching the arch.
      case $(uname -m) in
        i386|i686)
          if [ -n "$ALPINE_VERSION" ]; then
            rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/x86/alpine-minirootfs-${ALPINE_VERSION}-x86.tar.gz"
          else
            rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86/alpine-minirootfs-3.14.0-x86.tar.gz"
          fi
          ;;
        x86_64)
          if [ -n "$ALPINE_VERSION" ]; then
            rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"
          else
            rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86_64/alpine-minirootfs-3.14.0-x86_64.tar.gz"
          fi
          ;;
        armv7l)
          if [ -n "$ALPINE_VERSION" ]; then
            rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/armv7/alpine-minirootfs-${ALPINE_VERSION}-armv7.tar.gz"
          else
            rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/armv7/alpine-minirootfs-3.14.0-armv7.tar.gz"
          fi
          ;;
        aarch64)
          if [ -n "$ALPINE_VERSION" ]; then
            rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/aarch64/alpine-minirootfs-${ALPINE_VERSION}-aarch64.tar.gz"
          else
            rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/aarch64/alpine-minirootfs-3.14.0-aarch64.tar.gz"
          fi
          ;;
      esac
      rootfs_type="alpine"
    fi
    ;;
  alpine)
    case $(uname -m) in
      i386|i686)
        if [ -n "$ALPINE_VERSION" ]; then
          rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/x86/alpine-minirootfs-${ALPINE_VERSION}-x86.tar.gz"
        else
          rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86/alpine-minirootfs-3.14.0-x86.tar.gz"
        fi
        ;;
      x86_64)
        if [ -n "$ALPINE_VERSION" ]; then
          rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"
        else
          rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86_64/alpine-minirootfs-3.14.0-x86_64.tar.gz"
        fi
        ;;
      armv7l)
        if [ -n "$ALPINE_VERSION" ]; then
          rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/armv7/alpine-minirootfs-${ALPINE_VERSION}-armv7.tar.gz"
        else
          rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/armv7/alpine-minirootfs-3.14.0-armv7.tar.gz"
        fi
        ;;
      aarch64)
        if [ -n "$ALPINE_VERSION" ]; then
          rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/aarch64/alpine-minirootfs-${ALPINE_VERSION}-aarch64.tar.gz"
        else
          rootfs_url="https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/aarch64/alpine-minirootfs-3.14.0-aarch64.tar.gz"
        fi
        ;;
      *)  echo "Unsupported architecture $(uname -m)"; exit 1 ;;
    esac
    ;;
  *)      echo "Unknown rootfs type ${rootfs_type}"; exit 1 ;;
esac

if [ -n "$(ls -A "${PROOT_TEST_ROOTFS}" 2>/dev/null)" ]; then
  echo "The rootfs path ${PROOT_TEST_ROOTFS} exist but not empty. Skip creating rootfs..."
  exit 0
fi

echo "Creating ${rootfs_type} rootfs for $(uname -m) architecture in ${PROOT_TEST_ROOTFS}"

mkdir -p "${PROOT_TEST_ROOTFS}"

trap 'rm -f "${rootfs_archive}"' EXIT

rootfs_archive="$(mktemp)" || { echo "Failed to create temp file"; exit 1; }

download "${rootfs_url}" "${rootfs_archive}" || { echo "Failed to download ${rootfs_type} archive"; exit 1; }

tar -C "${PROOT_TEST_ROOTFS}" -xf "${rootfs_archive}" || { echo "Failed to unpack ${rootfs_type} tarball. Maybe the file is broken"; exit 1; }

echo "The rootfs was created at ${PROOT_TEST_ROOTFS}"
