#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
qemu_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
build_dir=${QEMU_IA64_BUILD_DIR:-$qemu_root/build-ia64-debug}

cc_machine=$(cc -dumpmachine 2>/dev/null || true)
if [ "${MINGW_PACKAGE_PREFIX:-}" != "mingw-w64-x86_64" ] &&
   ! printf '%s\n' "$cc_machine" | grep -q 'mingw32'; then
    echo "ERROR: run this script from the MSYS2 MINGW64 environment." >&2
    exit 1
fi

"$qemu_root/scripts/ia64-fetch-conformance-manuals.sh"
mkdir -p "$build_dir"
cd "$build_dir"

debug_cflags=${QEMU_IA64_DEBUG_CFLAGS:--O0 -g -DVIBTANIUM_DIAGNOSTICS=1}
build_ar=${QEMU_IA64_AR:-}
if [ -z "$build_ar" ]; then
    if command -v llvm-ar >/dev/null 2>&1; then
        build_ar=llvm-ar
    else
        build_ar=ar
    fi
fi
CFLAGS="$debug_cflags" \
CXXFLAGS="$debug_cflags" \
AR="$build_ar" \
"$qemu_root/configure" \
    --target-list=ia64-softmmu \
    --disable-docs \
    --disable-werror \
    --enable-slirp \
    --enable-debug \
    -Dbuildtype=debug \
    -Doptimization=0

ninja -j"${QEMU_IA64_BUILD_JOBS:-${NINJAJOBS:-4}}" qemu-system-ia64.exe
QEMU_IA64_BUILD_DIR="$build_dir" \
    "$qemu_root/scripts/ia64-run-required-conformance.sh"
