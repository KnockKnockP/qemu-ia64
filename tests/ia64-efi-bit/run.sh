#!/usr/bin/env bash
#
# Build (if needed) and run the IA-64 EFI BIT under qemu-system-ia64,
# then report PASS/FAIL based on the sentinel line the guest prints.
#
# Exit status: 0 = all checks passed, 1 = failure / crash / timeout.
#
# Environment overrides:
#   QEMU        path to qemu-system-ia64(.exe)
#   MINGW_BIN   directory with the MinGW runtime DLLs (added to PATH)
#   TIMEOUT     seconds to wait for the sentinel (default 40)
#   NVRAM       optional path to a persistent EFI variable store (-M nvram=)
#   BOOT_MODE   media (default, temp vvfat ESP) or kernel (old -kernel path)
#   SKIP_BIT_BUILD=1 or NO_BUILD=1
#               skip the build step and use the existing bit.efi
#
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"
repo_root="$(cd "$here/../.." && pwd)"

SENTINEL="VIBTANIUM-BIT-RESULT:"
TIMEOUT="${TIMEOUT:-40}"
BOOT_MODE="${BOOT_MODE:-media}"

# --- locate qemu ---------------------------------------------------------
if [ -z "${QEMU:-}" ]; then
    for cand in \
        "$repo_root/build-ia64-perf/qemu-system-ia64.exe" \
        "$repo_root/release-ia64/qemu-system-ia64.exe" \
        "$repo_root/build-ia64-debug/qemu-system-ia64.exe"; do
        if [ -x "$cand" ]; then QEMU="$cand"; break; fi
    done
fi
if [ -z "${QEMU:-}" ] || [ ! -x "$QEMU" ]; then
    echo "run.sh: could not find qemu-system-ia64; set QEMU=..." >&2
    exit 1
fi

# MinGW builds need their runtime DLLs on PATH.
MINGW_BIN="${MINGW_BIN:-/c/msys64/mingw64/bin}"
if [ -d "$MINGW_BIN" ]; then
    export PATH="$MINGW_BIN:$PATH"
fi

# --- build ---------------------------------------------------------------
skip_build="${SKIP_BIT_BUILD:-${NO_BUILD:-0}}"
if [ "$skip_build" != "1" ]; then
    bash "$here/build.sh" >/dev/null
fi
EFI="$here/bit.efi"
if [ ! -f "$EFI" ]; then
    echo "run.sh: $EFI not found (build failed?)" >&2
    exit 1
fi

# --- run -----------------------------------------------------------------
LOG="$(mktemp 2>/dev/null || echo "$here/bit-run.log")"
esp_dir=""
machine_arg="vibtanium,efi-boot-manager=off"
if [ -n "${NVRAM:-}" ]; then
    nvram_path="$(cygpath -am "$NVRAM" 2>/dev/null || printf '%s' "$NVRAM")"
    machine_arg="${machine_arg},nvram=$nvram_path"
fi

qemu_boot_args=()
case "$BOOT_MODE" in
media)
    esp_dir="$(mktemp -d 2>/dev/null || mktemp -d "$here/bit-esp.XXXXXX")"
    mkdir -p "$esp_dir/EFI/BOOT"
    cp "$EFI" "$esp_dir/EFI/BOOT/BOOTIA64.EFI"
    printf 'vibtanium-bit-ok\n' > "$esp_dir/EFI/BOOT/BIT.TXT"
    esp_path="$(cygpath -am "$esp_dir" 2>/dev/null || printf '%s' "$esp_dir")"
    qemu_boot_args=(-drive "file=fat:$esp_path,format=raw,if=ide,index=2,media=cdrom,readonly=on")
    ;;
kernel)
    qemu_boot_args=(-kernel "$EFI")
    ;;
*)
    echo "run.sh: invalid BOOT_MODE '$BOOT_MODE' (expected media or kernel)" >&2
    rm -f "$LOG" 2>/dev/null || true
    exit 1
    ;;
esac

"$QEMU" -M "$machine_arg" -m 512M \
        "${qemu_boot_args[@]}" -display none -serial null -no-reboot \
        >"$LOG" 2>&1 &
qpid=$!
winpid="$(cat "/proc/$qpid/winpid" 2>/dev/null || true)"

# Poll for the sentinel or process exit, up to TIMEOUT seconds.
deadline=$((SECONDS + TIMEOUT))
while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -q "$SENTINEL" "$LOG" 2>/dev/null; then break; fi
    if ! kill -0 "$qpid" 2>/dev/null; then break; fi
    sleep 1
done

# Stop qemu (the guest spins after printing its verdict). Never block: the
# MinGW qemu is a native process, so kill it by its Windows PID and only fall
# back to the MSYS pid. Poll (bounded) instead of an unbounded `wait`.
[ -z "$winpid" ] && winpid="$(cat "/proc/$qpid/winpid" 2>/dev/null || true)"
if [ -n "$winpid" ]; then
    taskkill //F //T //PID "$winpid" >/dev/null 2>&1 || true
fi
kill -9 "$qpid" 2>/dev/null || true
for _ in 1 2 3 4 5; do
    kill -0 "$qpid" 2>/dev/null || break
    sleep 1
done

# --- report --------------------------------------------------------------
echo "----- BIT serial output -----"
grep -aE "BIT:|\[PASS\]|\[FAIL\]|$SENTINEL" "$LOG" || cat "$LOG"
echo "-----------------------------------"

rc=1
if grep -q "$SENTINEL ALL PASS" "$LOG"; then
    echo "RESULT: PASS"
    rc=0
elif grep -q "$SENTINEL FAILURES" "$LOG"; then
    echo "RESULT: FAIL (one or more checks failed)"
elif grep -q "execution frontier" "$LOG"; then
    echo "RESULT: FAIL (emulator hit an execution frontier / unimplemented op)"
    grep -a "unsupported instruction" "$LOG" | head -1
else
    echo "RESULT: FAIL (no sentinel: timeout or crash within ${TIMEOUT}s)"
fi

rm -f "$LOG" 2>/dev/null || true
if [ -n "$esp_dir" ]; then
    rm -rf "$esp_dir" 2>/dev/null || true
fi
exit "$rc"
