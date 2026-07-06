#!/usr/bin/env bash
#
# Build (if needed) and run the IA-64 EFI self-test under qemu-system-ia64,
# then report PASS/FAIL based on the sentinel line the guest prints.
#
# Exit status: 0 = all checks passed, 1 = failure / crash / timeout.
#
# Environment overrides:
#   QEMU        path to qemu-system-ia64(.exe)
#   MINGW_BIN   directory with the MinGW runtime DLLs (added to PATH)
#   TIMEOUT     seconds to wait for the sentinel (default 40)
#   NVRAM       optional path to a persistent EFI variable store (-M nvram=)
#   NO_BUILD=1  skip the build step and use the existing selftest.efi
#
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"
repo_root="$(cd "$here/../.." && pwd)"

SENTINEL="VIBTANIUM-SELFTEST-RESULT:"
TIMEOUT="${TIMEOUT:-40}"

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
if [ "${NO_BUILD:-0}" != "1" ]; then
    bash "$here/build.sh" >/dev/null
fi
EFI="$here/selftest.efi"
if [ ! -f "$EFI" ]; then
    echo "run.sh: $EFI not found (build failed?)" >&2
    exit 1
fi

# --- run -----------------------------------------------------------------
LOG="$(mktemp 2>/dev/null || echo "$here/selftest-run.log")"
nvram_arg=""
if [ -n "${NVRAM:-}" ]; then
    nvram_arg=",nvram=$NVRAM"
fi

"$QEMU" -M "vibtanium${nvram_arg}" -m 512M \
        -kernel "$EFI" -display none -serial null -no-reboot \
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
echo "----- self-test serial output -----"
grep -aE "self-test:|\[PASS\]|\[FAIL\]|$SENTINEL" "$LOG" || cat "$LOG"
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
exit "$rc"
