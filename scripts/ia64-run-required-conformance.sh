#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
qemu_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
build_dir=${QEMU_IA64_BUILD_DIR:-$qemu_root/build-ia64-debug}
output_dir=${QEMU_IA64_CONFORMANCE_OUTPUT_DIR:-$qemu_root/conformance-results}
profile=${QEMU_IA64_CONFORMANCE_PROFILE:-vibtanium-strict-up}
meson="$build_dir/pyvenv/bin/meson.exe"
python="$build_dir/pyvenv/bin/python.exe"
binary=${QEMU_IA64_BIN:-$build_dir/qemu-system-ia64.exe}

cc_machine=$(cc -dumpmachine 2>/dev/null || true)
if [ "${MINGW_PACKAGE_PREFIX:-}" != "mingw-w64-x86_64" ] &&
   ! printf '%s\n' "$cc_machine" | grep -q 'mingw32'; then
    echo "ERROR: run this script from the MSYS2 MINGW64 environment." >&2
    exit 1
fi
"$qemu_root/scripts/ia64-fetch-conformance-manuals.sh"
if [ ! -x "$meson" ] || [ ! -x "$python" ] || [ ! -x "$binary" ]; then
    echo "ERROR: configured IA-64 debug build is unavailable: $build_dir" >&2
    exit 1
fi

cd "$qemu_root"
set +e
"$meson" test -C "$build_dir" \
    --print-errorlogs \
    --num-processes "${QEMU_IA64_TEST_JOBS:-4}" \
    qemu:test-ia64-bundle \
    qemu:test-ia64-decode \
    qemu:test-ia64-opcode-traits \
    qemu:test-ia64-insn \
    qemu:test-ia64-memory-exceptions \
    qemu:test-ia64-rse-spine \
    qemu:test-ia64-vmstate \
    qemu:test-ia64-full-tcg-static \
    qemu:test-ia64-platform-static \
    qemu:test-ia64-packed-tcg-static \
    qemu:test-ia64-data-plane-tcg-static \
    qemu:test-ia64-system-tcg-static \
    qemu:test-ia64-fp-tcg-static \
    qemu:test-ia64-register-tcg-static \
    qemu:test-ia64-opcode-ledger \
    qemu:test-ia64-normative-catalogue \
    qemu:test-ia64-runner-protocol \
    qemu:test-ia64-first-architectural-tranche-static \
    qemu:test-ia64-correctness-lessons-static \
    qemu:test-ia64-decoder-bundle-tranche-static \
    qemu:test-ia64-memory-boundary-tranche-static \
    qemu:test-ia64-packed-integer-tranche-static \
    qemu:test-ia64-predicate-branch-tranche-static \
    qemu:test-ia64-rse-spine-static \
    qemu:test-ia64-scalar-integer-tranche-static \
    qemu:test-ia64-engine-role \
    qemu:test-ia64-implementation-surface \
    qemu:test-ia64-evidence-map \
    qemu:test-ia64-conformance-closure \
    qemu:test-ia64-conformance-runner \
    qemu:test-ia64-first-architectural-tranche \
    qemu:test-ia64-correctness-lessons \
    qemu:test-ia64-decoder-bundle-tcg \
    qemu:test-ia64-decoder-bundle-tranche \
    qemu:test-ia64-memory-boundary-tranche \
    qemu:test-ia64-packed-integer-tranche \
    qemu:test-ia64-predicate-branch-tranche \
    qemu:test-ia64-scalar-integer-tranche \
    qemu:test-ia64-scalar-tcg \
    qemu:test-ia64-production-cutover \
    qemu:test-ia64-memory-tcg \
    qemu:test-ia64-system-tcg \
    qemu:test-ia64-data-plane-tcg \
    qemu:test-ia64-alat-tcg \
    qemu:test-ia64-alat-alias-tcg \
    qemu:test-ia64-full-tcg \
    qemu:test-ia64-tcp-migration \
    qemu:test-ia64-packed-tcg \
    qemu:test-ia64-fp-tcg \
    qemu:test-ia64-register-tcg \
    qemu:qtest-ia64/ia64-acpi-test \
    qemu:qtest-ia64/ia64-input-test
test_status=$?
set -e

mkdir -p "$output_dir"
"$python" "$qemu_root/scripts/ia64-gen-conformance-closure.py" \
    --root "$qemu_root" \
    --build-dir "$build_dir" \
    --binary "$binary" \
    --profile "$profile" \
    --test-log "$build_dir/meson-logs/testlog.json" \
    --output "$output_dir/ia64-conformance-closure.json" \
    --summary-output "$output_dir/ia64-conformance-closure.md"

printf 'IA-64 conformance closure JSON: %s\n' \
    "$output_dir/ia64-conformance-closure.json"
printf 'IA-64 conformance closure summary: %s\n' \
    "$output_dir/ia64-conformance-closure.md"
exit "$test_status"
