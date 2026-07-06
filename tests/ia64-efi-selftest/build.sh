#!/usr/bin/env bash
#
# Build the IA-64 EFI self-test into selftest.efi.
#
#   as/ld/objcopy come from the IA-64 cross binutils; python wraps the flat
#   binary into a PE32+ EFI image the vibtanium firmware can load.
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

BINUTILS="${IA64_BINUTILS:-/c/msys64/opt/ia64-binutils/bin}"
AS="$BINUTILS/ia64-linux-gnu-as"
LD="$BINUTILS/ia64-linux-gnu-ld"
OBJCOPY="$BINUTILS/ia64-linux-gnu-objcopy"
OBJDUMP="$BINUTILS/ia64-linux-gnu-objdump"
PYTHON="${PYTHON:-python}"

for tool in "$AS" "$LD" "$OBJCOPY"; do
    if [ ! -x "$tool" ] && ! command -v "$tool" >/dev/null 2>&1; then
        echo "build.sh: missing IA-64 tool: $tool" >&2
        echo "  set IA64_BINUTILS to the cross-binutils bin directory" >&2
        exit 1
    fi
done

echo "[1/5] generate strings.S"
"$PYTHON" gen_strings.py strings.S

echo "[2/5] assemble selftest.S"
"$AS" -o selftest.o selftest.S

echo "[3/5] link"
"$LD" -T link.ld -o selftest.elf selftest.o

echo "[4/5] objcopy -> flat binary"
"$OBJCOPY" -O binary selftest.elf selftest.bin

echo "[5/5] wrap PE32+ -> selftest.efi"
"$PYTHON" mkpe.py selftest.bin selftest.efi

echo "built $(pwd)/selftest.efi ($(wc -c < selftest.efi) bytes)"
if [ "${1:-}" = "-v" ]; then
    "$OBJDUMP" -d selftest.elf | sed -n '1,60p'
fi
