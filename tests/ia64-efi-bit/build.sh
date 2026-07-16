#!/usr/bin/env bash
#
# Build the IA-64 EFI BIT into bit.efi.
#
#   ia64-linux-gnu-gcc builds the C test body, the IA-64 cross binutils provide
#   as/objcopy/objdump, and python wraps the flat binary into a PE32+ EFI image
#   the vibtanium firmware can load.
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

GCC="${IA64_GCC:-/c/msys64/opt/ia64-gcc/bin/ia64-linux-gnu-gcc}"
BINUTILS="${IA64_BINUTILS:-/c/msys64/opt/ia64-binutils/bin}"
AS="$BINUTILS/ia64-linux-gnu-as"
OBJCOPY="$BINUTILS/ia64-linux-gnu-objcopy"
OBJDUMP="$BINUTILS/ia64-linux-gnu-objdump"
PYTHON="${PYTHON:-python}"

for tool in "$GCC" "$AS" "$OBJCOPY"; do
    if [ ! -x "$tool" ] && ! command -v "$tool" >/dev/null 2>&1; then
        echo "build.sh: missing IA-64 tool: $tool" >&2
        echo "  set IA64_GCC or IA64_BINUTILS to the cross-tool directory" >&2
        exit 1
    fi
done

rm -f entry.o bit.o bit.elf bit.bin bit.efi

echo "[1/5] assemble entry.S"
"$AS" -o entry.o entry.S

echo "[2/5] compile bit.c"
"$GCC" \
    -std=gnu99 \
    -ffreestanding -fno-builtin -fno-pic \
    -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -fno-stack-protector -O2 -Wall -Wextra \
    -c bit.c -o bit.o

echo "[3/5] link"
"$GCC" -nostdlib -T link.ld -Wl,--build-id=none \
    -o bit.elf entry.o bit.o -lgcc

echo "[4/5] objcopy -> flat binary"
"$OBJCOPY" -O binary bit.elf bit.bin

echo "[5/5] wrap PE32+ -> bit.efi"
"$PYTHON" mkpe.py bit.bin bit.efi

echo "built $(pwd)/bit.efi ($(wc -c < bit.efi) bytes)"
if [ "${1:-}" = "-v" ]; then
    "$OBJDUMP" -d bit.elf | sed -n '1,60p'
fi
