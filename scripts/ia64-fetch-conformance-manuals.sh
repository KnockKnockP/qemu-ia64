#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
qemu_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
manual_dir=${IA64_CONFORMANCE_MANUAL_DIR:-$qemu_root/tests/ia64-conformance/manuals}

mkdir -p "$manual_dir"

fetch_manual() {
    name=$1
    url=$2
    pdf="$manual_dir/$name.pdf"
    text="$manual_dir/$name.txt"
    if [ ! -s "$pdf" ]; then
        command -v curl >/dev/null 2>&1 || {
            echo "ERROR: curl is required to fetch $name.pdf." >&2
            exit 1
        }
        curl --fail --location --retry 3 --output "$pdf" "$url"
    fi
    if [ ! -s "$text" ] || [ "$pdf" -nt "$text" ]; then
        command -v pdftotext >/dev/null 2>&1 || {
            echo "ERROR: pdftotext is required to extract $name.txt." >&2
            exit 1
        }
        pdftotext "$pdf" "$text"
    fi
}

base=https://www.intel.com/content/dam/www/public/us/en/documents/manuals
fetch_manual \
    itanium-architecture-software-developer-rev-2-3-vol-1-manual \
    "$base/itanium-architecture-software-developer-rev-2-3-vol-1-manual.pdf"
fetch_manual \
    itanium-architecture-software-developer-rev-2-3-vol-2-manual \
    "$base/itanium-architecture-software-developer-rev-2-3-vol-2-manual.pdf"
fetch_manual \
    itanium-architecture-vol-3-manual \
    "$base/itanium-architecture-vol-3-manual.pdf"

printf 'IA-64 manuals ready for citation validation: %s\n' "$manual_dir"
